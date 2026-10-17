"""Domain profile: mail DNS records (MX, SPF, DMARC), registration age via RDAP,
free-mail / disposable lists and lookalike detection. No API keys needed."""

import asyncio
from datetime import UTC, datetime

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.analysis.lookalike import find_lookalike
from app.analysis.mailprovider import identify
from app.core.cache import Cache
from app.core.config import Settings
from app.core.http import UnsafeURLError, assert_public_url
from app.core.lists import disposable, freemail
from app.core.util import registrable_domain
from app.models.schemas import DomainProfile, Indicator, IndicatorType, SourceResult, SourceStatus

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"


_EMPTY = (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN)


async def _txt(resolver: dns.asyncresolver.Resolver, name: str) -> tuple[list[str], bool]:
    """Return (records, ok). ok=False means the lookup itself failed (timeout, no
    nameservers), which must not be mistaken for "the domain has no record"."""
    try:
        answer = await resolver.resolve(name, "TXT")
    except _EMPTY:
        return [], True
    except (dns.exception.DNSException, OSError):
        return [], False
    return ["".join(part.decode("utf-8", "replace") for part in r.strings) for r in answer], True


async def _addresses(resolver: dns.asyncresolver.Resolver, name: str) -> list[str]:
    """A then AAAA records; empty on any failure (this is context, not a verdict)."""
    for rtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(name, rtype)
            return [r.address for r in answer][:3]
        except (dns.exception.DNSException, OSError):
            continue
    return []


async def mail_dns(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4.0
    out: dict = {"mx": [], "spf": None, "dmarc": None, "dmarc_policy": None, "ok": True}
    try:
        mx = await resolver.resolve(domain, "MX")
        out["mx"] = sorted(str(r.exchange).rstrip(".") for r in mx)
    except dns.resolver.NXDOMAIN:
        out["nxdomain"] = True
    except dns.resolver.NoAnswer:
        pass
    except (dns.exception.DNSException, OSError):
        out["ok"] = False
    if out["mx"] == [""]:
        out["mx"], out["null_mx"] = [], True  # RFC 7505: the domain accepts no mail
    (txt, ok1), (dmarc, ok2), web = await asyncio.gather(
        _txt(resolver, domain), _txt(resolver, f"_dmarc.{domain}"), _addresses(resolver, domain),
    )
    out["ok"] = out["ok"] and ok1 and ok2
    out["web_ips"] = web
    mx_ips: list[str] = []
    for host in out["mx"][:2]:
        mx_ips += (await _addresses(resolver, host))[:1]
    out["mx_ips"] = list(dict.fromkeys(mx_ips))
    out["spf"] = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    record = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
    out["dmarc"] = record
    if record:
        for tag in record.split(";"):
            k, _, v = tag.strip().partition("=")
            if k.lower() == "p":
                out["dmarc_policy"] = v.strip().lower()
    return out


async def rdap_lookup(domain: str, client: httpx.AsyncClient) -> dict | None:
    """Follow the rdap.org bootstrap redirect to the registry; every hop is SSRF-checked."""
    url = RDAP_BOOTSTRAP.format(domain=domain)
    for _ in range(4):
        await assert_public_url(url)
        resp = await client.get(url, headers={"Accept": "application/rdap+json"})
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
            url = str(httpx.URL(url).join(resp.headers["location"]))
            continue
        if resp.status_code == 404:
            return {"not_found": True}
        resp.raise_for_status()
        data = resp.json()
        created = next(
            (e.get("eventDate") for e in data.get("events", []) if e.get("eventAction") == "registration"),
            None,
        )
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for item in (entity.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn":
                        registrar = item[3]
        return {"created": created, "registrar": registrar}
    return None


async def build_profile(
    host: str,
    role: str,
    settings: Settings,
    client: httpx.AsyncClient,
    cache: Cache,
    with_mail_dns: bool,
) -> tuple[DomainProfile, list[SourceResult]]:
    reg = registrable_domain(host)
    profile = DomainProfile(
        domain=host.lower(),
        registrable=reg,
        role=role,
        is_freemail=reg in freemail(),
        is_disposable=reg in disposable(),
    )
    indicator = Indicator(type=IndicatorType.domain, value=reg, origin=role)
    results: list[SourceResult] = []

    match = find_lookalike(reg, settings.protected_domain_list)
    if match:
        profile.lookalike_of, profile.lookalike_reason = match.target, match.reason
        profile.lookalike_strong = match.strong

    if with_mail_dns and settings.dns_enabled:
        key = f"dns:{reg}"
        data = await cache.get(key)
        cached = data is not None
        if data is None:
            data = await mail_dns(reg)
            if data["ok"]:
                await cache.set(key, data, 3600)
    if with_mail_dns and settings.dns_enabled and not data["ok"]:
        results.append(SourceResult(source="dns", indicator=indicator, status=SourceStatus.error,
                                    summary="DNS lookup failed (resolver unreachable or timed out)"))
    elif with_mail_dns and settings.dns_enabled:
        profile.mx, profile.spf = data["mx"], data["spf"]
        profile.dmarc, profile.dmarc_policy = data["dmarc"], data["dmarc_policy"]
        profile.null_mx = bool(data.get("null_mx"))
        profile.exists = not data.get("nxdomain")
        profile.mx_ips = data.get("mx_ips", [])
        profile.web_ips = data.get("web_ips", [])
        profile.has_website = bool(profile.web_ips)
        profile.mail_provider, profile.large_provider = identify(profile.mx)
        if profile.mx and not profile.mail_provider:
            profile.mail_provider = "self-hosted or unknown provider"
        profile.checks_run.append("dns")
        parts = [
            "null MX (accepts no mail)" if profile.null_mx else f"MX: {len(profile.mx)} record(s)" if profile.mx else "no MX record",
            "SPF present" if profile.spf else "no SPF",
            f"DMARC p={profile.dmarc_policy}" if profile.dmarc else "no DMARC",
            f"mail by {profile.mail_provider}" if profile.mail_provider else None,
            "website resolves" if profile.has_website else "no website (no A/AAAA record)",
        ]
        parts = [p for p in parts if p]
        if data.get("nxdomain"):
            parts = ["domain does not exist (NXDOMAIN)"]
        results.append(
            SourceResult(
                source="dns", indicator=indicator, status=SourceStatus.info, summary=", ".join(parts),
                details={"mx": profile.mx, "spf": profile.spf, "dmarc": profile.dmarc, "provider": profile.mail_provider}, cached=cached,
            )
        )

    if settings.rdap_enabled and not profile.is_freemail:
        key = f"rdap:{reg}"
        data = await cache.get(key)
        cached = data is not None
        if data is None:
            try:
                data = await rdap_lookup(reg, client)
            except (httpx.HTTPError, UnsafeURLError, ValueError) as exc:
                results.append(
                    SourceResult(source="rdap", indicator=indicator, status=SourceStatus.error,
                                 summary=f"RDAP lookup failed: {type(exc).__name__}")
                )
                data = None
            if data is not None:
                await cache.set(key, data, settings.cache_ttl_seconds)
        if data:
            profile.checks_run.append("rdap")
            if data.get("created"):
                created = datetime.fromisoformat(data["created"].replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=UTC)
                profile.created = created
                profile.age_days = (datetime.now(UTC) - created).days
            profile.registrar = data.get("registrar")
            summary = (
                f"registered {profile.created:%Y-%m-%d} ({profile.age_days} days ago)"
                if profile.created else "no registration date published"
            )
            if data.get("not_found"):
                summary = "not found in RDAP (unregistered or unsupported TLD)"
            results.append(
                SourceResult(source="rdap", indicator=indicator, status=SourceStatus.info, summary=summary,
                             details={"registrar": profile.registrar}, cached=cached)
            )
    return profile, results
