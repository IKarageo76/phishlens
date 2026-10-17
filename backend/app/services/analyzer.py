"""Orchestrates one analysis: parse -> extract indicators -> enrich in parallel -> score."""

import asyncio
import uuid
from datetime import UTC, datetime

import httpx

from app.analysis.domain import build_profile
from app.core.cache import Cache
from app.core.config import Settings
from app.core.http import UnsafeURLError, assert_public_url
from app.core.util import classify_input, domain_of_email, refang, registrable_domain
from app.enrichers.registry import run_enrichers
from app.models.schemas import (
    DomainProfile,
    Indicator,
    IndicatorType,
    Link,
    Report,
    SourceResult,
)
from app.parsers.eml import ParsedEmail, build_links, parse_eml
from app.scoring.engine import evaluate

MAX_LINK_DOMAINS = 8


class InvalidInput(ValueError):
    pass


def _dedupe(indicators: list[Indicator]) -> list[Indicator]:
    seen: set[str] = set()
    out: list[Indicator] = []
    for ind in indicators:
        if ind.key not in seen:
            seen.add(ind.key)
            out.append(ind)
    return out


async def _unshorten(link: Link, client: httpx.AsyncClient) -> None:
    """Resolve a shortener by reading redirect headers only (HEAD, no body, SSRF-checked)."""
    url = link.url
    for _ in range(5):
        try:
            await assert_public_url(url, allow_http=True)
            resp = await client.head(url)
        except (httpx.HTTPError, UnsafeURLError):
            return
        location = resp.headers.get("location")
        if resp.status_code not in (301, 302, 303, 307, 308) or not location:
            break
        url = str(httpx.URL(url).join(location))
    if url != link.url:
        link.final_url = url


async def _profiles(
    hosts: list[tuple[str, str, bool]], settings: Settings, client: httpx.AsyncClient, cache: Cache
) -> tuple[list[DomainProfile], list[SourceResult]]:
    tasks = [build_profile(h, role, settings, client, cache, mail) for h, role, mail in hosts]
    done = await asyncio.gather(*tasks)
    profiles = [p for p, _ in done]
    results = [r for _, rs in done for r in rs]
    return profiles, results


def _finish(
    *,
    input_type: str,
    input_value: str,
    title: str,
    profiles: list[DomainProfile],
    indicators: list[Indicator],
    results: list[SourceResult],
    parsed: ParsedEmail | None = None,
    links: list[Link] | None = None,
    notes: list[str] | None = None,
) -> Report:
    links = links if links is not None else (parsed.links if parsed else [])
    attachments = parsed.attachments if parsed else []
    headers = parsed.headers if parsed else None
    signals, verdict = evaluate(
        input_type=input_type, headers=headers, links=links,
        attachments=attachments, domains=profiles, results=results,
        body_text=parsed.text_body if parsed else "",
    )
    preview = None
    if parsed and parsed.text_body:
        preview = parsed.text_body.strip()[:3000]
    return Report(
        id=str(uuid.uuid4()),
        created_at=datetime.now(UTC),
        input_type=input_type,
        input_value=input_value,
        title=title,
        headers=headers,
        body_preview=preview,
        links=links,
        attachments=attachments,
        domains=profiles,
        indicators=indicators,
        results=results,
        signals=signals,
        verdict=verdict,
        notes=notes or [],
    )


async def analyze_value(value: str, settings: Settings, client: httpx.AsyncClient, cache: Cache) -> Report:
    clean = refang(value.strip())
    kind = classify_input(clean)
    if kind == "unknown":
        raise InvalidInput("Enter an email address, domain, URL, IP address or file hash.")

    hosts: list[tuple[str, str, bool]] = []
    indicators: list[Indicator] = []
    links: list[Link] = []

    if kind == "email_address":
        clean = clean.lower()
        domain = domain_of_email(clean) or ""
        hosts.append((domain, "input", True))
        indicators += [Indicator(type=IndicatorType.domain, value=registrable_domain(domain), origin="input"),
                       Indicator(type=IndicatorType.email, value=clean, origin="input")]
    elif kind == "domain":
        clean = clean.lower()
        hosts.append((clean, "input", True))
        indicators.append(Indicator(type=IndicatorType.domain, value=registrable_domain(clean), origin="input"))
    elif kind == "url":
        links = build_links([(clean, None)])
        if not links:
            raise InvalidInput("Only http and https URLs can be analysed.")
        link = links[0]
        if settings.unshorten_enabled and link.is_shortener:
            await _unshorten(link, client)
        indicators.append(Indicator(type=IndicatorType.url, value=link.url, origin="input"))
        if link.final_url:
            indicators.append(Indicator(type=IndicatorType.url, value=link.final_url, origin="redirect"))
        for u in filter(None, [link.url, link.final_url]):
            host = httpx.URL(u).host
            if host:
                hosts.append((host, "link", False))
                indicators.append(Indicator(type=IndicatorType.domain, value=registrable_domain(host), origin="input"))
    elif kind == "ip":
        indicators.append(Indicator(type=IndicatorType.ip, value=clean, origin="input"))
    elif kind == "hash":
        indicators.append(Indicator(type=IndicatorType.hash, value=clean.lower(), origin="input"))

    indicators = _dedupe(indicators)
    profiles, local_results = await _profiles(hosts, settings, client, cache)
    intel = await run_enrichers(indicators, settings, client, cache)
    return _finish(
        input_type=kind,
        input_value=clean,
        title=clean,
        profiles=profiles,
        indicators=indicators,
        results=local_results + intel,
        links=links,
    )


async def analyze_eml(raw: bytes, filename: str, settings: Settings, client: httpx.AsyncClient, cache: Cache) -> Report:
    try:
        parsed = parse_eml(raw)
    except Exception as exc:  # noqa: BLE001
        raise InvalidInput(f"Could not parse the email: {type(exc).__name__}") from exc
    h = parsed.headers
    if not (h.from_address or h.subject or h.hops):
        raise InvalidInput("This does not look like an email message (no From, Subject or Received headers).")

    if settings.unshorten_enabled:
        await asyncio.gather(*(_unshorten(l, client) for l in parsed.links if l.is_shortener))

    sender_dom = domain_of_email(h.from_address)
    reply_dom = domain_of_email(h.reply_to)
    hosts: list[tuple[str, str, bool]] = []
    if sender_dom:
        hosts.append((sender_dom, "sender", True))
    if reply_dom and registrable_domain(reply_dom) != registrable_domain(sender_dom or ""):
        hosts.append((reply_dom, "reply_to", True))
    taken = {registrable_domain(x) for x, _, _ in hosts}
    link_domains: list[str] = []
    for link in parsed.links:
        for u in filter(None, [link.url, link.final_url]):
            host = httpx.URL(u).host
            reg = registrable_domain(host) if host else ""
            if reg and reg not in taken and len(link_domains) < MAX_LINK_DOMAINS:
                taken.add(reg)
                link_domains.append(host)
    hosts += [(d, "link", False) for d in link_domains]

    flagged = [l for l in parsed.links if l.deceptive or l.is_shortener]
    others = [l for l in parsed.links if l not in flagged]
    ordered_links = (flagged + others)[: settings.max_urls_per_analysis]

    indicators: list[Indicator] = [
        Indicator(type=IndicatorType.hash, value=a.sha256, origin="attachment") for a in parsed.attachments
    ]
    indicators += [Indicator(type=IndicatorType.url, value=l.final_url or l.url, origin="body") for l in ordered_links[: len(flagged)]]
    if sender_dom:
        indicators.append(Indicator(type=IndicatorType.domain, value=registrable_domain(sender_dom), origin="header"))
    if h.origin_ip:
        indicators.append(Indicator(type=IndicatorType.ip, value=h.origin_ip, origin="header"))
    indicators += [Indicator(type=IndicatorType.url, value=l.final_url or l.url, origin="body") for l in ordered_links[len(flagged):]]
    indicators += [Indicator(type=IndicatorType.domain, value=registrable_domain(d), origin="body") for d in link_domains]
    if reply_dom:
        indicators.append(Indicator(type=IndicatorType.domain, value=registrable_domain(reply_dom), origin="header"))
    if h.from_address:
        indicators.append(Indicator(type=IndicatorType.email, value=h.from_address, origin="header"))
    indicators = _dedupe(indicators)

    profiles, local_results = await _profiles(hosts, settings, client, cache)
    intel = await run_enrichers(indicators, settings, client, cache)

    notes = ["Attachments were hashed in memory and discarded; file contents are never stored or opened."]
    if len(parsed.links) > len(ordered_links):
        notes.append(f"{len(parsed.links) - len(ordered_links)} more link(s) were extracted but not looked up (limit {settings.max_urls_per_analysis}).")
    return _finish(
        input_type="eml",
        input_value=filename,
        title=h.subject or filename,
        profiles=profiles,
        indicators=indicators,
        results=local_results + intel,
        parsed=parsed,
        notes=notes,
    )
