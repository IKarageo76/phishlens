"""Infrastructure context: CIRCL hashlookup (known-good files), Shodan InternetDB
(open services on an IP) and IPinfo Lite (network owner and country)."""

import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus

BAD_TAGS = {"compromised", "malware", "c2", "botnet", "doublepulsar", "honeypot"}
ANON_TAGS = {"tor", "proxy", "vpn"}


class CIRCLHashlookup(Enricher):
    name = "circl"
    title = "CIRCL hashlookup"
    indicator_types = {IndicatorType.hash}
    needs_key = False
    per_minute = 60
    rate_limit = "Free, best effort"
    licence_note = "Tells you a file is known (e.g. NSRL software); it never says a file is malicious."
    signup_url = "https://www.circl.lu/services/hashlookup/"

    def api_key(self) -> str:
        return ""

    def page_url(self, indicator: Indicator) -> str | None:
        algo = {32: "md5", 40: "sha1"}.get(len(indicator.value), "sha256")
        return f"https://hashlookup.circl.lu/lookup/{algo}/{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(indicator.value), "sha256")
        resp = await client.get(f"https://hashlookup.circl.lu/lookup/{algo}/{indicator.value}")
        if resp.status_code == 404:
            return self.result(indicator, SourceStatus.info, "not a known file (no verdict either way)")
        resp.raise_for_status()
        data = resp.json()
        trust = int(data.get("hashlookup:trust") or 50)
        name = data.get("FileName") or data.get("filename") or "known file"
        details = {"trust": trust, "file_name": name, "product": data.get("ProductName"), "known_good": trust >= 50}
        return self.result(indicator, SourceStatus.info, f"known file: {name} (trust {trust}/100)", details=details)


class InternetDB(Enricher):
    name = "internetdb"
    title = "Shodan InternetDB"
    indicator_types = {IndicatorType.ip}
    needs_key = False
    per_minute = 60
    rate_limit = "Free, no key"
    licence_note = "Free for non-commercial use; data refreshed weekly."
    signup_url = "https://internetdb.shodan.io/"

    def api_key(self) -> str:
        return ""

    def page_url(self, indicator: Indicator) -> str | None:
        return f"https://internetdb.shodan.io/{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.get(f"https://internetdb.shodan.io/{indicator.value}")
        if resp.status_code == 404:
            return self.result(indicator, SourceStatus.info, "no open services seen")
        resp.raise_for_status()
        d = resp.json()
        ports, vulns, tags = d.get("ports") or [], d.get("vulns") or [], [t.lower() for t in d.get("tags") or []]
        details = {"ports": ports, "vulns": vulns[:10], "vuln_count": len(vulns), "tags": tags, "hostnames": (d.get("hostnames") or [])[:5]}
        parts = [f"ports {', '.join(map(str, ports[:8]))}" if ports else "no open ports"]
        if vulns:
            parts.append(f"{len(vulns)} known CVE(s)")
        if tags:
            parts.append(f"tags: {', '.join(tags)}")
        summary = "; ".join(parts)
        link = None
        extra = [{"label": "Shodan host page (login needed)", "url": f"https://www.shodan.io/host/{indicator.value}"}]
        if set(tags) & BAD_TAGS:
            return self.result(indicator, SourceStatus.hit, summary, severity="medium", details=details, link=link, extra_links=extra)
        if set(tags) & ANON_TAGS:
            return self.result(indicator, SourceStatus.hit, summary, severity="low", details=details, link=link, extra_links=extra)
        return self.result(indicator, SourceStatus.info, summary, details=details, link=link, extra_links=extra)


class IPinfo(Enricher):
    name = "ipinfo"
    title = "IPinfo Lite"
    indicator_types = {IndicatorType.ip}
    per_minute = 120
    rate_limit = "Unlimited with a free token"
    licence_note = "Country and network owner (ASN). CC BY-SA 4.0, commercial use allowed."
    signup_url = "https://ipinfo.io/signup"

    def api_key(self) -> str:
        return self.settings.ipinfo_token

    def page_url(self, indicator: Indicator) -> str | None:
        return f"https://ipinfo.io/{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.get(f"https://api.ipinfo.io/lite/{indicator.value}", params={"token": self.api_key()})
        resp.raise_for_status()
        d = resp.json()
        details = {k: d.get(k) for k in ("asn", "as_name", "as_domain", "country", "country_code", "continent")}
        owner = " ".join(filter(None, [d.get("asn"), d.get("as_name")])) or "unknown network"
        where = d.get("country") or d.get("country_code") or "unknown country"
        return self.result(indicator, SourceStatus.info, f"{owner}, {where}", details=details)
