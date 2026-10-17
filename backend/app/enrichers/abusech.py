"""abuse.ch sources: URLhaus (malware URLs), ThreatFox (IOCs), MalwareBazaar (samples).
One free Auth-Key covers all three."""

from urllib.parse import quote

import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus


class _AbuseCH(Enricher):
    per_minute = 60
    rate_limit = "Free Auth-Key, fair use"
    licence_note = "abuse.ch data is free for commercial and non-commercial use under its terms of service."
    signup_url = "https://auth.abuse.ch/"

    def api_key(self) -> str:
        return self.settings.abusech_auth_key

    @property
    def headers(self) -> dict[str, str]:
        return {"Auth-Key": self.api_key()}


class URLhaus(_AbuseCH):
    name = "urlhaus"
    title = "URLhaus"
    indicator_types = {IndicatorType.url, IndicatorType.domain}

    def page_url(self, indicator: Indicator) -> str | None:
        return f"https://urlhaus.abuse.ch/browse.php?search={quote(indicator.value, safe='')}"

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        if indicator.type == IndicatorType.url:
            resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": indicator.value}, headers=self.headers)
        else:
            resp = await client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": indicator.value}, headers=self.headers)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")
        if status in ("no_results", "invalid_host", "invalid_url"):
            return self.result(indicator, SourceStatus.clean, "not listed in URLhaus")
        if status != "ok":
            return self.result(indicator, SourceStatus.error, f"URLhaus returned {status}")
        if indicator.type == IndicatorType.url:
            details = {"threat": data.get("threat"), "url_status": data.get("url_status"), "tags": data.get("tags")}
            summary = f"listed as {data.get('threat') or 'malware'} URL ({data.get('url_status')})"
        else:
            details = {"url_count": data.get("url_count"), "urls_online": sum(1 for u in data.get("urls", []) if u.get("url_status") == "online")}
            summary = f"host has {data.get('url_count')} known malware URL(s)"
        return self.result(indicator, SourceStatus.hit, summary, severity="high", details=details,
                           link=data.get("urlhaus_reference"))


class ThreatFox(_AbuseCH):
    name = "threatfox"
    title = "ThreatFox"
    indicator_types = {IndicatorType.domain, IndicatorType.ip, IndicatorType.url, IndicatorType.hash}

    def page_url(self, indicator: Indicator) -> str | None:
        return f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(indicator.value, safe='')}"

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": indicator.value, "exact_match": True},
            headers=self.headers,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok" or not data.get("data"):
            return self.result(indicator, SourceStatus.clean, "not listed in ThreatFox")
        first = data["data"][0]
        details = {
            "malware": first.get("malware_printable"),
            "threat_type": first.get("threat_type_desc"),
            "confidence": first.get("confidence_level"),
            "first_seen": first.get("first_seen"),
            "matches": len(data["data"]),
        }
        return self.result(indicator, SourceStatus.hit,
                           f"IOC for {first.get('malware_printable') or 'malware'} ({first.get('threat_type_desc')})",
                           severity="high", details=details,
                           link=f"https://threatfox.abuse.ch/ioc/{first.get('id')}/" if first.get("id") else None)


class MalwareBazaar(_AbuseCH):
    name = "malwarebazaar"
    title = "MalwareBazaar"
    indicator_types = {IndicatorType.hash}

    def page_url(self, indicator: Indicator) -> str | None:
        algo = {32: "md5", 40: "sha1"}.get(len(indicator.value), "sha256")
        return f"https://bazaar.abuse.ch/browse.php?search={algo}%3A{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": indicator.value},
                                 headers=self.headers)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok" or not data.get("data"):
            return self.result(indicator, SourceStatus.clean, "hash not in MalwareBazaar")
        sample = data["data"][0]
        details = {"signature": sample.get("signature"), "file_type": sample.get("file_type"),
                   "first_seen": sample.get("first_seen"), "tags": sample.get("tags")}
        return self.result(indicator, SourceStatus.hit,
                           f"known malware sample: {sample.get('signature') or sample.get('file_type')}",
                           severity="high", details=details,
                           link=f"https://bazaar.abuse.ch/sample/{sample.get('sha256_hash')}/")
