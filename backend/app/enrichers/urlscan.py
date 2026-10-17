from urllib.parse import urlsplit

import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus

API = "https://urlscan.io/api/v1/search/"


class URLScan(Enricher):
    """Search existing scans only. New submissions publish the URL and spend quota,
    so they are never made automatically."""

    name = "urlscan"
    title = "urlscan.io"
    indicator_types = {IndicatorType.url, IndicatorType.domain}
    per_minute = 30
    rate_limit = "Free key; search quota per day/hour on your account"
    licence_note = "Searching existing scans only; PhishLens never submits URLs automatically."
    signup_url = "https://urlscan.io/user/signup"

    def api_key(self) -> str:
        return self.settings.urlscan_api_key

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        if indicator.type == IndicatorType.url:
            host = urlsplit(indicator.value).hostname or indicator.value
            query = f'page.url:"{indicator.value}" OR page.domain:{host}'
        else:
            query = f"page.domain:{indicator.value}"
        resp = await client.get(API, params={"q": query, "size": 10}, headers={"API-Key": self.api_key()})
        if resp.status_code == 429:
            return self.result(indicator, SourceStatus.skipped, "urlscan quota exhausted")
        resp.raise_for_status()
        hits = resp.json().get("results", [])
        if not hits:
            return self.result(indicator, SourceStatus.info, "no previous scans")
        latest = hits[0]
        uuid = latest.get("_id") or latest.get("task", {}).get("uuid")
        malicious = [h for h in hits if (h.get("verdicts") or {}).get("overall", {}).get("malicious")]
        details = {
            "scans": len(hits),
            "latest_url": latest.get("page", {}).get("url"),
            "latest_ip": latest.get("page", {}).get("ip"),
            "latest_country": latest.get("page", {}).get("country"),
            "latest_time": latest.get("task", {}).get("time"),
            "screenshot": latest.get("screenshot"),
            "malicious_scans": len(malicious),
        }
        link = f"https://urlscan.io/result/{uuid}/" if uuid else None
        if malicious:
            return self.result(indicator, SourceStatus.hit, f"{len(malicious)} of {len(hits)} recent scans marked malicious",
                               severity="high", details=details, link=link)
        return self.result(indicator, SourceStatus.info, f"{len(hits)} previous scan(s), none marked malicious",
                           details=details, link=link)
