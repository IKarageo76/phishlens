from urllib.parse import quote

import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus

API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREATS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing / social engineering",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful application",
}


class SafeBrowsing(Enricher):
    name = "safebrowsing"
    title = "Google Safe Browsing"
    indicator_types = {IndicatorType.url}
    per_minute = 60
    rate_limit = "Free default quota per Google Cloud project"
    licence_note = "Free for non-commercial use only; commercial use needs Google Web Risk."
    signup_url = "https://developers.google.com/safe-browsing/v4/get-started"

    def api_key(self) -> str:
        return self.settings.gsb_api_key

    def page_url(self, indicator: Indicator) -> str | None:
        return f"https://transparencyreport.google.com/safe-browsing/search?url={quote(indicator.value, safe='')}"

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        body = {
            "client": {"clientId": "phishlens", "clientVersion": "0.3.0"},
            "threatInfo": {
                "threatTypes": list(THREATS),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": indicator.value}],
            },
        }
        resp = await client.post(API, params={"key": self.api_key()}, json=body)
        if resp.status_code == 429:
            return self.result(indicator, SourceStatus.skipped, "Safe Browsing quota exhausted")
        resp.raise_for_status()
        matches = resp.json().get("matches") or []
        if not matches:
            return self.result(indicator, SourceStatus.clean, "not on Google's unsafe lists")
        kinds = sorted({THREATS.get(m.get("threatType"), m.get("threatType", "unsafe")) for m in matches})
        return self.result(indicator, SourceStatus.hit, f"listed by Google as {', '.join(kinds)}",
                           severity="high", details={"threats": kinds})
