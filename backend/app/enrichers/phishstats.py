from urllib.parse import urlsplit

import httpx

from app.core.lists import brands, freemail, shorteners
from app.core.util import registrable_domain
from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus

API = "https://api.phishstats.info/api/phishing"


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


class PhishStats(Enricher):
    name = "phishstats"
    title = "PhishStats"
    indicator_types = {IndicatorType.url, IndicatorType.domain}
    needs_key = False
    per_minute = 20
    rate_limit = "50/day without a key, 150/day with a free key"
    licence_note = "Phishing URL database; shared platforms (big brands, free hosts) are reported as context only."
    signup_url = "https://phishstats.info/"

    def api_key(self) -> str:
        return self.settings.phishstats_api_key

    @property
    def budget(self) -> int | None:
        return 3

    def page_url(self, indicator: Indicator) -> str | None:
        host = _host(indicator.value) if indicator.type == IndicatorType.url else indicator.value.lower()
        # The public API answers anonymously in a browser: the result itself is the proof.
        return f"{API}?_where=(url,like,{host})&_sort=-id&_size=50" if host else None

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        host = _host(indicator.value) if indicator.type == IndicatorType.url else indicator.value.lower()
        if not host or not all(c.isalnum() or c in ".-" for c in host):
            return self.result(indicator, SourceStatus.skipped, "host not searchable")
        headers = {"X-API-Key": self.api_key()} if self.api_key() else {}
        resp = await client.get(
            API, params={"_where": f"(url,like,{host})", "_sort": "-id", "_size": 50}, headers=headers,
        )
        if resp.status_code == 429:
            return self.result(indicator, SourceStatus.skipped, "PhishStats daily quota reached")
        resp.raise_for_status()
        rows = resp.json() if isinstance(resp.json(), list) else []
        reg = registrable_domain(host)
        same = [r for r in rows if registrable_domain(_host(str(r.get("url", "")))) == reg]
        if not same:
            return self.result(indicator, SourceStatus.clean, "not in PhishStats")
        exact = [r for r in same if indicator.type == IndicatorType.url and str(r.get("url", "")).rstrip("/") == indicator.value.rstrip("/")]
        top = max((float(r.get("score") or 0) for r in same), default=0)
        details = {"matches": len(same), "max_score": top, "latest": str(same[0].get("date", ""))[:10],
                   "example": same[0].get("url")}
        if reg in brands() or reg in freemail() or reg in shorteners():
            return self.result(indicator, SourceStatus.info,
                               f"{len(same)} phishing URL(s) hosted on this shared platform; the platform itself is not the threat",
                               details=details)
        if exact:
            return self.result(indicator, SourceStatus.hit, "this exact URL is a reported phishing page",
                               severity="high", details=details)
        return self.result(indicator, SourceStatus.hit, f"{len(same)} reported phishing URL(s) on this domain",
                           severity="high" if top >= 5 or len(same) >= 3 else "medium", details=details)
