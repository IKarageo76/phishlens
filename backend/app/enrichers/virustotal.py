import base64

import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"


class VirusTotal(Enricher):
    name = "virustotal"
    title = "VirusTotal"
    indicator_types = {IndicatorType.url, IndicatorType.domain, IndicatorType.ip, IndicatorType.hash}
    per_minute = 4
    rate_limit = "Public API: 4 requests/min, 500/day"
    licence_note = (
        "The free public API must not be used in commercial products or business workflows. "
        "Use a premium key for work use."
    )
    signup_url = "https://www.virustotal.com/gui/join-us"

    def api_key(self) -> str:
        return self.settings.vt_api_key

    @property
    def budget(self) -> int | None:
        return self.settings.vt_max_lookups

    def page_url(self, indicator: Indicator) -> str | None:
        return self._paths(indicator)[1]

    def _paths(self, ind: Indicator) -> tuple[str, str]:
        if ind.type == IndicatorType.url:
            vid = base64.urlsafe_b64encode(ind.value.encode()).decode().strip("=")
            return f"/urls/{vid}", f"{GUI}/url/{vid}"
        if ind.type == IndicatorType.domain:
            return f"/domains/{ind.value}", f"{GUI}/domain/{ind.value}"
        if ind.type == IndicatorType.ip:
            return f"/ip_addresses/{ind.value}", f"{GUI}/ip-address/{ind.value}"
        return f"/files/{ind.value}", f"{GUI}/file/{ind.value}"

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        path, gui = self._paths(indicator)
        resp = await client.get(API + path, headers={"x-apikey": self.api_key()})
        if resp.status_code == 404:
            return self.result(indicator, SourceStatus.clean, "not seen by VirusTotal", link=gui)
        if resp.status_code == 429:
            return self.result(indicator, SourceStatus.skipped, "VirusTotal quota exhausted")
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or None
        details = {
            "malicious": malicious,
            "suspicious": suspicious,
            "engines": total,
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories"),
            "meaningful_name": attrs.get("meaningful_name"),
            "flagged_by": sorted(
                f"{engine}: {r.get('result') or r.get('category')}"
                for engine, r in (attrs.get("last_analysis_results") or {}).items()
                if r.get("category") in ("malicious", "suspicious")
            )[:30],
            "last_analysis": attrs.get("last_analysis_date"),
        }
        if malicious >= 3:
            return self.result(indicator, SourceStatus.hit, f"{malicious}/{total} engines flag it malicious",
                               severity="high", details=details, link=gui)
        if malicious or suspicious:
            return self.result(indicator, SourceStatus.hit,
                               f"{malicious} malicious, {suspicious} suspicious of {total} engines",
                               severity="medium", details=details, link=gui)
        return self.result(indicator, SourceStatus.clean, f"0/{total} engines flag it", details=details, link=gui)
