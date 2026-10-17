from urllib.parse import quote

import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus

API = "https://otx.alienvault.com/api/v1/indicators"


class OTX(Enricher):
    """AlienVault OTX community pulses. Works without a key (lower rate limit)."""

    name = "otx"
    title = "AlienVault OTX"
    indicator_types = {IndicatorType.domain, IndicatorType.ip, IndicatorType.url, IndicatorType.hash}
    needs_key = False
    per_minute = 60
    rate_limit = "1,000 requests/hour without a key, 10,000/hour with a free key"
    licence_note = "Community threat intelligence; pulses can be noisy, so hits add a small weight."
    signup_url = "https://otx.alienvault.com/"

    def api_key(self) -> str:
        return self.settings.otx_api_key

    def _section(self, ind: Indicator) -> str:
        if ind.type == IndicatorType.ip:
            return "IPv6" if ":" in ind.value else "IPv4"
        return {IndicatorType.domain: "domain", IndicatorType.url: "url", IndicatorType.hash: "file"}[ind.type]

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        section = self._section(indicator)
        headers = {"X-OTX-API-KEY": self.api_key()} if self.api_key() else {}
        value = quote(indicator.value, safe=":/") if indicator.type == IndicatorType.url else indicator.value
        resp = await client.get(f"{API}/{section}/{value}/general", headers=headers)
        page = f"https://otx.alienvault.com/indicator/{section.lower() if section != 'IPv4' else 'ip'}/{indicator.value}"
        if resp.status_code == 404:
            return self.result(indicator, SourceStatus.clean, "not in OTX")
        if resp.status_code == 429:
            return self.result(indicator, SourceStatus.skipped, "OTX rate limit reached")
        resp.raise_for_status()
        data = resp.json()
        pulse_info = data.get("pulse_info") or {}
        count = int(pulse_info.get("count") or 0)
        pulses = pulse_info.get("pulses") or []
        validation = data.get("validation") or []
        details = {
            "pulses": count,
            "pulse_names": [p.get("name") for p in pulses[:5]],
            "malware_families": sorted({m.get("display_name") for p in pulses for m in (p.get("malware_families") or []) if isinstance(m, dict) and m.get("display_name")})[:5],
            "allowlisted": [v.get("message") or v.get("name") for v in validation],
        }
        if validation:
            return self.result(indicator, SourceStatus.clean,
                               f"allowlisted by OTX ({details['allowlisted'][0]})" + (f"; in {count} pulse(s)" if count else ""),
                               details=details, link=page)
        if count == 0:
            return self.result(indicator, SourceStatus.clean, "in no OTX pulses", details=details, link=page)
        first = details["pulse_names"][0] if details["pulse_names"] else "a pulse"
        severity = "medium" if count >= 3 or details["malware_families"] else "low"
        return self.result(indicator, SourceStatus.hit, f"in {count} OTX pulse(s), e.g. '{first}'",
                           severity=severity, details=details, link=page)

