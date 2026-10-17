import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus

API = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB(Enricher):
    name = "abuseipdb"
    title = "AbuseIPDB"
    indicator_types = {IndicatorType.ip}
    per_minute = 60
    rate_limit = "Free: 1,000 checks/day"
    licence_note = "Attribution to AbuseIPDB is required when presenting results."
    signup_url = "https://www.abuseipdb.com/register"

    def api_key(self) -> str:
        return self.settings.abuseipdb_api_key

    def page_url(self, indicator: Indicator) -> str | None:
        return f"https://www.abuseipdb.com/check/{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.get(
            API,
            params={"ipAddress": indicator.value, "maxAgeInDays": 90},
            headers={"Key": self.api_key(), "Accept": "application/json"},
        )
        if resp.status_code == 429:
            return self.result(indicator, SourceStatus.skipped, "AbuseIPDB daily quota exhausted")
        resp.raise_for_status()
        d = resp.json().get("data", {})
        score = int(d.get("abuseConfidenceScore", 0))
        details = {
            "abuse_score": score,
            "reports": d.get("totalReports"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "usage_type": d.get("usageType"),
            "whitelisted": d.get("isWhitelisted"),
            "last_reported": d.get("lastReportedAt"),
        }
        link = f"https://www.abuseipdb.com/check/{indicator.value}"
        where = ", ".join(filter(None, [d.get("isp"), d.get("countryCode")]))
        if score >= 50:
            return self.result(indicator, SourceStatus.hit, f"abuse score {score}/100, {d.get('totalReports')} reports ({where})",
                               severity="high" if score >= 80 else "medium", details=details, link=link)
        if score > 0:
            return self.result(indicator, SourceStatus.hit, f"abuse score {score}/100 ({where})",
                               severity="low", details=details, link=link)
        return self.result(indicator, SourceStatus.clean, f"no abuse reports ({where})", details=details, link=link)
