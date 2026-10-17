from urllib.parse import quote

import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus


class HaveIBeenPwned(Enricher):
    """Breach presence for an email address: 'found in N breaches', never the breached data.
    A sender that appears in many breaches is a candidate for account takeover."""

    name = "hibp"
    title = "Have I Been Pwned"
    indicator_types = {IndicatorType.email}
    per_minute = 10
    rate_limit = "Depends on your subscription tier"
    licence_note = "Requires a paid HIBP subscription. Sends the full address to HIBP (blocked in privacy mode)."
    signup_url = "https://haveibeenpwned.com/API/Key"
    sends_email_address = True

    def api_key(self) -> str:
        return self.settings.hibp_api_key

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(indicator.value)}",
            params={"truncateResponse": "true"},
            headers={"hibp-api-key": self.api_key()},
        )
        link = "https://haveibeenpwned.com/"
        if resp.status_code == 404:
            return self.result(indicator, SourceStatus.clean, "not found in any known breach", link=link)
        if resp.status_code == 429:
            return self.result(indicator, SourceStatus.skipped, "HIBP rate limit reached")
        resp.raise_for_status()
        breaches = [b.get("Name") for b in resp.json()]
        return self.result(indicator, SourceStatus.info,
                           f"appears in {len(breaches)} known breach(es); account takeover is possible",
                           severity="low", details={"breaches": breaches[:20]}, link=link)
