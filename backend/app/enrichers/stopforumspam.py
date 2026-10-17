import hashlib

import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus

API = "https://api.stopforumspam.org/api"


class StopForumSpam(Enricher):
    """Spam reports for an email address or IP. Addresses are sent as an MD5 hash,
    never in clear text."""

    name = "stopforumspam"
    title = "StopForumSpam"
    indicator_types = {IndicatorType.email, IndicatorType.ip}
    needs_key = False
    per_minute = 60
    rate_limit = "20,000 queries/day, no key"
    licence_note = "Non-commercial use only. Email addresses are sent as MD5 hashes."
    signup_url = "https://www.stopforumspam.com/"

    def api_key(self) -> str:
        return ""

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        if indicator.type == IndicatorType.email:
            params = {"emailhash": hashlib.md5(indicator.value.strip().lower().encode()).hexdigest()}  # noqa: S324
            keys = ("emailhash", "email")
            what = "address"
        else:
            params = {"ip": indicator.value}
            keys = ("ip",)
            what = "IP"
        resp = await client.get(API, params={**params, "json": "", "confidence": ""})
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            return self.result(indicator, SourceStatus.error, f"StopForumSpam error: {data.get('error', 'unknown')}")
        entry = next((data[k] for k in keys if isinstance(data.get(k), dict)), {})
        if not int(entry.get("appears") or 0):
            return self.result(indicator, SourceStatus.clean, f"no spam reports for this {what}")
        freq = int(entry.get("frequency") or 0)
        conf = float(entry.get("confidence") or 0)
        details = {"reports": freq, "confidence": conf, "last_seen": entry.get("lastseen")}
        severity = "medium" if conf >= 25 or freq >= 5 else "low"
        seen = f", last {str(entry.get('lastseen'))[:10]}" if entry.get("lastseen") else ""
        return self.result(indicator, SourceStatus.hit,
                           f"{what} reported for spam {freq} time(s) (confidence {conf:.0f}%{seen})",
                           severity=severity, details=details,
                           link="https://www.stopforumspam.com/search?q=" + (indicator.value if what == "IP" else ""))
