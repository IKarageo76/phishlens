# Adding an intelligence source

A source is one class in `backend/app/enrichers/`. The runner handles parallelism, caching, rate limits, missing keys and errors, so a source only answers one question about one indicator.

## 1. Write the enricher

```python
# backend/app/enrichers/otx.py
import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus


class OTX(Enricher):
    name = "otx"
    title = "AlienVault OTX"
    indicator_types = {IndicatorType.domain, IndicatorType.ip}
    per_minute = 60
    rate_limit = "Free key"
    licence_note = "Community threat intelligence."
    signup_url = "https://otx.alienvault.com/"

    def api_key(self) -> str:
        return self.settings.otx_api_key          # add the field to core/config.py

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        kind = "domain" if indicator.type == IndicatorType.domain else "IPv4"
        resp = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/{kind}/{indicator.value}/general",
            headers={"X-OTX-API-KEY": self.api_key()},
        )
        resp.raise_for_status()
        pulses = resp.json().get("pulse_info", {}).get("count", 0)
        if pulses:
            return self.result(indicator, SourceStatus.hit, f"in {pulses} OTX pulse(s)", severity="medium")
        return self.result(indicator, SourceStatus.clean, "no OTX pulses")
```

Return `hit` with a severity (`low`, `medium` or `high`), `clean`, or `info`. Raise on HTTP errors: the runner turns them into `error` results so one broken source never breaks an analysis.

## 2. Register it

Add the class to `ENRICHERS` in `backend/app/enrichers/registry.py`, and add its title to `sourceTitle` in `frontend/src/lib/format.ts`.

## 3. Use it in scoring (optional)

If its hits should move the score, map them to a signal in `backend/app/scoring/engine.py` and give that signal a weight in `weights.yaml`.

## 4. Test it

Mock the HTTP call with `respx` and assert the status and summary. See `backend/tests/test_enrichers.py` for examples.
