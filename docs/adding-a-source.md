# Adding an intelligence source

A source is one class in `backend/app/enrichers/`. The runner handles parallelism, caching, rate limits, missing keys and errors, so a source only answers one question about one indicator.

## 1. Write the enricher

```python
# backend/app/enrichers/example.py
import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus


class ExampleIntel(Enricher):
    name = "example"
    title = "Example Intel"
    indicator_types = {IndicatorType.domain, IndicatorType.ip}
    per_minute = 60
    rate_limit = "Free key"
    licence_note = "Community threat intelligence."
    signup_url = "https://example.com/"

    def api_key(self) -> str:
        return self.settings.example_api_key      # add the field to core/config.py

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        resp = await client.get(f"https://api.example.com/v1/lookup/{indicator.value}",
                                headers={"Authorization": f"Bearer {self.api_key()}"})
        resp.raise_for_status()
        reports = resp.json().get("reports", 0)
        if reports:
            return self.result(indicator, SourceStatus.hit, f"{reports} report(s)", severity="medium")
        return self.result(indicator, SourceStatus.clean, "no reports")
```

Return `hit` with a severity (`low`, `medium` or `high`), `clean`, or `info`. Raise on HTTP errors: the runner turns them into `error` results so one broken source never breaks an analysis.

## 2. Register it

Real examples to copy: `otx.py` (optional key), `stopforumspam.py` (no key), `spamhaus.py` (DNS-based).

Add the class to `ENRICHERS` in `backend/app/enrichers/registry.py`, and add its title to `sourceTitle` in `frontend/src/lib/format.ts`.

## 3. Use it in scoring (optional)

Set `needs_key = False` for sources that work without a key, and override `budget` to cap lookups per analysis on small free quotas.

If its hits should move the score, map them to a signal in `backend/app/scoring/engine.py` and give that signal a weight in `weights.yaml`.

## 4. Test it

Mock the HTTP call with `respx` and assert the status and summary. See `backend/tests/test_enrichers.py` for examples.
