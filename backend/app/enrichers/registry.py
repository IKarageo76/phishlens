"""Source registry and the runner that fans lookups out in parallel."""

import asyncio
from collections import defaultdict

import httpx

from app.core.cache import Cache
from app.core.config import Settings
from app.core.http import rate_limiter
from app.enrichers.abusech import MalwareBazaar, ThreatFox, URLhaus
from app.enrichers.abuseipdb import AbuseIPDB
from app.enrichers.base import Enricher
from app.enrichers.hibp import HaveIBeenPwned
from app.enrichers.urlscan import URLScan
from app.enrichers.virustotal import VirusTotal
from app.models.schemas import Indicator, SourceResult, SourceStatus

ENRICHERS: list[type[Enricher]] = [VirusTotal, AbuseIPDB, URLScan, URLhaus, ThreatFox, MalwareBazaar, HaveIBeenPwned]


def build_enrichers(settings: Settings) -> list[Enricher]:
    return [cls(settings) for cls in ENRICHERS]


async def run_enrichers(
    indicators: list[Indicator],
    settings: Settings,
    client: httpx.AsyncClient,
    cache: Cache,
    enrichers: list[Enricher] | None = None,
) -> list[SourceResult]:
    """Run every applicable source for every indicator.

    `indicators` must already be ordered by priority: per-analysis budgets (e.g. the
    VirusTotal free tier) are spent on the first ones and the rest are reported as
    skipped, never silently dropped.
    """
    enrichers = enrichers if enrichers is not None else build_enrichers(settings)
    results: list[SourceResult] = []
    jobs: list[tuple[Enricher, Indicator]] = []
    budget_used: dict[str, int] = defaultdict(int)
    budgets = {"virustotal": settings.vt_max_lookups}
    over_budget: dict[str, list[str]] = defaultdict(list)

    for enricher in enrichers:
        applicable = [i for i in indicators if enricher.supports(i)]
        if not applicable:
            continue
        if not enricher.configured():
            results.append(SourceResult(source=enricher.name, indicator=applicable[0], status=SourceStatus.skipped,
                                        summary="no API key configured"))
            continue
        if enricher.sends_email_address and settings.privacy_mode:
            results.append(SourceResult(source=enricher.name, indicator=applicable[0], status=SourceStatus.skipped,
                                        summary="privacy mode: full email addresses are not sent to third parties"))
            continue
        for ind in applicable:
            limit = budgets.get(enricher.name)
            cached = await cache.get(f"{enricher.name}:{ind.key}")
            if cached is not None:
                result = SourceResult.model_validate(cached)
                result.cached = True
                results.append(result)
                continue
            if limit is not None and budget_used[enricher.name] >= limit:
                over_budget[enricher.name].append(ind.value)
                continue
            budget_used[enricher.name] += 1
            jobs.append((enricher, ind))

    async def _run(enricher: Enricher, ind: Indicator) -> SourceResult:
        if not rate_limiter.try_acquire(enricher.name, enricher.per_minute):
            return enricher.result(ind, SourceStatus.skipped, f"rate limit ({enricher.per_minute}/min) reached; retry shortly")
        try:
            result = await enricher.lookup(ind, client)
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            reason = "API key rejected" if code in (401, 403) else f"HTTP {code}"
            return enricher.result(ind, SourceStatus.error, reason)
        except httpx.HTTPError as exc:
            return enricher.result(ind, SourceStatus.error, f"network error: {type(exc).__name__}")
        except (ValueError, KeyError, TypeError) as exc:
            return enricher.result(ind, SourceStatus.error, f"unexpected response: {type(exc).__name__}")
        if result.status in (SourceStatus.hit, SourceStatus.clean, SourceStatus.info):
            await cache.set(f"{enricher.name}:{ind.key}", result.model_dump(mode="json"), settings.cache_ttl_seconds)
        return result

    results += await asyncio.gather(*(_run(e, i) for e, i in jobs))

    for name, values in over_budget.items():
        enricher = next(e for e in enrichers if e.name == name)
        first = next(i for i in indicators if i.value == values[0])
        results.append(enricher.result(
            first, SourceStatus.skipped,
            f"{len(values)} lower-priority indicator(s) skipped to protect the free-tier quota",
            details={"skipped": values},
        ))
    return results
