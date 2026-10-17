"""The enricher plugin contract.

Adding a source = one subclass in its own file + an entry in registry.py.
`lookup` gets one indicator and returns one SourceResult; it should never raise
for ordinary failures (the runner converts exceptions into `error` results).
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import ClassVar

import httpx

from app.core.config import Settings
from app.core.evidence import from_last_response
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus


class Enricher(ABC):
    name: ClassVar[str]
    title: ClassVar[str]
    indicator_types: ClassVar[set[IndicatorType]]
    needs_key: ClassVar[bool] = True
    per_minute: ClassVar[int | None] = None      # enforced by the runner
    rate_limit: ClassVar[str] = ""
    licence_note: ClassVar[str] = ""
    signup_url: ClassVar[str | None] = None
    sends_email_address: ClassVar[bool] = False  # blocked in privacy mode

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @abstractmethod
    def api_key(self) -> str: ...

    def configured(self) -> bool:
        return bool(self.api_key()) if self.needs_key else True

    def disabled(self) -> bool:
        return self.name in self.settings.disabled_source_set

    @property
    def budget(self) -> int | None:
        """Max lookups per analysis (None = unlimited). Protects small free quotas."""
        return None

    def supports(self, indicator: Indicator) -> bool:
        return indicator.type in self.indicator_types

    @abstractmethod
    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult: ...

    def page_url(self, indicator: Indicator) -> str | None:
        """Public page where an analyst can verify (and screenshot) this result."""
        return None

    # helpers -------------------------------------------------------------
    def result(self, indicator: Indicator, status: SourceStatus, summary: str, **kw) -> SourceResult:
        """Build a result with its evidence: time, redacted request, raw response, link."""
        if not kw.get("link"):
            kw["link"] = self.page_url(indicator)
        evidence = from_last_response()
        kw.setdefault("query", evidence.get("query"))
        kw.setdefault("raw", evidence.get("raw"))
        kw.setdefault("checked_at", datetime.now(UTC))
        return SourceResult(source=self.name, indicator=indicator, status=status, summary=summary, **kw)
