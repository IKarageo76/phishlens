"""Pydantic models shared by the parsers, enrichers, scoring engine and API."""

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    url = "url"
    domain = "domain"
    ip = "ip"
    email = "email"
    hash = "hash"


class Indicator(BaseModel):
    type: IndicatorType
    value: str
    origin: str = Field(description="Where it was found: input, header, body, attachment")

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.value.lower()}"


class SourceStatus(str, Enum):
    hit = "hit"            # source reports the indicator as malicious/suspicious
    clean = "clean"        # source checked it and found nothing bad
    info = "info"          # neutral facts (e.g. domain age, prior scans)
    skipped = "skipped"    # not run: missing key, quota budget, privacy mode
    error = "error"        # run but failed (timeout, HTTP error)


class SourceResult(BaseModel):
    source: str
    indicator: Indicator
    status: SourceStatus
    summary: str
    severity: Literal["none", "low", "medium", "high"] = "none"
    details: dict[str, Any] = Field(default_factory=dict)
    link: str | None = None
    cached: bool = False
    checked_at: datetime | None = None
    query: str | None = None
    raw: Any | None = None
    extra_links: list[dict[str, str]] = Field(default_factory=list)


class AuthResults(BaseModel):
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    raw: list[str] = Field(default_factory=list)


class Hop(BaseModel):
    index: int
    from_host: str | None = None
    by_host: str | None = None
    ip: str | None = None
    timestamp: datetime | None = None
    delay_seconds: float | None = None


class HeaderAnalysis(BaseModel):
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None
    from_display: str | None = None
    from_address: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    to: list[str] = Field(default_factory=list)
    auth: AuthResults = Field(default_factory=AuthResults)
    hops: list[Hop] = Field(default_factory=list)
    origin_ip: str | None = None
    mismatches: list[str] = Field(default_factory=list)
    x_mailer: str | None = None
    raw_headers: list[tuple[str, str]] = Field(default_factory=list)


class Link(BaseModel):
    url: str
    defanged: str
    domain: str | None = None
    display_text: str | None = None
    is_shortener: bool = False
    deceptive: bool = False
    final_url: str | None = None


class Attachment(BaseModel):
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    detected_type: str
    risky: bool = False
    reasons: list[str] = Field(default_factory=list)


class DomainProfile(BaseModel):
    domain: str
    registrable: str
    role: Literal["sender", "reply_to", "link", "input"] = "input"
    mx: list[str] = Field(default_factory=list)
    spf: str | None = None
    dmarc: str | None = None
    dmarc_policy: str | None = None
    created: datetime | None = None
    age_days: int | None = None
    registrar: str | None = None
    is_freemail: bool = False
    is_disposable: bool = False
    lookalike_of: str | None = None
    lookalike_reason: str | None = None
    lookalike_strong: bool = False
    exists: bool | None = None
    null_mx: bool = False
    mail_provider: str | None = None
    large_provider: bool = False
    mx_ips: list[str] = Field(default_factory=list)
    web_ips: list[str] = Field(default_factory=list)
    has_website: bool | None = None
    checks_run: list[str] = Field(default_factory=list)


class AddressProfile(BaseModel):
    address: str
    local_part: str
    role_word: str | None = None
    plus_tag: str | None = None
    looks_random: bool = False
    random_reasons: list[str] = Field(default_factory=list)


class Signal(BaseModel):
    id: str
    label: str
    weight: int
    evidence: str
    source: str


class VerdictLabel(str, Enum):
    likely_legitimate = "likely_legitimate"
    suspicious = "suspicious"
    malicious = "malicious"


class Verdict(BaseModel):
    score: int
    label: VerdictLabel
    confidence: Literal["low", "medium", "high"]
    sources_run: int
    sources_skipped: int
    hard_override: bool = False
    reasons: list[str] = Field(default_factory=list)


class Report(BaseModel):
    id: str
    created_at: datetime
    input_type: Literal["email_address", "domain", "url", "ip", "hash", "eml"]
    input_value: str
    title: str
    headers: HeaderAnalysis | None = None
    body_preview: str | None = None
    links: list[Link] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    domains: list[DomainProfile] = Field(default_factory=list)
    address: AddressProfile | None = None
    indicators: list[Indicator] = Field(default_factory=list)
    results: list[SourceResult] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)
    verdict: Verdict
    notes: list[str] = Field(default_factory=list)


class ReportSummary(BaseModel):
    id: str
    created_at: datetime
    input_type: str
    title: str
    score: int
    label: VerdictLabel


class IndicatorRequest(BaseModel):
    value: str = Field(min_length=1, max_length=2048)


class SourceInfo(BaseModel):
    name: str
    title: str
    configured: bool
    needs_key: bool
    indicator_types: list[str]
    rate_limit: str
    licence_note: str
    signup_url: str | None = None
