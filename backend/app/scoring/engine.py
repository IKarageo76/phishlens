"""Explainable scoring: every point of the score comes from a named signal with evidence."""

import re
from functools import lru_cache
from pathlib import Path

import yaml

from app.core.lists import brands
from app.core.util import domain_label
from app.models.schemas import (
    AddressProfile,
    Attachment,
    DomainProfile,
    HeaderAnalysis,
    Link,
    Signal,
    SourceResult,
    SourceStatus,
    Verdict,
    VerdictLabel,
)

WEIGHTS_FILE = Path(__file__).with_name("weights.yaml")
INTEL_SOURCES = {"urlhaus", "threatfox", "malwarebazaar", "virustotal", "safebrowsing", "spamhaus", "phishstats"}
CORPORATE_WORDS = re.compile(
    r"\b(support|billing|accounts?|security|admin|administrator|team|service|services|payroll|hr|"
    r"invoices?|helpdesk|help desk|it department|finance|ceo|director|bank|delivery|customer care)\b",
    re.IGNORECASE,
)
BEC_MONEY = re.compile(r"\b(iban|swift|bic|bank (?:details|account)|wire transfer|payment|invoice|remittance|gift cards?)\b", re.I)
BEC_PRESSURE = re.compile(r"\b(urgent(?:ly)?|today|immediately|asap|changed|new (?:bank|account)|updated|frozen|confidential|do not call)\b", re.I)
RISKY_TLDS = {
    "top", "xyz", "click", "zip", "mov", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "cam",
    "icu", "sbs", "cfd", "bond", "buzz", "monster", "quest", "lol", "support", "live",
}


@lru_cache
def load_weights(path: str = str(WEIGHTS_FILE)) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class _Collector:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg["signals"]
        self.signals: dict[str, Signal] = {}

    def add(self, sid: str, evidence: str, source: str) -> None:
        if sid in self.signals or sid not in self.cfg:
            return
        spec = self.cfg[sid]
        self.signals[sid] = Signal(id=sid, label=spec["label"], weight=int(spec["weight"]), evidence=evidence, source=source)


def evaluate(
    *,
    input_type: str,
    headers: HeaderAnalysis | None,
    links: list[Link],
    attachments: list[Attachment],
    domains: list[DomainProfile],
    results: list[SourceResult],
    body_text: str = "",
    address: AddressProfile | None = None,
) -> tuple[list[Signal], Verdict]:
    cfg = load_weights()
    c = _Collector(cfg)

    # --- threat intelligence hits -------------------------------------------------
    for r in results:
        if r.status != SourceStatus.hit:
            continue
        what = f"{r.indicator.type.value} {r.indicator.value}"
        if r.source in INTEL_SOURCES and r.severity == "high":
            c.add("known_malicious", f"{r.source}: {r.summary} ({what})", r.source)
        elif r.source == "urlscan":
            c.add("phishing_page", f"urlscan: {r.summary} ({what})", r.source)
        elif r.source == "virustotal" and r.severity == "medium":
            c.add("vt_suspicious", f"VirusTotal: {r.summary} ({what})", r.source)
        elif r.source == "abuseipdb" and r.severity in ("medium", "high"):
            c.add("ip_abuse", f"AbuseIPDB: {r.summary} ({r.indicator.value})", r.source)
        elif r.source == "spamhaus":
            if r.details.get("zrd_hours"):
                c.add("zero_reputation", f"Spamhaus: {r.indicator.value} {r.summary}", r.source)
            if r.details.get("block_severity") == "medium":
                c.add("spamhaus_listed", f"Spamhaus: {r.summary} ({what})", r.source)
        elif r.source == "phishstats":
            c.add("phishing_db", f"PhishStats: {r.summary} ({what})", r.source)
        elif r.source == "otx":
            c.add("otx_pulses", f"OTX: {r.summary} ({what})", r.source)
        elif r.source == "stopforumspam" and r.severity in ("medium", "high"):
            c.add("spam_reports", f"StopForumSpam: {r.summary} ({what})", r.source)
        elif r.source == "internetdb" and r.severity in ("medium", "high"):
            c.add("risky_host", f"Shodan InternetDB: {r.summary} ({r.indicator.value})", r.source)

    # --- header and authentication checks -----------------------------------------
    if headers:
        auth = headers.auth
        if auth.dmarc == "fail":
            c.add("dmarc_fail", "Authentication-Results: dmarc=fail", "headers")
        failed = [f"{k}={v}" for k, v in (("spf", auth.spf), ("dkim", auth.dkim)) if v in ("fail", "softfail", "permerror")]
        if failed:
            c.add("auth_fail", "Authentication-Results: " + ", ".join(failed), "headers")
        for m in headers.mismatches:
            if m.startswith("Reply-To"):
                c.add("reply_to_mismatch", m, "headers")
            elif m.startswith("Return-Path") and auth.dmarc != "pass":
                c.add("return_path_mismatch", m, "headers")
            elif m.startswith("Display name"):
                c.add("display_name_spoof", m, "headers")

    # --- domains ------------------------------------------------------------------
    sender_roles = {"sender", "input"}
    for d in domains:
        if d.lookalike_of:
            sid = "lookalike_domain" if d.lookalike_strong else "lookalike_tld"
            c.add(sid, f"{d.registrable}: {d.lookalike_reason}", "lookalike")
        if d.age_days is not None and not d.is_freemail:
            if d.age_days < 30:
                c.add("young_domain", f"{d.registrable} registered {d.age_days} day(s) ago", "rdap")
            elif d.age_days < 90:
                c.add("newish_domain", f"{d.registrable} registered {d.age_days} days ago", "rdap")
        if d.role in sender_roles | {"reply_to"} and d.is_disposable:
            c.add("disposable_sender", f"{d.registrable} is a disposable mailbox provider", "lists")
        if d.role in sender_roles and "dns" in d.checks_run and not d.spf and not d.dmarc and not d.is_freemail:
            c.add("no_mail_auth", f"{d.registrable} has no SPF and no DMARC record", "dns")

        if d.role in sender_roles | {"reply_to"} and not d.is_freemail:
            if d.exists is False:
                c.add("sender_domain_missing", f"{d.registrable} does not exist in DNS", "dns")
            elif d.null_mx:
                c.add("null_mx", f"{d.registrable} publishes a null MX, so replies cannot be delivered", "dns")
            elif "dns" in d.checks_run and not d.mx:
                c.add("no_mx", f"{d.registrable} has no MX record, so it cannot receive replies", "dns")
            if "dns" in d.checks_run and d.exists is not False and d.has_website is False:
                c.add("no_website", f"{d.registrable} has no website (no A/AAAA record)", "dns")

        tld = d.registrable.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS and not d.is_freemail:
            c.add("risky_tld", f"{d.registrable} uses .{tld}", "lists")

    sender = next((d for d in domains if d.role in sender_roles), None)
    if headers and sender and headers.from_display:
        brand_labels = {domain_label(b) for b in brands() if len(domain_label(b)) >= 4}
        shown = headers.from_display.lower().replace(" ", "")
        own = domain_label(sender.registrable)
        used = next((b for b in sorted(brand_labels) if b in shown and b not in own.replace("-", "")), None)
        if sender.is_freemail and (CORPORATE_WORDS.search(headers.from_display) or used):
            c.add("freemail_impersonation", f"'{headers.from_display}' sent from free-mail domain {sender.registrable}", "headers")
        elif used and not sender.is_freemail:
            c.add("brand_display_name", f"display name '{headers.from_display}' but sender domain is {sender.registrable}", "headers")

    if address and sender:
        if address.role_word and sender.is_freemail:
            c.add("role_on_freemail", f"'{address.local_part}' is a role or company-style name on free-mail ({sender.registrable})", "address")
        if address.looks_random:
            c.add("random_local_part", f"'{address.local_part}': {address.random_reasons[0]}", "address")

    if body_text or headers:
        text = " ".join(filter(None, [headers.subject if headers else "", body_text[:5000]]))
        money, pressure = BEC_MONEY.findall(text), BEC_PRESSURE.findall(text)
        if money and pressure:
            words = sorted({w.lower() for w in money + pressure})[:5]
            c.add("bec_language", f"money + pressure wording: {', '.join(words)}", "body")

    # --- links and attachments ----------------------------------------------------
    deceptive = [l for l in links if l.deceptive]
    if deceptive:
        l = deceptive[0]
        c.add("deceptive_link", f"text '{l.display_text}' points to {l.domain}", "body")
    short = [l for l in links if l.is_shortener]
    if short:
        c.add("shortener", f"{len(short)} shortened link(s), e.g. {short[0].defanged}", "body")
    known_good = {r.indicator.value for r in results if r.source == "circl" and r.details.get("known_good")}
    risky = [a for a in attachments if a.risky and a.sha256 not in known_good]
    if risky:
        a = risky[0]
        c.add("risky_attachment", f"{a.filename}: {a.reasons[0]}", "attachments")

    # --- trust credits (only when nothing points the other way) ------------------
    has_intel_hit = any(r.status == SourceStatus.hit and r.severity in ("medium", "high") for r in results)
    risky_signals = set(c.signals) - {"return_path_mismatch"}
    if sender and not has_intel_hit and not risky_signals and (sender.age_days or 0) > 365 and not sender.lookalike_of:
        if headers and (headers.auth.spf, headers.auth.dkim, headers.auth.dmarc) == ("pass", "pass", "pass"):
            c.add("trust_authenticated", f"spf, dkim and dmarc pass; {sender.registrable} is {sender.age_days} days old", "headers")
        elif input_type in ("email_address", "domain") and sender.dmarc_policy in ("reject", "quarantine") and sender.mx:
            c.add("trust_established_domain", f"{sender.registrable}: DMARC p={sender.dmarc_policy}, {sender.age_days} days old", "dns")

    signals = sorted(c.signals.values(), key=lambda s: -s.weight)
    hard = any(cfg["signals"][s.id].get("hard_override") for s in signals)
    score = max(0, min(100, sum(s.weight for s in signals)))
    if hard:
        score = max(score, 90)
    bands = cfg["bands"]
    label = (
        VerdictLabel.malicious if hard or score >= bands["malicious"]
        else VerdictLabel.suspicious if score >= bands["suspicious"]
        else VerdictLabel.likely_legitimate
    )

    by_source: dict[str, set[str]] = {}
    for r in results:
        by_source.setdefault(r.source, set()).add(r.status.value)
    ran = sum(1 for s in by_source.values() if s & {"hit", "clean", "info"})
    skipped = sum(1 for s in by_source.values() if not s & {"hit", "clean", "info"})
    ratio = ran / (ran + skipped) if ran + skipped else 0
    confidence = "high" if ratio >= 0.8 and ran >= 3 else "medium" if ratio >= 0.5 and ran >= 2 else "low"

    reasons = [f"{s.label}: {s.evidence}" for s in signals if s.weight > 0][:3]
    if not reasons:
        reasons = [f"{s.label}" for s in signals] or ["No risk signals found in the sources that ran"]
    verdict = Verdict(score=score, label=label, confidence=confidence, sources_run=ran,
                      sources_skipped=skipped, hard_override=hard, reasons=reasons)
    return signals, verdict
