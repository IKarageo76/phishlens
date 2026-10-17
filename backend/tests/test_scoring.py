from datetime import UTC

import httpx
import pytest
import respx

from app.analysis import domain as domain_mod
from app.models.schemas import (
    DomainProfile,
    Indicator,
    IndicatorType,
    SourceResult,
    SourceStatus,
    VerdictLabel,
)
from app.scoring.engine import evaluate
from app.services.analyzer import analyze_eml, analyze_value
from tests.conftest import sample


@pytest.mark.parametrize(
    "name,label,must_have",
    [
        ("01-credential-phish.eml", VerdictLabel.malicious, {"dmarc_fail", "lookalike_domain", "deceptive_link"}),
        ("02-bec-bank-change.eml", VerdictLabel.suspicious, {"reply_to_mismatch", "bec_language", "freemail_impersonation"}),
        ("03-malware-attachment.eml", VerdictLabel.suspicious, {"risky_attachment", "auth_fail"}),
        ("04-legit-github.eml", VerdictLabel.likely_legitimate, set()),
    ],
)
async def test_sample_verdicts(name, label, must_have, offline_settings, cache):
    async with httpx.AsyncClient() as client:
        report = await analyze_eml(sample(name), name, offline_settings, client, cache)
    ids = {s.id for s in report.signals}
    assert report.verdict.label == label, (report.verdict.score, ids)
    assert must_have <= ids
    assert report.verdict.confidence == "low"  # nothing ran without keys


def _hit(source, severity, value="https://x.test/", t="url"):
    return SourceResult(source=source, indicator=Indicator(type=IndicatorType(t), value=value, origin="body"),
                        status=SourceStatus.hit, severity=severity, summary="flagged")


def test_known_malicious_is_a_hard_override():
    trusted = DomainProfile(domain="github.com", registrable="github.com", role="sender", age_days=6000,
                            checks_run=["dns", "rdap"], spf="v=spf1", dmarc="v=DMARC1; p=reject", dmarc_policy="reject")
    signals, verdict = evaluate(input_type="domain", headers=None, links=[], attachments=[], domains=[trusted],
                                results=[_hit("malwarebazaar", "high", "a" * 64, "hash")])
    assert verdict.hard_override and verdict.label == VerdictLabel.malicious and verdict.score >= 90
    assert "trust_established_domain" not in {s.id for s in signals}


def test_trust_credit_for_established_domain():
    d = DomainProfile(domain="github.com", registrable="github.com", role="input", age_days=6000, mx=["mx.github.com"],
                      checks_run=["dns", "rdap"], spf="v=spf1", dmarc="v=DMARC1; p=reject", dmarc_policy="reject")
    signals, verdict = evaluate(input_type="domain", headers=None, links=[], attachments=[], domains=[d], results=[])
    assert [s.id for s in signals] == ["trust_established_domain"]
    assert verdict.score == 0 and verdict.label == VerdictLabel.likely_legitimate


def test_score_is_capped_and_explained():
    results = [_hit("urlscan", "high"), _hit("abuseipdb", "high", "194.0.234.10", "ip"), _hit("virustotal", "medium")]
    signals, verdict = evaluate(input_type="url", headers=None, links=[], attachments=[], domains=[], results=results)
    assert {s.id for s in signals} == {"phishing_page", "ip_abuse", "vt_suspicious"}
    assert verdict.score == 55 and verdict.label == VerdictLabel.suspicious
    assert len(verdict.reasons) == 3


async def test_sender_lookup_young_domain(offline_settings, cache, monkeypatch):
    offline_settings.rdap_enabled = True

    async def fake_public(url, allow_http=False):
        return None

    monkeypatch.setattr(domain_mod, "assert_public_url", fake_public)
    from datetime import datetime, timedelta
    created = (datetime.now(UTC) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with respx.mock:
        respx.get("https://rdap.org/domain/paypa1-billing.com").mock(
            return_value=httpx.Response(302, headers={"location": "https://rdap.verisign.test/com/v1/domain/paypa1-billing.com"}))
        respx.get("https://rdap.verisign.test/com/v1/domain/paypa1-billing.com").mock(return_value=httpx.Response(200, json={
            "events": [{"eventAction": "registration", "eventDate": created}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Cheap Registrar Ltd"]]]}],
        }))
        async with httpx.AsyncClient() as client:
            report = await analyze_value("billing@paypa1-billing.com", offline_settings, client, cache)
    ids = {s.id for s in report.signals}
    assert {"young_domain", "lookalike_domain"} <= ids
    assert report.verdict.label == VerdictLabel.suspicious
    assert report.domains[0].registrar == "Cheap Registrar Ltd"
