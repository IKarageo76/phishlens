import pytest

from app.analysis.address import analyse_address
from app.analysis.mailprovider import identify
from app.models.schemas import (
    Attachment,
    DomainProfile,
    Indicator,
    IndicatorType,
    SourceResult,
    SourceStatus,
)
from app.scoring.engine import evaluate
from app.services.analyzer import _infra_indicators


@pytest.mark.parametrize("mx,name,large", [
    (["acme-gr.mail.protection.outlook.com"], "Microsoft 365", True),
    (["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "Google Workspace / Gmail", True),
    (["mail.protonmail.ch"], "Proton Mail", True),
    (["mx1.cheap-host.top"], None, False),
])
def test_mail_provider(mx, name, large):
    assert identify(mx) == (name, large)


@pytest.mark.parametrize("addr,random,role", [
    ("x7k2q9p@gmail.com", True, None),
    ("qwrtzxcvbm@yahoo.com", True, None),
    ("john.smith1985@gmail.com", False, None),
    ("maria.papadopoulou@outlook.com", False, None),
    ("billing.dept@gmail.com", False, "billing"),
    ("ceo+urgent@proton.me", False, "ceo"),
])
def test_address_heuristics(addr, random, role):
    a = analyse_address(addr)
    assert a.looks_random is random and a.role_word == role


def _sender(**kw) -> DomainProfile:
    base = dict(domain="acme-pay.com", registrable="acme-pay.com", role="input", checks_run=["dns"], exists=True,
                mx=["mx.acme-pay.com"], spf="v=spf1 -all", has_website=True)
    base.update(kw)
    return DomainProfile(**base)


def _ids(**kw):
    signals, verdict = evaluate(input_type="email_address", headers=None, links=[], attachments=[],
                                domains=kw.pop("domains"), results=kw.pop("results", []), address=kw.pop("address", None))
    return {s.id for s in signals}, verdict


def test_null_mx_and_no_website():
    ids, _ = _ids(domains=[_sender(mx=[], null_mx=True, has_website=False)])
    assert {"null_mx", "no_website"} <= ids


def test_missing_domain():
    ids, _ = _ids(domains=[_sender(exists=False, mx=[], has_website=False)])
    assert "sender_domain_missing" in ids and "no_website" not in ids


def test_freemail_role_and_random_address():
    gmail = _sender(domain="gmail.com", registrable="gmail.com", is_freemail=True)
    ids, _ = _ids(domains=[gmail], address=analyse_address("payroll@gmail.com"))
    assert "role_on_freemail" in ids and "no_website" not in ids
    ids, _ = _ids(domains=[gmail], address=analyse_address("x7k2q9p@gmail.com"))
    assert "random_local_part" in ids


def test_spam_reports_and_zero_reputation_score():
    results = [
        SourceResult(source="stopforumspam", indicator=Indicator(type=IndicatorType.email, value="a@acme-pay.com", origin="input"),
                     status=SourceStatus.hit, severity="medium", summary="address reported for spam 42 time(s)"),
        SourceResult(source="spamhaus", indicator=Indicator(type=IndicatorType.domain, value="acme-pay.com", origin="input"),
                     status=SourceStatus.hit, severity="medium", summary="first seen within the last 3 hour(s)",
                     details={"zrd_hours": 3, "block_severity": "none", "codes": ["127.0.2.3"]}),
    ]
    ids, verdict = _ids(domains=[_sender()], results=results)
    assert {"spam_reports", "zero_reputation"} <= ids and "spamhaus_listed" not in ids
    assert verdict.label.value == "suspicious"


def test_known_good_attachment_suppresses_risky_signal():
    att = Attachment(filename="setup.exe", content_type="application/octet-stream", size=10, sha256="c" * 64,
                     md5="d" * 32, detected_type="pe-executable", risky=True, reasons=["content is pe-executable"])
    known = SourceResult(source="circl", indicator=Indicator(type=IndicatorType.hash, value="c" * 64, origin="attachment"),
                         status=SourceStatus.info, summary="known file", details={"known_good": True})
    with_circl, _ = evaluate(input_type="eml", headers=None, links=[], attachments=[att], domains=[], results=[known])
    without, _ = evaluate(input_type="eml", headers=None, links=[], attachments=[att], domains=[], results=[])
    assert "risky_attachment" not in {s.id for s in with_circl}
    assert "risky_attachment" in {s.id for s in without}


def test_infra_ips_skip_big_providers():
    small = _sender(mx_ips=["194.0.234.30"], web_ips=["194.0.234.31"])
    big = _sender(domain="acme.gr", registrable="acme.gr", mail_provider="Microsoft 365", large_provider=True,
                  mx_ips=["52.101.1.1"], web_ips=["20.1.1.1"])
    got = {(i.value, i.origin) for i in _infra_indicators([small, big])}
    assert got == {("194.0.234.30", "mx"), ("194.0.234.31", "web"), ("20.1.1.1", "web")}
