import io
import zipfile

import pytest

from app.core.util import classify_input, defang, refang, registrable_domain
from app.parsers.eml import analyse_attachment, build_links, parse_eml
from tests.conftest import sample


def test_credential_phish_headers():
    p = parse_eml(sample("01-credential-phish.eml"))
    h = p.headers
    assert h.from_address == "security@micros0ft-alerts.com"
    assert h.from_display == "Microsoft 365 Security"
    assert (h.auth.spf, h.auth.dkim, h.auth.dmarc) == ("fail", "none", "fail")
    assert [hop.ip for hop in h.hops] == ["194.0.234.10", "194.0.234.11"]
    assert h.origin_ip == "194.0.234.10"
    assert h.hops[1].delay_seconds == 7.0
    assert any(m.startswith("Reply-To") for m in h.mismatches)
    assert any(m.startswith("Return-Path") for m in h.mismatches)


def test_links_are_taken_from_href_not_visible_text():
    p = parse_eml(sample("01-credential-phish.eml"))
    urls = {l.url: l for l in p.links}
    assert "https://micros0ft-login.com/verify?u=analyst" in urls
    assert "https://login.microsoftonline.com/verify" not in urls  # only shown as text
    assert urls["https://micros0ft-login.com/verify?u=analyst"].deceptive
    assert urls["https://bit.ly/3xFakeLnk"].is_shortener


def test_legit_link_is_not_deceptive():
    p = parse_eml(sample("04-legit-github.eml"))
    assert len(p.links) == 1 and not p.links[0].deceptive


def test_html_attachment_form_is_extracted():
    p = parse_eml(sample("03-malware-attachment.eml"))
    names = {a.filename: a for a in p.attachments}
    assert names["Scan_7781.pdf.html"].risky
    assert any("double extension" in r for r in names["Scan_7781.pdf.html"].reasons)
    assert any("js" in r for r in names["documents.zip"].reasons)
    assert any(l.url == "https://office-docs-share.top/c" for l in p.links)


def test_attachment_magic_mismatch():
    a = analyse_attachment("invoice.pdf", "application/pdf", b"MZ\x90\x00" + b"\x00" * 100)
    assert a.detected_type == "pe-executable"
    assert a.risky and any("extension says .pdf" in r for r in a.reasons)


def test_macro_office_document():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<w/>")
        z.writestr("word/vbaProject.bin", b"\x00")
    a = analyse_attachment("report.docm", "application/octet-stream", buf.getvalue())
    assert a.detected_type == "office-word"
    assert any("macros" in r for r in a.reasons) and a.risky


def test_clean_pdf_is_not_risky():
    a = analyse_attachment("menu.pdf", "application/pdf", b"%PDF-1.7\n...")
    assert a.detected_type == "pdf" and not a.risky
    assert len(a.sha256) == 64


def test_build_links_skips_non_http():
    links = build_links([("mailto:x@y.com", None), ("javascript:void(0)", None), ("https://a.example.com/x", "x")])
    assert [l.url for l in links] == ["https://a.example.com/x"]


@pytest.mark.parametrize(
    "value,kind",
    [
        ("a.b@example.com", "email_address"),
        ("hxxps://evil[.]com/login", "url"),
        ("evil[.]com", "domain"),
        ("8.8.8.8", "ip"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
        ("not a thing", "unknown"),
    ],
)
def test_classify(value, kind):
    assert classify_input(value) == kind


def test_defang_round_trip():
    assert defang("https://evil.com/a.php") == "hxxps://evil[.]com/a.php"
    assert defang("user@evil.co.uk") == "user[@]evil[.]co[.]uk"
    assert refang("hxxps://evil[.]com/a.php") == "https://evil.com/a.php"


def test_registrable_domain_is_offline_and_correct():
    assert registrable_domain("mail.login.example.co.uk") == "example.co.uk"
    assert registrable_domain("8.8.8.8") == "8.8.8.8"


def test_garbage_input_does_not_crash():
    p = parse_eml(b"\x00\xff not an email at all")
    assert p.headers.from_address is None
