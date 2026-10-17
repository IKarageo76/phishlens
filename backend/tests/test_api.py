import pytest
from fastapi.testclient import TestClient

from app.core import config
from tests.conftest import sample


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("DNS_ENABLED", "false")
    monkeypatch.setenv("RDAP_ENABLED", "false")
    for key in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY", "ABUSECH_AUTH_KEY", "HIBP_API_KEY"):
        monkeypatch.setenv(key, "")
    config.get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as c:
        yield c
    config.get_settings.cache_clear()


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_analyze_indicator_and_fetch(client):
    r = client.post("/api/analyze/indicator", json={"value": "hxxps://paypa1-secure[.]com/login"})
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["input_type"] == "url"
    assert any(s["id"] == "lookalike_domain" for s in report["signals"])
    again = client.get(f"/api/reports/{report['id']}")
    assert again.status_code == 200 and again.json()["id"] == report["id"]
    assert client.get("/api/reports").json()[0]["id"] == report["id"]


def test_invalid_indicator(client):
    r = client.post("/api/analyze/indicator", json={"value": "hello world"})
    assert r.status_code == 422


def test_upload_eml_and_exports(client):
    r = client.post("/api/analyze/eml", files={"file": ("phish.eml", sample("01-credential-phish.eml"), "message/rfc822")})
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    assert r.json()["verdict"]["label"] == "malicious"
    note = client.get(f"/api/reports/{rid}/case-note.md")
    assert note.status_code == 200 and "Malicious" in note.text
    assert "micros0ft-login[.]com" in note.text and "micros0ft-login.com" not in note.text  # defanged
    csv = client.get(f"/api/reports/{rid}/iocs.csv")
    assert csv.status_code == 200 and csv.text.startswith("type,value_defanged")


def test_msg_files_get_a_clear_message(client):
    r = client.post("/api/analyze/eml", files={"file": ("mail.msg", b"\xd0\xcf\x11\xe0", "application/vnd.ms-outlook")})
    assert r.status_code == 415


def test_non_email_upload_rejected(client):
    r = client.post("/api/analyze/eml", files={"file": ("notes.eml", b"just some text", "message/rfc822")})
    assert r.status_code == 422


def test_upload_size_limit(client, monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_MB", "1")
    config.get_settings.cache_clear()
    r = client.post("/api/analyze/eml", files={"file": ("big.eml", b"x" * (1024 * 1024 + 10), "message/rfc822")})
    assert r.status_code == 413


def test_sources_never_expose_keys(client):
    r = client.get("/api/settings/sources")
    assert r.status_code == 200
    names = {s["name"] for s in r.json()}
    assert {"virustotal", "abuseipdb", "urlscan", "urlhaus", "dns", "rdap"} <= names
    assert "vt-" not in r.text and "api_key" not in r.text


def test_delete_report(client):
    rid = client.post("/api/analyze/indicator", json={"value": "8.8.8.8"}).json()["id"]
    assert client.delete(f"/api/reports/{rid}").status_code == 204
    assert client.get(f"/api/reports/{rid}").status_code == 404


def test_retention_purge(tmp_path):
    from datetime import UTC, datetime, timedelta

    from app.models.schemas import Report, Verdict, VerdictLabel
    from app.storage.db import ReportStore

    store = ReportStore(f"sqlite:///{tmp_path}/r.db")
    verdict = Verdict(score=0, label=VerdictLabel.likely_legitimate, confidence="low", sources_run=0, sources_skipped=0)
    old = Report(id="old", created_at=datetime.now(UTC) - timedelta(days=40), input_type="ip",
                 input_value="8.8.8.8", title="old", verdict=verdict)
    new = old.model_copy(update={"id": "new", "created_at": datetime.now(UTC)})
    store.save(old)
    store.save(new)
    assert store.purge_older_than(30) == 1
    assert store.get("old") is None and store.get("new") is not None
