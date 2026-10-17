"""Every result must carry proof: when it was checked, what was asked (no secrets),
what came back, and a link the analyst can open and screenshot."""

import httpx
import pytest
import respx

from app.core.cache import MemoryCache
from app.core.config import Settings
from app.core.evidence import redact_url, trim
from app.core.http import make_client
from app.enrichers.registry import build_enrichers, run_enrichers
from app.enrichers.spamhaus import Spamhaus
from app.models.schemas import Indicator, IndicatorType, SourceStatus

SAMPLES = {
    IndicatorType.url: "https://evil-phish.com/login?x=1",
    IndicatorType.domain: "evil-phish.com",
    IndicatorType.ip: "194.0.234.10",
    IndicatorType.email: "billing@evil-phish.com",
    IndicatorType.hash: "a" * 64,
}


def test_every_source_has_a_verification_link():
    s = Settings(_env_file=None)
    for e in build_enrichers(s):
        for t in e.indicator_types:
            url = e.page_url(Indicator(type=t, value=SAMPLES[t], origin="input"))
            assert url and url.startswith("https://"), (e.name, t)


def test_redact_url_hides_keys():
    out = redact_url("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=SECRET123&x=1")
    assert "SECRET123" not in out and "<redacted>" in out and "x=1" in out
    assert redact_url("https://api.ipinfo.io/lite/1.1.1.1?token=tok").endswith("token=<redacted>")


def test_trim_keeps_large_raw_small():
    big = {"data": {"attributes": {"results": {f"engine{i}": {"category": "harmless", "result": "x" * 50} for i in range(500)}}}}
    out = trim(big)
    import json
    assert len(json.dumps(out)) <= 13_000


@respx.mock
async def test_http_evidence_is_captured_without_secrets():
    s = Settings(_env_file=None, VT_API_KEY="VTSECRET", GSB_API_KEY="GSBSECRET",
                 DISABLED_SOURCES="otx,phishstats,urlscan,urlhaus,threatfox,stopforumspam,spamhaus")
    respx.get(url__startswith="https://www.virustotal.com/api/v3/urls/").mock(return_value=httpx.Response(200, json={
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 60},
                                "last_analysis_results": {"Fortinet": {"category": "malicious", "result": "phishing"},
                                                          "Google": {"category": "harmless", "result": "clean"}}}}}))
    respx.post(url__startswith="https://safebrowsing.googleapis.com/").mock(return_value=httpx.Response(200, json={}))
    async with make_client(5) as client:
        results = await run_enrichers([Indicator(type=IndicatorType.url, value=SAMPLES[IndicatorType.url], origin="input")],
                                      s, client, MemoryCache())
    by = {r.source: r for r in results}
    vt, gsb = by["virustotal"], by["safebrowsing"]
    assert vt.checked_at and vt.query.startswith("GET https://www.virustotal.com/api/v3/urls/") and "HTTP 200" in vt.query
    assert vt.raw["data"]["attributes"]["last_analysis_stats"]["malicious"] == 5
    assert vt.details["flagged_by"] == ["Fortinet: phishing"]
    assert vt.link.startswith("https://www.virustotal.com/gui/url/")
    assert "GSBSECRET" not in (gsb.query or "") and "<redacted>" in gsb.query
    assert gsb.link.startswith("https://transparencyreport.google.com/")
    assert "VTSECRET" not in str([r.model_dump() for r in results])


async def test_skipped_sources_still_link_to_the_source(cache):
    s = Settings(_env_file=None, DISABLED_SOURCES="otx,phishstats,stopforumspam,circl,internetdb")
    async with httpx.AsyncClient() as c:
        results = await run_enrichers([Indicator(type=IndicatorType.ip, value="194.0.234.10", origin="input")], s, c, cache)
    vt = next(r for r in results if r.source == "virustotal")
    assert vt.status == SourceStatus.skipped and vt.link == "https://www.virustotal.com/gui/ip-address/194.0.234.10"


async def test_spamhaus_evidence_redacts_key(monkeypatch):
    async def fake(self, name):
        return ["127.0.1.4"] if ".dbl." in name else []

    monkeypatch.setattr(Spamhaus, "_resolve", fake)
    r = await Spamhaus(Settings(_env_file=None, SPAMHAUS_DQS_KEY="DQSSECRET")).lookup(
        Indicator(type=IndicatorType.domain, value="evil-phish.com", origin="input"), None)
    assert "DQSSECRET" not in r.query and "<key>" in r.query
    assert r.raw == {"dbl": ["127.0.1.4"], "zrd": "NXDOMAIN (not listed)"}


@pytest.fixture
def cache():
    return MemoryCache()
