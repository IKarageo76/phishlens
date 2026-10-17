"""Tests for the v0.2 sources. All HTTP is mocked; Spamhaus DNS is monkeypatched."""

import hashlib

import httpx
import pytest
import respx

from app.core.config import Settings
from app.enrichers.infra import CIRCLHashlookup, InternetDB, IPinfo
from app.enrichers.otx import OTX
from app.enrichers.phishstats import PhishStats
from app.enrichers.registry import run_enrichers
from app.enrichers.safebrowsing import SafeBrowsing
from app.enrichers.spamhaus import Spamhaus, reverse_ip
from app.enrichers.stopforumspam import StopForumSpam
from app.models.schemas import Indicator, IndicatorType, SourceStatus


def ind(t, v):
    return Indicator(type=IndicatorType(t), value=v, origin="input")


@pytest.fixture
def s() -> Settings:
    return Settings(_env_file=None, OTX_API_KEY="otx", GSB_API_KEY="gsb", SPAMHAUS_DQS_KEY="dqskey",
                    PHISHSTATS_API_KEY="psk_x", IPINFO_TOKEN="tok")


@respx.mock
async def test_otx_hit_and_allowlist(s):
    respx.get("https://otx.alienvault.com/api/v1/indicators/domain/evil.test/general").mock(return_value=httpx.Response(200, json={
        "pulse_info": {"count": 4, "pulses": [{"name": "Phishing kit wave", "malware_families": []}]}, "validation": []}))
    respx.get("https://otx.alienvault.com/api/v1/indicators/domain/google.com/general").mock(return_value=httpx.Response(200, json={
        "pulse_info": {"count": 40, "pulses": []}, "validation": [{"source": "alexa", "message": "Alexa top 10"}]}))
    async with httpx.AsyncClient() as c:
        hit = await OTX(s).lookup(ind("domain", "evil.test"), c)
        ok = await OTX(s).lookup(ind("domain", "google.com"), c)
    assert hit.status == SourceStatus.hit and hit.severity == "medium" and "Phishing kit wave" in hit.summary
    assert ok.status == SourceStatus.clean and "allowlisted" in ok.summary


@respx.mock
async def test_otx_works_without_key():
    route = respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/194.0.234.10/general").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 0}}))
    keyless = Settings(_env_file=None)
    assert OTX(keyless).configured()
    async with httpx.AsyncClient() as c:
        r = await OTX(keyless).lookup(ind("ip", "194.0.234.10"), c)
    assert r.status == SourceStatus.clean and "X-OTX-API-KEY" not in route.calls[0].request.headers


@respx.mock
async def test_safebrowsing(s):
    route = respx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").mock(
        return_value=httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}))
    async with httpx.AsyncClient() as c:
        r = await SafeBrowsing(s).lookup(ind("url", "https://evil.test/login"), c)
    assert r.status == SourceStatus.hit and r.severity == "high" and "phishing" in r.summary
    assert route.calls[0].request.url.params["key"] == "gsb"
    respx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").mock(return_value=httpx.Response(200, json={}))
    async with httpx.AsyncClient() as c:
        assert (await SafeBrowsing(s).lookup(ind("url", "https://ok.test/"), c)).status == SourceStatus.clean


def test_reverse_ip():
    assert reverse_ip("194.0.234.10") == "10.234.0.194"
    assert reverse_ip("2001:db8::1").startswith("1.0.0.0")


async def test_spamhaus_domain_and_ip(s, monkeypatch):
    asked: list[str] = []
    answers = {
        "evil.test.dqskey.dbl.dq.spamhaus.net": ["127.0.1.4"],
        "evil.test.dqskey.zrd.dq.spamhaus.net": ["127.0.2.5"],
        "10.234.0.194.dqskey.zen.dq.spamhaus.net": ["127.0.0.2", "127.0.0.10"],
    }

    async def fake(self, name):
        asked.append(name)
        return answers.get(name, [])

    monkeypatch.setattr(Spamhaus, "_resolve", fake)
    sh = Spamhaus(s)
    dom = await sh.lookup(ind("domain", "evil.test"), None)
    ip = await sh.lookup(ind("ip", "194.0.234.10"), None)
    clean = await sh.lookup(ind("domain", "fine.test"), None)
    assert dom.severity == "high" and dom.details["zrd_hours"] == 5 and "phishing" in dom.summary
    assert ip.severity == "medium" and ip.details["block_severity"] == "medium" and "PBL" in ip.summary
    assert clean.status == SourceStatus.clean
    assert all(".dqskey." in n for n in asked)


async def test_spamhaus_bad_key(s, monkeypatch):
    async def fake(self, name):
        return ["127.255.255.250"]

    monkeypatch.setattr(Spamhaus, "_resolve", fake)
    r = await Spamhaus(s).lookup(ind("domain", "x.test"), None)
    assert r.status == SourceStatus.error and "SPAMHAUS_DQS_KEY" in r.summary


@respx.mock
async def test_stopforumspam_sends_hash_not_address(s):
    addr = "Spammer@Example.test"
    md5 = hashlib.md5(addr.lower().encode()).hexdigest()
    route = respx.get("https://api.stopforumspam.org/api").mock(return_value=httpx.Response(200, json={
        "success": 1, "emailhash": {"value": md5, "appears": 1, "frequency": 42, "confidence": 88.5, "lastseen": "2026-10-01 10:00:00"}}))
    async with httpx.AsyncClient() as c:
        r = await StopForumSpam(s).lookup(ind("email", addr), c)
    sent = str(route.calls[0].request.url)
    assert "example" not in sent.lower() and md5 in sent
    assert r.status == SourceStatus.hit and r.severity == "medium" and "42 time" in r.summary


@respx.mock
async def test_phishstats_filters_to_same_domain(s):
    respx.get(url__startswith="https://api.phishstats.info/api/phishing").mock(return_value=httpx.Response(200, json=[
        {"url": "https://login.evil-phish.com/a", "score": 8, "date": "2026-10-10"},
        {"url": "https://evil-phish.com.other.net/", "score": 9},
    ]))
    async with httpx.AsyncClient() as c:
        r = await PhishStats(s).lookup(ind("domain", "evil-phish.com"), c)
        exact = await PhishStats(s).lookup(ind("url", "https://login.evil-phish.com/a"), c)
    assert r.status == SourceStatus.hit and r.details["matches"] == 1 and r.severity == "high"
    assert exact.summary.startswith("this exact URL")


@respx.mock
async def test_phishstats_shared_platform_is_context_only(s):
    respx.get(url__startswith="https://api.phishstats.info/api/phishing").mock(return_value=httpx.Response(200, json=[
        {"url": "https://sites.google.com/view/fake-bank", "score": 9}]))
    async with httpx.AsyncClient() as c:
        r = await PhishStats(s).lookup(ind("domain", "google.com"), c)
    assert r.status == SourceStatus.info


@respx.mock
async def test_circl_known_file(s):
    h = "a" * 64
    respx.get(f"https://hashlookup.circl.lu/lookup/sha256/{h}").mock(return_value=httpx.Response(200, json={
        "FileName": "calc.exe", "hashlookup:trust": 90}))
    respx.get(f"https://hashlookup.circl.lu/lookup/sha256/{'b' * 64}").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as c:
        known = await CIRCLHashlookup(s).lookup(ind("hash", h), c)
        unknown = await CIRCLHashlookup(s).lookup(ind("hash", "b" * 64), c)
    assert known.details["known_good"] and "calc.exe" in known.summary
    assert unknown.status == SourceStatus.info and "no verdict" in unknown.summary


@respx.mock
async def test_internetdb_tags(s):
    respx.get("https://internetdb.shodan.io/194.0.234.10").mock(return_value=httpx.Response(200, json={
        "ports": [22, 25, 443], "vulns": ["CVE-2024-1"], "tags": ["compromised"], "hostnames": []}))
    respx.get("https://internetdb.shodan.io/8.8.8.8").mock(return_value=httpx.Response(200, json={"ports": [53, 443], "tags": []}))
    async with httpx.AsyncClient() as c:
        bad = await InternetDB(s).lookup(ind("ip", "194.0.234.10"), c)
        ok = await InternetDB(s).lookup(ind("ip", "8.8.8.8"), c)
    assert bad.status == SourceStatus.hit and bad.severity == "medium" and "1 known CVE" in bad.summary
    assert ok.status == SourceStatus.info


@respx.mock
async def test_ipinfo(s):
    respx.get("https://api.ipinfo.io/lite/194.0.234.10").mock(return_value=httpx.Response(200, json={
        "ip": "194.0.234.10", "asn": "AS64500", "as_name": "Bulletproof Hosting", "as_domain": "bp.test", "country": "Seychelles"}))
    async with httpx.AsyncClient() as c:
        r = await IPinfo(s).lookup(ind("ip", "194.0.234.10"), c)
    assert r.summary == "AS64500 Bulletproof Hosting, Seychelles" and r.details["as_domain"] == "bp.test"


async def test_disabled_sources_are_not_run(cache):
    s = Settings(_env_file=None, DISABLED_SOURCES="otx, stopforumspam,phishstats,circl,internetdb,spamhaus,ipinfo,virustotal,abuseipdb,threatfox")
    async with httpx.AsyncClient() as c:
        results = await run_enrichers([ind("ip", "194.0.234.10")], s, c, cache)
    assert results == []


@respx.mock
async def test_phishstats_budget(cache):
    s = Settings(_env_file=None, DISABLED_SOURCES="otx,urlhaus,threatfox,urlscan,virustotal,safebrowsing,spamhaus")
    route = respx.get(url__startswith="https://api.phishstats.info/").mock(return_value=httpx.Response(200, json=[]))
    async with httpx.AsyncClient() as c:
        results = await run_enrichers([ind("domain", f"d{i}.test") for i in range(5)], s, c, cache)
    assert route.call_count == 3
    assert any("free-tier quota" in r.summary for r in results if r.source == "phishstats")
