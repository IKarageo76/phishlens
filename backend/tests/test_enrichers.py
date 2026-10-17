import httpx
import respx

from app.enrichers.registry import run_enrichers
from app.models.schemas import Indicator, IndicatorType, SourceStatus

VT = "https://www.virustotal.com/api/v3"


def ind(t, v):
    return Indicator(type=IndicatorType(t), value=v, origin="input")


def vt_stats(mal=0, sus=0, harmless=60):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": harmless, "undetected": 10}}}}


@respx.mock
async def test_all_sources_for_a_url(keyed_settings, cache):
    respx.get(url__startswith=f"{VT}/urls/").mock(return_value=httpx.Response(200, json=vt_stats(mal=7)))
    respx.get(url__startswith="https://urlscan.io/api/v1/search/").mock(return_value=httpx.Response(200, json={
        "results": [{"_id": "abc", "page": {"url": "https://evil.test/x"}, "verdicts": {"overall": {"malicious": True}}}]}))
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(return_value=httpx.Response(200, json={
        "query_status": "ok", "threat": "malware_download", "url_status": "online", "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}))
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(return_value=httpx.Response(200, json={"query_status": "no_result"}))

    async with httpx.AsyncClient() as client:
        results = await run_enrichers([ind("url", "https://evil.test/x")], keyed_settings, client, cache)
    by = {r.source: r for r in results}
    assert by["virustotal"].status == SourceStatus.hit and by["virustotal"].severity == "high"
    assert by["urlscan"].status == SourceStatus.hit
    assert by["urlhaus"].status == SourceStatus.hit
    assert by["threatfox"].status == SourceStatus.clean
    assert "abuseipdb" not in by  # does not support URLs


async def test_missing_keys_are_reported_as_skipped(offline_settings, cache):
    async with httpx.AsyncClient() as client:
        results = await run_enrichers([ind("ip", "194.0.234.10")], offline_settings, client, cache)
    assert {r.source for r in results} == {"virustotal", "abuseipdb", "threatfox"}
    assert all(r.status == SourceStatus.skipped and "no API key" in r.summary for r in results)


@respx.mock
async def test_virustotal_budget_protects_quota(keyed_settings, cache):
    keyed_settings.vt_max_lookups = 2
    route = respx.get(url__startswith=f"{VT}/domains/").mock(return_value=httpx.Response(200, json=vt_stats()))
    respx.post(url__startswith="https://urlhaus-api.abuse.ch/").mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(return_value=httpx.Response(200, json={"query_status": "no_result"}))
    respx.get(url__startswith="https://urlscan.io/").mock(return_value=httpx.Response(200, json={"results": []}))
    domains = [ind("domain", f"d{i}.test") for i in range(4)]
    async with httpx.AsyncClient() as client:
        results = await run_enrichers(domains, keyed_settings, client, cache)
    vt = [r for r in results if r.source == "virustotal"]
    assert route.call_count == 2
    assert any(r.status == SourceStatus.skipped and "free-tier quota" in r.summary for r in vt)


@respx.mock
async def test_results_are_cached(keyed_settings, cache):
    route = respx.get("https://api.abuseipdb.com/api/v2/check").mock(return_value=httpx.Response(200, json={
        "data": {"abuseConfidenceScore": 92, "totalReports": 40, "countryCode": "NL", "isp": "BadHost"}}))
    respx.get(url__startswith=f"{VT}/ip_addresses/").mock(return_value=httpx.Response(404))
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(return_value=httpx.Response(200, json={"query_status": "no_result"}))
    async with httpx.AsyncClient() as client:
        first = await run_enrichers([ind("ip", "194.0.234.10")], keyed_settings, client, cache)
        second = await run_enrichers([ind("ip", "194.0.234.10")], keyed_settings, client, cache)
    assert route.call_count == 1
    ab1 = next(r for r in first if r.source == "abuseipdb")
    ab2 = next(r for r in second if r.source == "abuseipdb")
    assert ab1.severity == "high" and not ab1.cached and ab2.cached
    assert next(r for r in first if r.source == "virustotal").status == SourceStatus.clean


@respx.mock
async def test_bad_key_becomes_error_not_crash(keyed_settings, cache):
    respx.get(url__startswith=f"{VT}/files/").mock(return_value=httpx.Response(401))
    respx.post("https://mb-api.abuse.ch/api/v1/").mock(side_effect=httpx.ConnectTimeout("slow"))
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(return_value=httpx.Response(200, json={"query_status": "no_result"}))
    async with httpx.AsyncClient() as client:
        results = await run_enrichers([ind("hash", "a" * 64)], keyed_settings, client, cache)
    by = {r.source: r for r in results}
    assert by["virustotal"].status == SourceStatus.error and "rejected" in by["virustotal"].summary
    assert by["malwarebazaar"].status == SourceStatus.error


async def test_privacy_mode_blocks_email_lookups(keyed_settings, cache):
    keyed_settings.privacy_mode = True
    async with httpx.AsyncClient() as client:
        results = await run_enrichers([ind("email", "a@b.test")], keyed_settings, client, cache)
    assert results[0].source == "hibp" and results[0].status == SourceStatus.skipped
    assert "privacy mode" in results[0].summary


@respx.mock
async def test_hibp_breach_count(keyed_settings, cache):
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/breachedaccount/").mock(
        return_value=httpx.Response(200, json=[{"Name": "Adobe"}, {"Name": "LinkedIn"}]))
    async with httpx.AsyncClient() as client:
        results = await run_enrichers([ind("email", "a@b.test")], keyed_settings, client, cache)
    assert "2 known breach" in results[0].summary
