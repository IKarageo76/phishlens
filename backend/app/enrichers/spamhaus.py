"""Spamhaus Data Query Service (free DQS account): ZEN for IPs, DBL and ZRD for domains.
Queries go over DNS with your key in the hostname, so no IP or domain leaves via HTTP."""

import asyncio
import ipaddress

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.enrichers.base import Enricher
from app.models.schemas import Indicator, IndicatorType, SourceResult, SourceStatus

ZEN = {
    "127.0.0.2": ("SBL (spam source)", "medium"),
    "127.0.0.3": ("SBL CSS (snowshoe spam)", "medium"),
    "127.0.0.4": ("XBL (compromised / botnet host)", "medium"),
    "127.0.0.5": ("XBL (compromised host)", "medium"),
    "127.0.0.6": ("XBL (compromised host)", "medium"),
    "127.0.0.7": ("XBL (compromised host)", "medium"),
    "127.0.0.9": ("DROP (hijacked / criminal network)", "high"),
    "127.0.0.10": ("PBL (end-user IP, should not send mail directly)", "low"),
    "127.0.0.11": ("PBL (end-user IP, should not send mail directly)", "low"),
    "127.0.0.30": ("BCL (botnet controller)", "high"),
}
DBL = {
    "127.0.1.2": ("low-reputation domain", "medium"),
    "127.0.1.4": ("phishing domain", "high"),
    "127.0.1.5": ("malware domain", "high"),
    "127.0.1.6": ("botnet C&C domain", "high"),
    "127.0.1.102": ("legitimate domain abused for spam", "low"),
    "127.0.1.103": ("legitimate domain abused as a redirector", "medium"),
    "127.0.1.104": ("legitimate domain abused for phishing", "medium"),
    "127.0.1.105": ("legitimate domain abused for malware", "medium"),
    "127.0.1.106": ("legitimate domain abused for C&C", "medium"),
}
_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


def reverse_ip(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split(".")))
    return ".".join(reversed(addr.exploded.replace(":", "")))


class Spamhaus(Enricher):
    name = "spamhaus"
    title = "Spamhaus (DQS)"
    indicator_types = {IndicatorType.ip, IndicatorType.domain}
    per_minute = None
    rate_limit = "Free DQS account: non-commercial, low volume"
    licence_note = "Free for non-commercial use with low query volumes; queried over DNS."
    signup_url = "https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/"

    def api_key(self) -> str:
        return self.settings.spamhaus_dqs_key

    def page_url(self, indicator: Indicator) -> str | None:
        return f"https://check.spamhaus.org/results/?query={indicator.value}"

    async def _resolve(self, name: str) -> list[str]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 4.0
        try:
            answer = await resolver.resolve(name, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        return [r.address for r in answer]

    def _dns_evidence(self, answers: dict[str, list[str]], indicator: Indicator) -> dict:
        """DNS queries with the DQS key redacted, plus the raw answers."""
        zone_q = {"zen": f"{reverse_ip(indicator.value) if indicator.type == IndicatorType.ip else indicator.value}.<key>.zen.dq.spamhaus.net",
                  "dbl": f"{indicator.value}.<key>.dbl.dq.spamhaus.net",
                  "zrd": f"{indicator.value}.<key>.zrd.dq.spamhaus.net"}
        return {
            "query": "DNS A " + ", ".join(zone_q[z] for z in answers),
            "raw": {z: (codes or "NXDOMAIN (not listed)") for z, codes in answers.items()},
        }

    async def lookup(self, indicator: Indicator, client: httpx.AsyncClient) -> SourceResult:
        key = self.api_key()
        try:
            if indicator.type == IndicatorType.ip:
                answers = {"zen": await self._resolve(f"{reverse_ip(indicator.value)}.{key}.zen.dq.spamhaus.net")}
            else:
                dbl, zrd = await asyncio.gather(
                    self._resolve(f"{indicator.value}.{key}.dbl.dq.spamhaus.net"),
                    self._resolve(f"{indicator.value}.{key}.zrd.dq.spamhaus.net"),
                )
                answers = {"dbl": dbl, "zrd": zrd}
        except (dns.exception.DNSException, OSError) as exc:
            return self.result(indicator, SourceStatus.error, f"DNS query failed: {type(exc).__name__}")

        codes = [c for v in answers.values() for c in v]
        if any(c.startswith("127.255.255.") for c in codes):
            return self.result(indicator, SourceStatus.error, "Spamhaus rejected the query (check SPAMHAUS_DQS_KEY)")

        found: list[tuple[str, str]] = []
        for code in answers.get("zen", []):
            found.append(ZEN.get(code, (f"listed ({code})", "medium")))
        for code in answers.get("dbl", []):
            found.append(DBL.get(code, (f"listed in DBL ({code})", "medium")))
        zrd_hours = None
        for code in answers.get("zrd", []):
            last = int(code.rsplit(".", 1)[1])
            if 2 <= last <= 24:
                zrd_hours = last
                found.append((f"first seen on the internet within the last {last} hour(s)", "medium"))

        if not found:
            return self.result(indicator, SourceStatus.clean, "not listed", **self._dns_evidence(answers, indicator))
        severity = max((sev for _, sev in found), key=_RANK.get)
        blocklist = [sev for label, sev in found if not label.startswith("first seen")]
        block_severity = max(blocklist, key=_RANK.get) if blocklist else "none"
        return self.result(
            indicator, SourceStatus.hit, "; ".join(label for label, _ in found), severity=severity,
            details={"codes": codes, "zrd_hours": zrd_hours, "block_severity": block_severity, "lists": sorted(answers)},
            **self._dns_evidence(answers, indicator),
        )
