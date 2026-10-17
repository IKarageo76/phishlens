"""Shared outbound HTTP client, rate limiting and SSRF protection."""

import asyncio
import ipaddress
import socket
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

import httpx

USER_AGENT = "PhishLens/0.4 (self-hosted email triage)"


class UnsafeURLError(ValueError):
    """Raised when a URL would make the server call a private or local address."""


def make_client(timeout: float) -> httpx.AsyncClient:
    from app.core.evidence import record_response

    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=False,
        event_hooks={"response": [record_response]},
    )


async def assert_public_url(url: str, allow_http: bool = False) -> None:
    """Block requests to internal networks (SSRF). Every hop of a redirect chain
    must pass this check before it is requested."""
    parts = urlsplit(url)
    if parts.scheme not in (("https", "http") if allow_http else ("https",)):
        raise UnsafeURLError(f"scheme {parts.scheme!r} not allowed")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("no host")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, parts.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"cannot resolve {host}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise UnsafeURLError(f"{host} resolves to non-public address {ip}")


class RateLimiter:
    """Sliding one-minute window per source. Over the limit = the lookup is skipped,
    never queued, so one analysis cannot stall on a slow free tier."""

    def __init__(self) -> None:
        self._calls: dict[str, deque[float]] = defaultdict(deque)

    def try_acquire(self, source: str, per_minute: int | None) -> bool:
        if not per_minute:
            return True
        now = time.monotonic()
        window = self._calls[source]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= per_minute:
            return False
        window.append(now)
        return True


rate_limiter = RateLimiter()
