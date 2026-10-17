from pathlib import Path

import pytest

from app.core import http as http_mod
from app.core.cache import MemoryCache, reset_cache
from app.core.config import Settings
from app.core.http import RateLimiter

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def sample(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


KEYLESS = "otx,stopforumspam,phishstats,circl,internetdb"


@pytest.fixture
def offline_settings() -> Settings:
    """No network: DNS/RDAP off, no API keys, keyless sources disabled."""
    return Settings(DNS_ENABLED=False, RDAP_ENABLED=False, DISABLED_SOURCES=KEYLESS, _env_file=None)


@pytest.fixture
def keyed_settings() -> Settings:
    return Settings(
        DNS_ENABLED=False, RDAP_ENABLED=False, _env_file=None,
        VT_API_KEY="vt-test", ABUSEIPDB_API_KEY="ab-test", URLSCAN_API_KEY="us-test",
        ABUSECH_AUTH_KEY="ac-test", HIBP_API_KEY="hibp-test", DISABLED_SOURCES=KEYLESS,
    )


@pytest.fixture
def cache() -> MemoryCache:
    reset_cache()
    return MemoryCache()


@pytest.fixture(autouse=True)
def fresh_rate_limiter(monkeypatch):
    limiter = RateLimiter()
    monkeypatch.setattr(http_mod, "rate_limiter", limiter)
    import app.enrichers.registry as reg
    monkeypatch.setattr(reg, "rate_limiter", limiter)
    return limiter
