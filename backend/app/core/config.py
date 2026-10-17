"""Runtime configuration, read from environment variables or a .env file."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Intelligence source keys (all optional; a missing key = source skipped) ---
    vt_api_key: str = Field(default="", alias="VT_API_KEY")
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    urlscan_api_key: str = Field(default="", alias="URLSCAN_API_KEY")
    abusech_auth_key: str = Field(default="", alias="ABUSECH_AUTH_KEY")
    hibp_api_key: str = Field(default="", alias="HIBP_API_KEY")

    # --- Behaviour ---
    protected_domains: str = Field(default="", alias="PROTECTED_DOMAINS")
    privacy_mode: bool = Field(default=False, alias="PRIVACY_MODE")
    unshorten_enabled: bool = Field(default=False, alias="UNSHORTEN_ENABLED")
    rdap_enabled: bool = Field(default=True, alias="RDAP_ENABLED")
    dns_enabled: bool = Field(default=True, alias="DNS_ENABLED")
    vt_max_lookups: int = Field(default=4, alias="VT_MAX_LOOKUPS_PER_ANALYSIS")
    max_urls_per_analysis: int = Field(default=15, alias="MAX_URLS_PER_ANALYSIS")

    # --- Infrastructure ---
    database_url: str = Field(default="sqlite:///./data/phishlens.db", alias="DATABASE_URL")
    redis_url: str = Field(default="", alias="REDIS_URL")
    cache_ttl_seconds: int = Field(default=86400, alias="CACHE_TTL_SECONDS")
    retention_days: int = Field(default=30, alias="RETENTION_DAYS")
    http_timeout: float = Field(default=10.0, alias="HTTP_TIMEOUT_SECONDS")
    max_upload_mb: int = Field(default=25, alias="MAX_UPLOAD_MB")
    cors_origins: str = Field(default="http://localhost:5173", alias="CORS_ORIGINS")

    @property
    def protected_domain_list(self) -> list[str]:
        return [d.strip().lower() for d in self.protected_domains.split(",") if d.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
