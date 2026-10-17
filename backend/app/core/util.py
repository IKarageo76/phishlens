"""Small helpers: domain parsing, defanging, IP classification."""

import ipaddress
import re
from functools import lru_cache

import tldextract

# Offline public-suffix list: never fetch it from the internet at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=())

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")


@lru_cache(maxsize=4096)
def registrable_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1): mail.login.example.co.uk -> example.co.uk."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if is_ip(host):
        return host
    parts = _extract(host)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    return host


def domain_label(host: str) -> str:
    """Return just the label left of the public suffix: paypal.com -> paypal."""
    parts = _extract((host or "").lower())
    return parts.domain or host


def domain_of_email(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().strip(">").lower() or None


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def defang(value: str) -> str:
    """Make an indicator safe to display and paste: hxxps://evil[.]com."""
    if "://" in value:
        scheme, rest = value.split("://", 1)
        scheme = re.sub(r"^http", "hxxp", scheme, flags=re.IGNORECASE)
        host, sep, path = rest.partition("/")
        return f"{scheme}://{host.replace('.', '[.]')}{sep}{path}"
    if "@" in value:
        local, domain = value.rsplit("@", 1)
        return f"{local}[@]{domain.replace('.', '[.]')}"
    return value.replace(".", "[.]")


def refang(value: str) -> str:
    """Accept defanged input from analysts: hxxp -> http, [.] -> ."""
    out = value.strip()
    out = re.sub(r"^hxxp", "http", out, flags=re.IGNORECASE)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[@]", "@"), ("[at]", "@"), ("[://]", "://")):
        out = out.replace(a, b)
    return out


def classify_input(value: str) -> str:
    """Return one of email_address, url, ip, domain, hash or 'unknown'."""
    v = refang(value)
    if EMAIL_RE.match(v):
        return "email_address"
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.IGNORECASE):
        return "url"
    if is_ip(v):
        return "ip"
    if HASH_RE.match(v):
        return "hash"
    if DOMAIN_RE.match(v):
        return "domain"
    return "unknown"
