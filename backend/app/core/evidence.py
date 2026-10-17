"""Evidence capture: what was asked, what came back, and when.

The shared HTTP client records the last response of each lookup in a context
variable (every lookup runs in its own asyncio task, so they never mix). The
enricher's `result()` helper then attaches a redacted request line and a trimmed
copy of the raw response to the SourceResult, so the report can show proof.
"""

import json
from contextvars import ContextVar
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

SECRET_PARAMS = {"key", "token", "apikey", "api_key", "auth-key", "authkey", "access_token"}
MAX_RAW_CHARS = 12_000

last_response: ContextVar[httpx.Response | None] = ContextVar("last_response", default=None)


async def record_response(response: httpx.Response) -> None:
    last_response.set(response)


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    query = [(k, "<redacted>" if k.lower() in SECRET_PARAMS else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, safe="(),:<>~"), ""))


def _shrink(obj: Any, depth: int = 0) -> Any:
    if isinstance(obj, dict):
        return {k: _shrink(v, depth + 1) for k, v in list(obj.items())[:60]}
    if isinstance(obj, list):
        items = [_shrink(v, depth + 1) for v in obj[:25]]
        if len(obj) > 25:
            items.append(f"... {len(obj) - 25} more item(s)")
        return items
    if isinstance(obj, str) and len(obj) > 800:
        return obj[:800] + f"... ({len(obj) - 800} more characters)"
    return obj


def trim(obj: Any) -> Any:
    """Keep raw evidence readable and the report small."""
    try:
        text = json.dumps(obj, default=str)
    except (TypeError, ValueError):
        return str(obj)[:MAX_RAW_CHARS]
    if len(text) <= MAX_RAW_CHARS:
        return obj
    small = _shrink(obj)
    text = json.dumps(small, default=str)
    if len(text) <= MAX_RAW_CHARS:
        return small
    return {"truncated": True, "excerpt": text[:MAX_RAW_CHARS]}


def from_last_response() -> dict[str, Any]:
    resp = last_response.get()
    if resp is None:
        return {}
    out: dict[str, Any] = {"query": f"{resp.request.method} {redact_url(str(resp.request.url))} -> HTTP {resp.status_code}"}
    try:
        out["raw"] = trim(resp.json())
    except (ValueError, httpx.ResponseNotRead, UnicodeDecodeError):
        try:
            text = resp.text
            out["raw"] = text[:2000] if text else None
        except httpx.ResponseNotRead:
            out["raw"] = None
    return out


def redact_text(text: str, secret: str) -> str:
    return text.replace(secret, "<key>") if secret else text


__all__ = ["last_response", "record_response", "redact_url", "trim", "from_last_response", "redact_text"]
