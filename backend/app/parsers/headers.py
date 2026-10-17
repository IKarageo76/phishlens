"""Header analysis: authentication results, Received chain, address mismatches."""

import re
from email.message import Message
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from app.core.util import domain_of_email, is_public_ip, registrable_domain
from app.models.schemas import AuthResults, HeaderAnalysis, Hop

_IP_IN_BRACKETS = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]{3,45})\]")
_IP_BARE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_FROM = re.compile(r"^\s*from\s+(\S+)", re.IGNORECASE)
_BY = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_AUTH_KEYS = ("spf", "dkim", "dmarc")


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    return re.sub(r"\s+", " ", str(value)).strip() or None


def parse_auth_results(msg: Message) -> AuthResults:
    """Read SPF/DKIM/DMARC verdicts. The topmost header is the one added by the
    receiving server, so it wins; ARC and Received-SPF are fallbacks."""
    auth = AuthResults()
    candidates = (msg.get_all("Authentication-Results") or []) + (
        msg.get_all("ARC-Authentication-Results") or []
    )
    for header in candidates:
        text = _clean(header) or ""
        auth.raw.append(text)
        for key in _AUTH_KEYS:
            if getattr(auth, key) is None:
                m = re.search(rf"\b{key}=([a-zA-Z]+)", text)
                if m:
                    setattr(auth, key, m.group(1).lower())
    if auth.spf is None:
        received_spf = msg.get("Received-SPF")
        if received_spf:
            auth.spf = (str(received_spf).split() or ["none"])[0].lower()
            auth.raw.append(_clean(received_spf) or "")
    return auth


def parse_received_chain(msg: Message) -> list[Hop]:
    """Return hops in chronological order (first hop = where the mail started)."""
    received = list(reversed(msg.get_all("Received") or []))
    hops: list[Hop] = []
    previous_ts = None
    for i, raw in enumerate(received, start=1):
        text = _clean(raw) or ""
        head, _, date_part = text.rpartition(";")
        if not head:
            head, date_part = text, ""
        from_section = head.split(" by ", 1)[0]
        ip = None
        m = _IP_IN_BRACKETS.search(from_section) or _IP_BARE.search(from_section)
        if m:
            ip = m.group(1)
        from_m, by_m = _FROM.search(head), _BY.search(head)
        ts = None
        if date_part.strip():
            try:
                ts = parsedate_to_datetime(date_part.strip())
            except (TypeError, ValueError, IndexError):
                ts = None
        delay = None
        if ts and previous_ts and ts.tzinfo and previous_ts.tzinfo:
            delay = round((ts - previous_ts).total_seconds(), 1)
        hops.append(
            Hop(
                index=i,
                from_host=from_m.group(1) if from_m else None,
                by_host=by_m.group(1).rstrip(";") if by_m else None,
                ip=ip,
                timestamp=ts,
                delay_seconds=delay,
            )
        )
        if ts:
            previous_ts = ts
    return hops


def analyse_headers(msg: Message) -> HeaderAnalysis:
    display, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    to_list = [a for _, a in getaddresses([str(v) for v in msg.get_all("To", [])]) if a]

    hops = parse_received_chain(msg)
    origin_ip = next((h.ip for h in hops if h.ip and is_public_ip(h.ip)), None)

    analysis = HeaderAnalysis(
        subject=_clean(msg.get("Subject")),
        date=_clean(msg.get("Date")),
        message_id=_clean(msg.get("Message-ID")),
        from_display=_clean(display),
        from_address=from_addr.lower() or None,
        reply_to=reply_to.lower() or None,
        return_path=return_path.lower() or None,
        to=to_list,
        auth=parse_auth_results(msg),
        hops=hops,
        origin_ip=origin_ip,
        x_mailer=_clean(msg.get("X-Mailer") or msg.get("User-Agent")),
        raw_headers=[(k, _clean(v) or "") for k, v in msg.items()],
    )

    from_dom = registrable_domain(domain_of_email(analysis.from_address) or "")
    for label, addr in (("Reply-To", analysis.reply_to), ("Return-Path", analysis.return_path)):
        other = registrable_domain(domain_of_email(addr) or "")
        if from_dom and other and other != from_dom:
            analysis.mismatches.append(f"{label} domain {other} differs from From domain {from_dom}")
    if display and "@" in display:
        shown = registrable_domain(domain_of_email(display.strip("'\" <>")) or "")
        if shown and from_dom and shown != from_dom:
            analysis.mismatches.append(f"Display name shows {shown} but the real sender is {from_dom}")
    return analysis
