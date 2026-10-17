"""Parse a raw RFC 5322 message (.eml) into headers, body text, links and attachments.

Nothing in the message is executed or rendered: HTML is only tokenised to find
links, and attachments are hashed in memory and then discarded.
"""

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from html import unescape
from html.parser import HTMLParser
from pathlib import PurePath
from urllib.parse import urlsplit

from app.core.lists import shorteners
from app.core.util import defang, registrable_domain
from app.models.schemas import Attachment, HeaderAnalysis, Link
from app.parsers.headers import analyse_headers

URL_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s<>\"'`)\]]+", re.IGNORECASE)
DOMAINISH_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,63})\b", re.IGNORECASE)

RISKY_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "hta", "html", "htm", "shtml", "xhtml", "svg", "iso", "img", "vhd", "vhdx", "lnk", "msi",
    "jar", "one", "docm", "xlsm", "pptm", "xlam", "dotm", "chm", "reg", "cpl", "url",
    "library-ms", "appx", "msix", "iqy", "slk",
}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "cab", "ace", "arj"}


@dataclass
class ParsedEmail:
    headers: HeaderAnalysis
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)


class _LinkCollector(HTMLParser):
    """Collect (href, visible text) pairs from <a> tags and form actions."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []
        self.text_chunks: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a" and attrs.get("href"):
            self._href, self._text = attrs["href"].strip(), []
        elif tag == "form" and attrs.get("action"):
            self.links.append((attrs["action"].strip(), "[form action]"))
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text_chunks.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_chunks.append(data)
        if self._href is not None:
            self._text.append(data)


def _decode_part(part: Message) -> str:
    try:
        return part.get_content() if isinstance(part, EmailMessage) else ""
    except (LookupError, KeyError, ValueError, AssertionError):
        raw = part.get_payload(decode=True) or b""
        return raw.decode(part.get_content_charset() or "utf-8", errors="replace")


def _normalise_url(url: str) -> str:
    url = unescape(url).strip().rstrip(".,;")
    return re.sub(r"^hxxp", "http", url, flags=re.IGNORECASE)


def _host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def build_links(pairs: list[tuple[str, str | None]]) -> list[Link]:
    seen: dict[str, Link] = {}
    for href, text in pairs:
        if not href or href.startswith(("mailto:", "tel:", "cid:", "#", "javascript:void")):
            continue
        url = _normalise_url(href)
        if not url.lower().startswith(("http://", "https://")):
            continue
        host = _host(url)
        link = seen.get(url) or Link(
            url=url,
            defanged=defang(url),
            domain=host,
            is_shortener=bool(host and registrable_domain(host) in shorteners()),
        )
        if text and not link.display_text:
            link.display_text = text[:200]
            shown = DOMAINISH_RE.search(text)
            if shown and host:
                shown_dom = registrable_domain(shown.group(1))
                if "." in shown_dom and shown_dom != registrable_domain(host):
                    link.deceptive = True
        seen[url] = link
    return list(seen.values())


def _sniff(data: bytes) -> str:
    head = data[:2048].lower()
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if data.startswith(b"MZ"):
        return "pe-executable"
    if data.startswith(b"\x7fELF"):
        return "elf-executable"
    if data.startswith(b"Rar!"):
        return "rar"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if data.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if data.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8")):
        return "image"
    if b"<svg" in head:
        return "svg"
    if b"<html" in head or b"<!doctype html" in head or b"<script" in head:
        return "html"
    return "unknown"


def _inspect_zip(data: bytes) -> tuple[str, list[str]]:
    reasons: list[str] = []
    kind = "zip"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            names = [i.filename.lower() for i in infos]
            if any(i.flag_bits & 0x1 for i in infos):
                reasons.append("password-protected archive (hides content from scanners)")
            if any(n.startswith("word/") for n in names):
                kind = "office-word"
            elif any(n.startswith("xl/") for n in names):
                kind = "office-excel"
            elif any(n.startswith("ppt/") for n in names):
                kind = "office-powerpoint"
            if any(n.endswith("vbaproject.bin") for n in names):
                reasons.append("Office document contains VBA macros")
            inner = {PurePath(n).suffix.lstrip(".") for n in names}
            bad_inner = sorted(inner & RISKY_EXTENSIONS)
            if kind == "zip" and bad_inner:
                reasons.append(f"archive contains risky file types: {', '.join(bad_inner)}")
    except (zipfile.BadZipFile, RuntimeError, ValueError):
        reasons.append("corrupt or unusual ZIP structure")
    return kind, reasons


_TYPE_FOR_EXT = {
    "pdf": {"pdf"}, "docx": {"office-word"}, "xlsx": {"office-excel"}, "pptx": {"office-powerpoint"},
    "zip": {"zip"}, "png": {"image"}, "jpg": {"image"}, "jpeg": {"image"}, "gif": {"image"},
    "doc": {"ole"}, "xls": {"ole"}, "ppt": {"ole"},
}


def analyse_attachment(filename: str, content_type: str, data: bytes) -> Attachment:
    detected = _sniff(data)
    reasons: list[str] = []
    if detected == "zip":
        detected, zip_reasons = _inspect_zip(data)
        reasons += zip_reasons

    suffixes = [s.lstrip(".").lower() for s in PurePath(filename).suffixes]
    ext = suffixes[-1] if suffixes else ""
    if ext in RISKY_EXTENSIONS:
        reasons.append(f".{ext} files are commonly used to deliver malware or phishing pages")
    if len(suffixes) >= 2 and ext in RISKY_EXTENSIONS | {"exe"} and suffixes[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}:
        reasons.append(f"double extension '.{suffixes[-2]}.{ext}' disguises the real file type")
    expected = _TYPE_FOR_EXT.get(ext)
    if expected and detected != "unknown" and detected not in expected:
        reasons.append(f"extension says .{ext} but the content is {detected}")
    if detected in {"pe-executable", "elf-executable", "lnk", "iso", "html", "svg"} and not any(
        detected in r for r in reasons
    ):
        reasons.append(f"content is {detected}")
    if detected == "ole":
        reasons.append("legacy Office format (can carry macros)")
    if ext in ARCHIVE_EXTENSIONS and not reasons:
        reasons.append("archive: contents not scanned by mail filters in some setups")

    strong = [r for r in reasons if not r.startswith(("archive:", "legacy Office"))]
    return Attachment(
        filename=filename,
        content_type=content_type,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324 - used only as a lookup key
        detected_type=detected,
        risky=bool(strong),
        reasons=reasons,
    )


def parse_eml(raw: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    parsed = ParsedEmail(headers=analyse_headers(msg))

    text_parts: list[str] = []
    html_parts: list[str] = []
    link_pairs: list[tuple[str, str | None]] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        if filename or disposition == "attachment":
            data = part.get_payload(decode=True) or b""
            attachment = analyse_attachment(filename or "unnamed", ctype, data)
            parsed.attachments.append(attachment)
            if attachment.detected_type in ("html", "svg"):
                # HTML/SVG attachments often hide credential forms or smuggled payload links
                collector = _LinkCollector()
                try:
                    collector.feed(data.decode("utf-8", errors="replace"))
                except Exception:  # noqa: BLE001
                    pass
                link_pairs += [(href, text or f"[in attachment {attachment.filename}]") for href, text in collector.links]
            continue
        if ctype == "text/plain":
            text_parts.append(_decode_part(part))
        elif ctype == "text/html":
            html_parts.append(_decode_part(part))

    has_plain = any(t.strip() for t in text_parts)
    parsed.text_body = "\n".join(text_parts)
    parsed.html_body = "\n".join(html_parts)

    for html in html_parts:
        collector = _LinkCollector()
        try:
            collector.feed(html)
        except Exception:  # noqa: BLE001 - malformed HTML must never break analysis
            pass
        link_pairs += collector.links
        if not parsed.text_body.strip():
            parsed.text_body = re.sub(r"\n\s*\n+", "\n\n", "".join(collector.text_chunks)).strip()
    if has_plain:
        # Only the real text/plain part: URLs inside HTML are taken from hrefs, never from
        # visible text, which is exactly what a deceptive link fakes.
        for match in URL_RE.finditer("\n".join(text_parts)):
            link_pairs.append((match.group(0), None))

    parsed.links = build_links(link_pairs)
    return parsed
