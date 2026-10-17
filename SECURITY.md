# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability** button (Security tab), not as a public issue. You will get an acknowledgement within 7 days.

## Threat model

PhishLens processes hostile input by design: phishing emails, malware attachments and attacker URLs.

| Threat | Mitigation |
| --- | --- |
| Malicious HTML or script in an email | HTML is tokenised for links and never rendered; the UI shows plain text only |
| Malware in attachments | Hashed in memory and discarded; never written to disk or opened |
| Parser exploits / resource exhaustion | Upload size limit (`MAX_UPLOAD_MB`), stdlib parsers, malformed input handled as data |
| SSRF via URLs in the email | Only fixed API hosts are called; RDAP redirects and optional unshortening are checked against private, loopback and link-local ranges on every hop |
| Tipping off the attacker | No requests to attacker infrastructure by default; urlscan is searched, not submitted to |
| Leaking client data to third parties | Privacy mode; only indicators are sent, never message bodies |
| API key theft | Keys stay in the server environment, are never returned by the API, and are not logged |
| Stored sensitive data | Retention purge; reports contain metadata and indicators, not attachments |
| XSS in the web UI | React escaping, no `dangerouslySetInnerHTML`, strict CSP, `X-Frame-Options: DENY` |

## Deployment notes

- The compose file binds the UI to `127.0.0.1` only. For team use, put a TLS reverse proxy with authentication in front of it until built-in login ships (v0.2).
- Do not commit `.env`. Rotate any key you suspect was exposed.
- Before using PhishLens with client data, get approval from your organisation and use API keys licensed for commercial use.
