# Changelog

## v0.1.0 (2026-10-17)

First public release.

- Sender, domain, URL, IP and hash lookups; `.eml` upload and pasted raw source
- Header analysis: SPF/DKIM/DMARC, Received chain, address mismatches
- Link, attachment and lookalike-domain checks; BEC wording detection
- Sources: VirusTotal, AbuseIPDB, urlscan.io (search), URLhaus, ThreatFox, MalwareBazaar, Have I Been Pwned, DNS, RDAP
- Explainable 0-100 score with editable weights
- Markdown case note and defanged IOC CSV export
- Docker Compose deployment, retention purge, privacy mode
