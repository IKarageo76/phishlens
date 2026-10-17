# Changelog

## v0.3.0 (2026-10-17)

- Evidence section on every report: per source and indicator, the result as returned, key fields,
  raw response (trimmed), check time in local time and UTC, and the request sent with keys removed
- Verification link for every source, including skipped ones, plus extra links (MXToolbox SPF/DMARC,
  raw RDAP record, urlscan screenshot, Shodan host page)
- VirusTotal evidence lists the engines that flagged the indicator
- Spamhaus evidence shows the DNS queries (key redacted) and return codes
- Print or save as PDF: expands all evidence, light print layout
- Case note: evidence table with result, check time and verification link per source

## v0.2.0 (2026-10-17)

- 8 new sources: Google Safe Browsing, Spamhaus DQS (ZEN, DBL, ZRD), AlienVault OTX, PhishStats,
  StopForumSpam, CIRCL hashlookup, Shodan InternetDB, IPinfo Lite; five of them need no key
- Sender-address checks: mail provider from MX, null MX, missing domain, no website,
  role names on free-mail, machine-generated local parts
- Mail-server and website IPs are checked with the IP sources (skipped for big shared providers)
- Known-good attachments (CIRCL) no longer count as risky
- New report panels: sender address and IP addresses
- `DISABLED_SOURCES` setting; per-source lookup budgets

## v0.1.0 (2026-10-17)

First public release.

- Sender, domain, URL, IP and hash lookups; `.eml` upload and pasted raw source
- Header analysis: SPF/DKIM/DMARC, Received chain, address mismatches
- Link, attachment and lookalike-domain checks; BEC wording detection
- Sources: VirusTotal, AbuseIPDB, urlscan.io (search), URLhaus, ThreatFox, MalwareBazaar, Have I Been Pwned, DNS, RDAP
- Explainable 0-100 score with editable weights
- Markdown case note and defanged IOC CSV export
- Docker Compose deployment, retention purge, privacy mode
