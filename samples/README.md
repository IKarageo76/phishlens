# Sample emails

Fictitious test messages for demos and tests. The domains, people and IPs are made up and may be registered by someone else, so **do not visit the links**. Regenerate them with `python scripts/make_samples.py`.

| File | Scenario | Expected verdict (no API keys) |
| --- | --- | --- |
| `01-credential-phish.eml` | Lookalike Microsoft sender, DMARC fail, deceptive link, shortener | Malicious |
| `02-bec-bank-change.eml` | Free-mail "accounts department", reply-to elsewhere, bank change request | Suspicious |
| `03-malware-attachment.eml` | `.pdf.html` attachment with a form, zip containing a script | Suspicious |
| `04-legit-github.eml` | Authenticated GitHub notification | Likely legitimate |
