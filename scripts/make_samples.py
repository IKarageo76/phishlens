"""Generate the sample emails in samples/. All domains, people and IPs are fictitious
test data; never click anything in them. Run: python scripts/make_samples.py"""

import io
import zipfile
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
OUT.mkdir(exist_ok=True)
T0 = datetime(2026, 10, 12, 8, 14, 3, tzinfo=timezone.utc)


def received(msg, hops):
    # hops are chronological; Received headers are prepended, so add in reverse
    for i, (frm, ip, by) in reversed(list(enumerate(hops))):
        ts = format_datetime(T0 + timedelta(seconds=7 * i))
        msg["Received"] = f"from {frm} ({frm} [{ip}]) by {by} with ESMTPS id {1000+i}; {ts}"


def base(subject, from_, to="analyst@client-bank.gr", **extra):
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = from_
    m["To"] = to
    m["Date"] = format_datetime(T0)
    m["Message-ID"] = f"<{abs(hash(subject))}@mail.local>"
    for k, v in extra.items():
        m[k.replace("_", "-")] = v
    return m


# 1. Credential harvesting with a lookalike domain and a deceptive link
m = base("Action required: your mailbox will be suspended",
         '"Microsoft 365 Security" <security@micros0ft-alerts.com>',
         Reply_To="helpdesk.verify@outlook-support-team.com",
         Return_Path="<bounce@mailer-cheap.xyz>")
m["Authentication-Results"] = ("mx.client-bank.gr; spf=fail smtp.mailfrom=mailer-cheap.xyz; "
                               "dkim=none; dmarc=fail header.from=micros0ft-alerts.com")
received(m, [("smtp.mailer-cheap.xyz", "194.0.234.10", "relay.mailer-cheap.xyz"),
             ("relay.mailer-cheap.xyz", "194.0.234.11", "mx.client-bank.gr")])
m.set_content("Your mailbox has exceeded its quota. Verify now: https://micros0ft-login.com/verify?u=analyst\n")
m.add_alternative("""<html><body><p>Dear user,</p>
<p>Your mailbox will be suspended in 24 hours. To keep access, verify your account:</p>
<p><a href="https://micros0ft-login.com/verify?u=analyst">https://login.microsoftonline.com/verify</a></p>
<p>Or use the short link: <a href="https://bit.ly/3xFakeLnk">bit.ly/3xFakeLnk</a></p>
<p>Microsoft 365 Security Team</p></body></html>""", subtype="html")
(OUT / "01-credential-phish.eml").write_bytes(bytes(m))

# 2. Business email compromise from free mail, no links
m = base("Urgent: updated bank details for invoice INV-20431",
         '"Accounts Department - Acme Supplies" <acme.accounts.dept@gmail.com>',
         Reply_To="acme-payments@proton.me")
m["Authentication-Results"] = ("mx.client-bank.gr; spf=pass smtp.mailfrom=gmail.com; "
                               "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com")
received(m, [("mail-sor-f41.google.com", "209.85.220.41", "mx.client-bank.gr")])
m.set_content("""Hello,

Please note our bank account has changed due to an audit. Kindly pay invoice INV-20431
(EUR 48,600) to the new IBAN in the attached instructions today, as the old account is frozen.

Reply to this email to confirm once done.

Regards,
Accounts Department
""")
(OUT / "02-bec-bank-change.eml").write_bytes(bytes(m))

# 3. Malware delivery: disguised HTML attachment and a zip with a script
m = base("Scanned document from Xerox WorkCentre",
         '"Scanner" <scanner@office-docs-share.top>')
m["Authentication-Results"] = "mx.client-bank.gr; spf=softfail smtp.mailfrom=office-docs-share.top; dkim=none; dmarc=none"
received(m, [("vps-2231.hosting-cheap.top", "194.0.234.20", "mx.client-bank.gr")])
m.set_content("Please find the scanned document attached.\n")
m.add_attachment(b"<html><body><script>/* harmless test file */</script><form action='https://office-docs-share.top/c'>"
                 b"</form></body></html>", maintype="text", subtype="html", filename="Scan_7781.pdf.html")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("document.js", "// harmless test file\n")
m.add_attachment(buf.getvalue(), maintype="application", subtype="zip", filename="documents.zip")
(OUT / "03-malware-attachment.eml").write_bytes(bytes(m))

# 4. Legitimate notification
m = base("[GitHub] A new SSH key was added to your account",
         '"GitHub" <noreply@github.com>', Return_Path="<noreply@github.com>")
m["Authentication-Results"] = ("mx.client-bank.gr; spf=pass smtp.mailfrom=github.com; "
                               "dkim=pass header.d=github.com; dmarc=pass header.from=github.com")
received(m, [("out-21.smtp.github.com", "192.30.252.204", "mx.client-bank.gr")])
m.set_content("A new public key was added to your account.\nIf you did not add it, review your keys: https://github.com/settings/keys\n")
m.add_alternative("""<html><body><p>A new public key was added to your account.</p>
<p><a href="https://github.com/settings/keys">Review your SSH keys</a></p></body></html>""", subtype="html")
(OUT / "04-legit-github.eml").write_bytes(bytes(m))

print("wrote", sorted(p.name for p in OUT.glob("*.eml")))
