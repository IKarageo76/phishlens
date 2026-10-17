"""Identify who hosts a domain's mailboxes from its MX records."""

PROVIDERS: list[tuple[str, str, bool]] = [
    # (MX suffix, provider name, large shared provider)
    (".mail.protection.outlook.com", "Microsoft 365", True),
    (".olc.protection.outlook.com", "Outlook.com", True),
    ("google.com", "Google Workspace / Gmail", True),
    ("googlemail.com", "Google Workspace / Gmail", True),
    (".protonmail.ch", "Proton Mail", True),
    (".zoho.com", "Zoho Mail", True),
    (".zoho.eu", "Zoho Mail", True),
    (".yahoodns.net", "Yahoo Mail", True),
    (".icloud.com", "iCloud Mail", True),
    (".yandex.net", "Yandex Mail", True),
    (".mail.ru", "Mail.ru", True),
    (".gmx.net", "GMX", True),
    (".web.de", "WEB.DE", True),
    (".mimecast.com", "Mimecast (gateway)", True),
    (".pphosted.com", "Proofpoint (gateway)", True),
    (".ppe-hosted.com", "Proofpoint Essentials (gateway)", True),
    (".barracudanetworks.com", "Barracuda (gateway)", True),
    (".messagelabs.com", "Broadcom / Symantec (gateway)", True),
    (".iphmx.com", "Cisco Secure Email (gateway)", True),
    (".trendmicro.com", "Trend Micro (gateway)", True),
    (".mx.cloudflare.net", "Cloudflare Email Routing (forwarding)", True),
    (".improvmx.com", "ImprovMX (forwarding)", True),
    ("forwardemail.net", "Forward Email (forwarding)", True),
    (".amazonaws.com", "Amazon SES", True),
    (".secureserver.net", "GoDaddy", True),
    (".registrar-servers.com", "Namecheap", True),
    (".privateemail.com", "Namecheap Private Email", True),
    (".ovh.net", "OVHcloud", True),
    (".ionos.com", "IONOS", True),
    (".ionos.de", "IONOS", True),
    (".hostinger.com", "Hostinger", True),
    (".titan.email", "Titan Email", True),
    (".fastmail.com", "Fastmail", True),
]


def identify(mx_hosts: list[str]) -> tuple[str | None, bool]:
    """Return (provider name, is_large_shared_provider). Unknown MX = (None, False)."""
    for host in mx_hosts:
        h = host.lower().rstrip(".")
        for suffix, name, large in PROVIDERS:
            s = suffix.lstrip(".")
            if h == s or h.endswith("." + s):
                return name, large
    return None, False
