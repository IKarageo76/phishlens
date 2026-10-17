"""Heuristics on the local part of an email address (before the @)."""

import re

from app.models.schemas import AddressProfile

ROLE_WORDS = {
    "admin", "administrator", "billing", "accounts", "account", "accounting", "invoice", "invoices",
    "payment", "payments", "payroll", "finance", "security", "support", "helpdesk", "service",
    "services", "hr", "ceo", "cfo", "director", "noreply", "no-reply", "donotreply", "info", "sales",
    "office", "it", "verify", "verification", "alert", "alerts", "notification", "notifications",
    "webmaster", "postmaster", "team", "bank", "secure", "update", "mailbox", "itsupport",
}
VOWELS = set("aeiou")


def _longest_consonant_run(s: str) -> int:
    best = run = 0
    for ch in s:
        if ch.isalpha() and ch not in VOWELS and ch != "y":
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def analyse_address(address: str) -> AddressProfile:
    local = address.split("@", 1)[0].lower()
    base, _, tag = local.partition("+")
    tokens = [t for t in re.split(r"[._\-]+", base) if t]
    role = next((t for t in tokens if t in ROLE_WORDS), None)
    if role is None and base in ROLE_WORDS:
        role = base

    letters_digits = re.sub(r"[^a-z0-9]", "", base)
    digits = sum(c.isdigit() for c in letters_digits)
    letters = len(letters_digits) - digits
    switches = sum(1 for a, b in zip(letters_digits, letters_digits[1:], strict=False) if a.isdigit() != b.isdigit())

    reasons: list[str] = []
    if len(letters_digits) >= 6 and digits >= 2 and letters >= 2 and switches >= 3:
        reasons.append("letters and digits are mixed like a generated string")
    if len(letters_digits) >= 8 and _longest_consonant_run(letters_digits) >= 5:
        reasons.append("contains a long run of consonants (not a name or word)")
    if len(letters_digits) >= 10 and digits / max(len(letters_digits), 1) > 0.5:
        reasons.append("mostly digits")

    return AddressProfile(
        address=address.lower(),
        local_part=local,
        role_word=role,
        plus_tag=tag or None,
        looks_random=bool(reasons),
        random_reasons=reasons,
    )
