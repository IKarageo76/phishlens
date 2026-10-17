"""Lookalike (typosquat, homoglyph, combosquat) detection against protected domains."""

from dataclasses import dataclass

from app.core.lists import brands
from app.core.util import domain_label, registrable_domain

_CONFUSABLES = {
    # Cyrillic and Greek letters that render like Latin ones
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ο": "o", "α": "a", "ν": "v", "τ": "t", "κ": "k",
    # digits and look-alike Latin sequences
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s",
}
_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
# Brand labels that are also everyday words: only exact typos/homoglyphs count for these,
# not "contains the word" (office-supplies.com is not Microsoft).
GENERIC_LABELS = {"office", "live", "booking", "slack", "zoom"}


@dataclass
class LookalikeMatch:
    target: str
    reason: str
    strong: bool


def _decode_idna(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label


def normalise(label: str) -> str:
    out = "".join(_CONFUSABLES.get(ch, ch) for ch in _decode_idna(label.lower()))
    for seq, rep in _SEQUENCES:
        out = out.replace(seq, rep)
    return out.replace("-", "")


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (insert, delete, substitute, transpose)."""
    if a == b:
        return 0
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def find_lookalike(host: str, extra_protected: list[str] | None = None) -> LookalikeMatch | None:
    candidate = registrable_domain(host)
    protected = {registrable_domain(p) for p in brands() | set(extra_protected or [])}
    if not candidate or candidate in protected:
        return None

    label = domain_label(candidate)
    norm = normalise(label)
    best: LookalikeMatch | None = None

    for target in sorted(protected):
        t_label = domain_label(target)
        if len(t_label) < 4:
            continue  # ups, dhl: too short to compare without noise
        t_norm = normalise(t_label)  # both sides normalised the same way
        if norm == t_norm and label != t_label:
            return LookalikeMatch(target, f"homoglyph of {target} ('{label}' reads as '{t_label}')", True)
        if label == t_label:
            best = best or LookalikeMatch(target, f"same name as {target} on a different TLD", False)
            continue
        distance = damerau_levenshtein(norm, t_norm)
        limit = 1 if len(t_label) < 8 else 2
        if 0 < distance <= limit:
            return LookalikeMatch(target, f"typosquat of {target} (edit distance {distance})", True)
        if len(t_label) >= 5 and t_label not in GENERIC_LABELS and t_norm in norm:
            how = "contains" if t_label in label.replace("-", "") else "contains a look-alike spelling of"
            best = LookalikeMatch(target, f"{how} the brand '{t_label}' ({target}) plus extra words", True)
    return best
