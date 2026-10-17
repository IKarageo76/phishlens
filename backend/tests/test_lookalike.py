import pytest

from app.analysis.lookalike import damerau_levenshtein, find_lookalike


@pytest.mark.parametrize(
    "domain,target,kind",
    [
        ("paypa1.com", "paypal.com", "homoglyph"),
        ("rnicrosoft.com", "microsoft.com", "homoglyph"),
        ("paypall.com", "paypal.com", "typosquat"),
        ("microsfot.com", "microsoft.com", "typosquat"),
        ("paypal-secure-login.com", "paypal.com", "contains"),
        ("xn--pypal-4ve.com", "paypal.com", "homoglyph"),  # Cyrillic 'а'
    ],
)
def test_detects_lookalikes(domain, target, kind):
    match = find_lookalike(domain)
    assert match is not None, domain
    assert match.target == target
    assert kind in match.reason and match.strong


@pytest.mark.parametrize("domain", ["paypal.com", "github.com", "office-supplies.com", "example.org", "client-bank.gr"])
def test_no_false_positive(domain):
    assert find_lookalike(domain) is None


def test_protected_client_domain():
    match = find_lookalike("cIient-bank.gr".lower().replace("i", "1", 1), ["client-bank.gr"])
    assert match and match.target == "client-bank.gr"


def test_tld_swap_is_weak():
    match = find_lookalike("paypal.co")
    assert match and not match.strong


def test_distance():
    assert damerau_levenshtein("paypal", "paypla") == 1
    assert damerau_levenshtein("abc", "abc") == 0
