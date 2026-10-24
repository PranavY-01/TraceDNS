import pytest

from helpers import txt_result
from tracedns.analyzers.spf import analyze_spf, is_spf_record
from tracedns.models import FindingStatus, QueryStatus, Severity


def rule_ids(findings):
    return [f.rule_id for f in findings]


def test_single_valid_record_passes():
    findings = analyze_spf(txt_result("v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all"))
    assert rule_ids(findings) == ["SPF-100"]
    assert findings[0].status is FindingStatus.PASS
    assert findings[0].severity is None
    assert "v=spf1 ip4:192.0.2.0/24" in findings[0].evidence[0]


def test_missing_spf_when_query_succeeded():
    findings = analyze_spf(txt_result("google-site-verification=abc"))
    assert rule_ids(findings) == ["SPF-001"]
    assert findings[0].status is FindingStatus.FINDING
    assert findings[0].severity is Severity.MEDIUM
    assert "none begin with 'v=spf1'" in findings[0].evidence[0]


def test_missing_spf_when_no_txt_records():
    findings = analyze_spf(txt_result())
    assert rule_ids(findings) == ["SPF-001"]
    assert "no TXT records" in findings[0].evidence[0]


@pytest.mark.parametrize(
    "status", [QueryStatus.TIMEOUT, QueryStatus.SERVFAIL, QueryStatus.REFUSED, QueryStatus.ERROR]
)
def test_query_failure_is_error_not_missing(status):
    findings = analyze_spf(txt_result(status=status))
    assert rule_ids(findings) == ["SPF-900"]
    assert findings[0].status is FindingStatus.ERROR
    assert findings[0].severity is None


def test_nxdomain_is_inconclusive():
    findings = analyze_spf(txt_result(status=QueryStatus.NXDOMAIN))
    assert rule_ids(findings) == ["SPF-901"]
    assert findings[0].status is FindingStatus.INCONCLUSIVE


def test_multiple_spf_records():
    findings = analyze_spf(txt_result("v=spf1 -all", "v=spf1 include:x.example ~all"))
    assert rule_ids(findings) == ["SPF-002"]
    assert len(findings[0].evidence) == 2


def test_unrelated_txt_records_are_ignored():
    findings = analyze_spf(txt_result("ms=12345", "v=spf1 -all", "v=spf10 something"))
    assert rule_ids(findings) == ["SPF-100"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("v=spf1 -all", True),
        ("V=SPF1 -all", True),
        ("v=spf1", True),
        ("v=spf10 -all", False),
        ("spf1 -all", False),
        (" v=spf1 -all", False),
    ],
)
def test_is_spf_record(text, expected):
    assert is_spf_record(text) is expected


@pytest.mark.parametrize(
    ("record", "rule", "severity"),
    [
        ("v=spf1 +all", "SPF-004", Severity.HIGH),
        ("v=spf1 all", "SPF-004", Severity.HIGH),
        ("v=spf1 ?all", "SPF-005", Severity.LOW),
        ("v=spf1 ~all", "SPF-006", Severity.INFO),
    ],
)
def test_all_qualifiers_have_distinct_rules(record, rule, severity):
    findings = analyze_spf(txt_result(record))
    match = [f for f in findings if f.rule_id == rule]
    assert match and match[0].severity is severity


def test_softfail_still_passes_basic_checks():
    findings = analyze_spf(txt_result("v=spf1 mx ~all"))
    assert rule_ids(findings) == ["SPF-100", "SPF-006"]


def test_hardfail_has_no_qualifier_finding():
    assert rule_ids(analyze_spf(txt_result("v=spf1 mx -all"))) == ["SPF-100"]


@pytest.mark.parametrize(
    ("record", "fragment"),
    [
        ("v=spf1 inlcude:example.net -all", "unknown mechanism"),
        ("v=spf1 ip4:999.0.0.1 -all", "not a valid IPv4"),
        ("v=spf1 ip4:192.0.2.0/33 -all", "prefix length"),
        ("v=spf1 ip6:192.0.2.1 -all", "not a valid IPv6"),
        ("v=spf1 include -all", "requires ':domain'"),
        ("v=spf1 all:foo", "takes no argument"),
        ("v=spf1 a/40 -all", "IPv4 prefix"),
        ("v=spf1 --all", "not a valid mechanism"),
        ("v=spf1 redirect=a.example redirect=b.example", "more than once"),
        ("v=spf1 redirect= -all", "requires a domain"),
    ],
)
def test_malformed_syntax(record, fragment):
    findings = analyze_spf(txt_result(record))
    syntax = [f for f in findings if f.rule_id == "SPF-003"]
    assert syntax, findings
    assert any(fragment in line for line in syntax[0].evidence)
    assert "SPF-100" not in rule_ids(findings)


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 a mx -all",
        "v=spf1 a:mail.example.com/24 mx//64 -all",
        "v=spf1 ip6:2001:db8::/32 -all",
        "v=spf1 exists:%{i}._spf.example.com -all",
        "v=spf1 include:_spf.example.net exp=explain.example.com -all",
        "v=spf1 redirect=_spf.example.net",
        "v=spf1 unknown-mod=value -all",
    ],
)
def test_valid_syntax_variants(record):
    assert rule_ids(analyze_spf(txt_result(record))) == ["SPF-100"]


def test_missing_all_and_redirect():
    assert "SPF-007" in rule_ids(analyze_spf(txt_result("v=spf1 mx")))


def test_terms_after_all_are_flagged():
    findings = analyze_spf(txt_result("v=spf1 -all include:late.example"))
    after = [f for f in findings if f.rule_id == "SPF-008"]
    assert after and "Ignored: include:late.example" in after[0].evidence


def test_ptr_is_flagged():
    assert "SPF-009" in rule_ids(analyze_spf(txt_result("v=spf1 ptr -all")))


def test_finding_ids_are_stable_and_scoped_to_the_name():
    finding = analyze_spf(txt_result("v=spf1 +all"))[0]
    assert finding.id == "SPF-004:example.com"
    assert finding.category == "email-authentication"
    assert finding.check == "spf"
