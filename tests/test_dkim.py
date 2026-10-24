import pytest

from helpers import make_resolver, txt
from tracedns.analyzers.dkim import analyze_dkim
from tracedns.models import DNSResult, FindingStatus, QueryStatus, Severity
from tracedns.resolver import InvalidNameError, dkim_query_name, normalize_selector

NAME = "s1._domainkey.example.com"
KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"


def dkim_result(*records, status=QueryStatus.SUCCESS):
    if not records and status is QueryStatus.SUCCESS:
        status = QueryStatus.NOT_FOUND
    error = None if status.completed else "simulated failure"
    return DNSResult(NAME, "TXT", status, records=list(records), error=error)


def rule_ids(findings):
    return [f.rule_id for f in findings]


def test_supplied_selector_resolves_and_passes():
    resolver = make_resolver({(NAME, "TXT"): [txt(f"v=DKIM1; k=rsa; p={KEY}")]})
    result = resolver.query(dkim_query_name(normalize_selector("S1"), "example.com"), "TXT")
    findings = analyze_dkim(result, "example.com")
    assert rule_ids(findings) == ["DKIM-100"]
    assert findings[0].status is FindingStatus.PASS
    assert "does not prove" in findings[0].description


def test_selector_omitted_is_skipped():
    findings = analyze_dkim(None, "example.com")
    assert rule_ids(findings) == ["DKIM-800"]
    assert findings[0].status is FindingStatus.SKIPPED
    assert "--dkim-selector" in findings[0].recommendation


@pytest.mark.parametrize("status", [QueryStatus.NOT_FOUND, QueryStatus.NXDOMAIN])
def test_record_missing(status):
    findings = analyze_dkim(dkim_result(status=status), "example.com")
    assert rule_ids(findings) == ["DKIM-001"]
    assert findings[0].severity is Severity.LOW
    assert "different selector" in findings[0].description


@pytest.mark.parametrize("status", [QueryStatus.TIMEOUT, QueryStatus.REFUSED, QueryStatus.ERROR])
def test_query_failure_is_error_not_missing(status):
    findings = analyze_dkim(dkim_result(status=status), "example.com")
    assert rule_ids(findings) == ["DKIM-900"]
    assert findings[0].status is FindingStatus.ERROR


@pytest.mark.parametrize("selector", ["bad selector", "s1;rm -rf", "../x", "-s1"])
def test_invalid_selector_rejected(selector):
    with pytest.raises(InvalidNameError):
        normalize_selector(selector)


def test_missing_public_key():
    assert "DKIM-002" in rule_ids(analyze_dkim(dkim_result("v=DKIM1; k=rsa"), "example.com"))


def test_revoked_key():
    assert rule_ids(analyze_dkim(dkim_result("v=DKIM1; p="), "example.com")) == ["DKIM-004"]


def test_malformed_key_and_tags():
    findings = analyze_dkim(dkim_result("k=dsa; v=DKIM1; p=not*base64"), "example.com")
    malformed = [f for f in findings if f.rule_id == "DKIM-003"]
    assert malformed
    text = " ".join(malformed[0].evidence)
    assert "k=dsa" in text and "first tag" in text and "base64" in text


def test_testing_flag():
    findings = analyze_dkim(dkim_result(f"v=DKIM1; t=y; p={KEY}"), "example.com")
    assert rule_ids(findings) == ["DKIM-100", "DKIM-005"]


def test_multiple_records():
    findings = analyze_dkim(dkim_result(f"p={KEY}", f"p={KEY}"), "example.com")
    assert rule_ids(findings) == ["DKIM-006"]


def test_record_contents_are_treated_as_data():
    hostile = "v=DKIM1; p=$(rm -rf /); [bold red]x[/]; \x1b[31m"
    findings = analyze_dkim(dkim_result(hostile), "example.com")
    # The record is parsed and quoted as evidence, never interpreted.
    assert any(hostile in line for f in findings for line in f.evidence)
    assert "DKIM-100" not in rule_ids(findings)


def test_target_missing_is_inconclusive():
    findings = analyze_dkim(dkim_result(status=QueryStatus.NXDOMAIN), "example.com", False)
    assert rule_ids(findings) == ["DKIM-901"]
