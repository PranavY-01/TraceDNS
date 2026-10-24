import pytest

from helpers import txt_result
from tracedns.analyzers.dmarc import analyze_dmarc
from tracedns.models import FindingStatus, QueryStatus, Severity

NAME = "_dmarc.example.com"


def dmarc(*records, status=QueryStatus.SUCCESS):
    return analyze_dmarc(txt_result(*records, name=NAME, status=status))


def rule_ids(findings):
    return [f.rule_id for f in findings]


def test_valid_enforcing_record_passes():
    findings = dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com")
    assert rule_ids(findings) == ["DMARC-100"]
    assert findings[0].status is FindingStatus.PASS


def test_missing_record_when_query_returned_no_txt():
    findings = dmarc()
    assert rule_ids(findings) == ["DMARC-001"]
    assert findings[0].severity is Severity.MEDIUM


def test_missing_record_when_name_does_not_exist():
    findings = dmarc(status=QueryStatus.NXDOMAIN)
    assert rule_ids(findings) == ["DMARC-001"]
    assert "NXDOMAIN" in findings[0].evidence[0]


@pytest.mark.parametrize("status", [QueryStatus.TIMEOUT, QueryStatus.SERVFAIL, QueryStatus.ERROR])
def test_dns_failure_is_not_reported_as_missing(status):
    findings = dmarc(status=status)
    assert rule_ids(findings) == ["DMARC-900"]
    assert findings[0].status is FindingStatus.ERROR


def test_unrelated_txt_records_are_ignored():
    findings = dmarc("some-verification=1", "v=DMARC1; p=quarantine; rua=mailto:d@example.com")
    assert rule_ids(findings) == ["DMARC-100"]


def test_only_unrelated_records_means_missing():
    assert rule_ids(dmarc("some-verification=1")) == ["DMARC-001"]


def test_duplicate_candidate_records():
    findings = dmarc("v=DMARC1; p=none", "v=DMARC1; p=reject")
    assert rule_ids(findings) == ["DMARC-002"]
    assert len(findings[0].evidence) == 2


@pytest.mark.parametrize("record", ["v=DMARC2; p=reject", "v=dmarc1; p=reject"])
def test_invalid_version(record):
    assert rule_ids(dmarc(record)) == ["DMARC-003"]


def test_version_must_be_first():
    # Starts with "v=DMARC" so it is a candidate, but the first tag is malformed.
    assert rule_ids(dmarc("v=DMARC; v=DMARC1; p=reject")) == ["DMARC-003"]


def test_missing_policy():
    assert "DMARC-004" in rule_ids(dmarc("v=DMARC1; rua=mailto:d@example.com"))


def test_invalid_policy_value():
    findings = dmarc("v=DMARC1; p=block; rua=mailto:d@example.com")
    assert "DMARC-005" in rule_ids(findings)
    assert "DMARC-100" not in rule_ids(findings)


def test_tag_order_does_not_matter():
    findings = dmarc("v=DMARC1; rua=mailto:d@example.com; adkim=s; p=reject")
    assert rule_ids(findings) == ["DMARC-100"]


def test_whitespace_is_tolerated():
    findings = dmarc("v = DMARC1 ;p= quarantine;   rua=mailto:d@example.com ;  ")
    assert rule_ids(findings) == ["DMARC-100"]


def test_policy_value_is_case_insensitive():
    assert rule_ids(dmarc("v=DMARC1; p=Reject; rua=mailto:d@example.com")) == ["DMARC-100"]


def test_p_none_is_info_not_vulnerability():
    findings = dmarc("v=DMARC1; p=none; rua=mailto:d@example.com")
    assert rule_ids(findings) == ["DMARC-100", "DMARC-007"]
    observation = findings[1]
    assert observation.severity is Severity.INFO


def test_malformed_tags_and_values():
    findings = dmarc("v=DMARC1; p=reject; pct=150; adkim=x; sp=maybe; junk; p=none")
    malformed = [f for f in findings if f.rule_id == "DMARC-006"]
    assert malformed
    text = " ".join(malformed[0].evidence)
    for fragment in ["pct=150", "adkim=x", "sp=maybe", "'junk'", "Duplicate tag 'p'"]:
        assert fragment in text


def test_pct_below_100_is_observed():
    findings = dmarc("v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com")
    assert "DMARC-008" in rule_ids(findings)


def test_missing_rua_is_observed():
    assert rule_ids(dmarc("v=DMARC1; p=reject")) == ["DMARC-100", "DMARC-009"]


def test_weaker_subdomain_policy_is_observed():
    findings = dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com")
    assert "DMARC-010" in rule_ids(findings)


def test_target_missing_makes_check_inconclusive():
    findings = analyze_dmarc(txt_result(name=NAME, status=QueryStatus.NXDOMAIN), False)
    assert rule_ids(findings) == ["DMARC-901"]
    assert findings[0].status is FindingStatus.INCONCLUSIVE
