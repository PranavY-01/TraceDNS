import base64

import pytest

from helpers import (
    ED25519_KEY,
    RSA_512_KEY,
    RSA_1024_KEY,
    RSA_2048_KEY,
    RSA_2048_PKCS1_KEY,
    long_txt,
    make_resolver,
)
from tracedns.analyzers.dkim import analyze_dkim, rsa_key_bits
from tracedns.models import DNSResult, FindingStatus, QueryStatus, Severity
from tracedns.resolver import InvalidNameError, dkim_query_name, normalize_selector

NAME = "s1._domainkey.example.com"
KEY = RSA_2048_KEY


def dkim_result(*records, status=QueryStatus.SUCCESS):
    if not records and status is QueryStatus.SUCCESS:
        status = QueryStatus.NOT_FOUND
    error = None if status.completed else "simulated failure"
    return DNSResult(NAME, "TXT", status, records=list(records), error=error)


def dkim(record):
    return analyze_dkim(dkim_result(record), "example.com")


def rule_ids(findings):
    return [f.rule_id for f in findings]


def test_supplied_selector_resolves_and_passes():
    resolver = make_resolver({(NAME, "TXT"): [long_txt(f"v=DKIM1; k=rsa; p={KEY}")]})
    result = resolver.query(dkim_query_name(normalize_selector("S1"), "example.com"), "TXT")
    findings = analyze_dkim(result, "example.com")
    assert rule_ids(findings) == ["DKIM-100"]
    assert findings[0].status is FindingStatus.PASS
    assert "does not prove" in findings[0].description
    assert "RSA key size: 2048 bits." in findings[0].evidence


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
    assert "DKIM-002" in rule_ids(dkim("v=DKIM1; k=rsa"))


def test_revoked_key():
    assert rule_ids(dkim("v=DKIM1; p=")) == ["DKIM-004"]


def test_malformed_key_and_tags():
    findings = dkim("k=dsa; v=DKIM1; p=not*base64")
    malformed = [f for f in findings if f.rule_id == "DKIM-003"]
    assert malformed
    text = " ".join(malformed[0].evidence)
    assert "k=dsa" in text and "first tag" in text and "base64" in text


def test_testing_flag():
    assert rule_ids(dkim(f"v=DKIM1; t=y; p={KEY}")) == ["DKIM-100", "DKIM-005"]


def test_multiple_records():
    findings = analyze_dkim(dkim_result(f"p={KEY}", f"p={KEY}"), "example.com")
    assert rule_ids(findings) == ["DKIM-006"]


def test_record_contents_are_treated_as_data():
    hostile = "v=DKIM1; p=$(rm -rf /); [bold red]x[/]; \x1b[31m"
    findings = dkim(hostile)
    # The record is parsed and quoted as evidence, never interpreted.
    assert any(hostile in line for f in findings for line in f.evidence)
    assert "DKIM-100" not in rule_ids(findings)


def test_target_missing_is_inconclusive():
    findings = analyze_dkim(dkim_result(status=QueryStatus.NXDOMAIN), "example.com", False)
    assert rule_ids(findings) == ["DKIM-901"]


# ------------------------------------------------------------- key quality


def test_bare_pkcs1_rsa_key_is_accepted():
    findings = dkim(f"v=DKIM1; p={RSA_2048_PKCS1_KEY}")
    assert rule_ids(findings) == ["DKIM-100"]


def test_whitespace_inside_key_is_ignored():
    spaced = " ".join(KEY[i : i + 64] for i in range(0, len(KEY), 64))
    assert rule_ids(dkim(f"v=DKIM1; p={spaced}")) == ["DKIM-100"]


def test_1024_bit_rsa_key_is_weak():
    findings = dkim(f"v=DKIM1; k=rsa; p={RSA_1024_KEY}")
    assert rule_ids(findings) == ["DKIM-008"]
    assert findings[0].severity is Severity.LOW
    assert "RSA key size: 1024 bits." in findings[0].evidence


def test_rsa_key_under_1024_bits_is_unusable():
    findings = dkim(f"v=DKIM1; p={RSA_512_KEY}")
    assert rule_ids(findings) == ["DKIM-009"]
    assert findings[0].severity is Severity.MEDIUM
    assert "RSA key size: 512 bits." in findings[0].evidence


@pytest.mark.parametrize("key", ["AAAA", base64.b64encode(b"\x30\x03\x02\x01\x05").decode()])
def test_base64_that_is_not_an_rsa_key(key):
    findings = dkim(f"v=DKIM1; p={key}")
    assert rule_ids(findings) == ["DKIM-007"]
    assert findings[0].severity is Severity.MEDIUM


def test_ed25519_key_passes():
    findings = dkim(f"v=DKIM1; k=ed25519; p={ED25519_KEY}")
    assert rule_ids(findings) == ["DKIM-100"]
    assert "Ed25519 key (32 bytes)." in findings[0].evidence


def test_ed25519_key_with_wrong_length():
    findings = dkim(f"v=DKIM1; k=ed25519; p={KEY}")
    assert rule_ids(findings) == ["DKIM-007"]
    assert "Ed25519 keys are 32 bytes" in findings[0].evidence[1]


def test_ed25519_key_declared_as_rsa_is_unparseable():
    assert rule_ids(dkim(f"v=DKIM1; p={ED25519_KEY}")) == ["DKIM-007"]


def test_rsa_parser_rejects_truncated_and_trailing_data():
    der = base64.b64decode(KEY)
    assert rsa_key_bits(der) == 2048
    assert rsa_key_bits(der[:-1]) is None
    assert rsa_key_bits(der + b"\x00") is None
    assert rsa_key_bits(b"") is None
