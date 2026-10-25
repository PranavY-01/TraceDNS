"""The JSON report must match schema/report-<version>.json, and the schema must match the code."""

import json
import re
from pathlib import Path

import dns.resolver
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from helpers import healthy_responses, make_resolver, txt
from tracedns.models import (
    SCHEMA_VERSION,
    SUPPORTED_CHECKS,
    SUPPORTED_RECORD_TYPES,
    FindingStatus,
    QueryStatus,
    ScanStatus,
    Severity,
)
from tracedns.reporter import report_to_json
from tracedns.rules import RULES
from tracedns.scanner import ScanRequest, run_scan

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / f"report-{SCHEMA_VERSION}.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
DEFS = SCHEMA["$defs"]


def report_json(responses, checks=("spf", "dmarc", "dkim"), selector=None, nameservers=()):
    request = ScanRequest(
        "example.com", SUPPORTED_RECORD_TYPES, checks, selector, 5.0, tuple(nameservers)
    )
    return json.loads(report_to_json(run_scan(request, make_resolver(responses))))


def errors(document):
    return [error.message for error in VALIDATOR.iter_errors(document)]


def test_schema_itself_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_sample_report_matches_schema():
    sample = json.loads((ROOT / "examples" / "sample-report.json").read_text(encoding="utf-8"))
    assert errors(sample) == []


def _timeouts():
    return {
        key: dns.resolver.LifetimeTimeout(timeout=1.0, errors=[]) for key in healthy_responses()
    }


def _nxdomain():
    return {key: dns.resolver.NXDOMAIN() for key in healthy_responses()}


def _findings():
    responses = healthy_responses()
    responses[("example.com", "TXT")] = [txt("v=spf1 +all"), txt("v=spf1 -all")]
    responses[("_dmarc.example.com", "TXT")] = [txt("v=DMARC1; p=none; pct=50")]
    return responses


@pytest.mark.parametrize(
    ("responses", "kwargs"),
    [
        (healthy_responses(), {}),
        (healthy_responses(), {"selector": "s1", "nameservers": ["192.0.2.53", "2001:db8::53"]}),
        (healthy_responses(), {"checks": ()}),
        (_timeouts(), {"selector": "s1"}),
        (_nxdomain(), {}),
        (_findings(), {"selector": "missing"}),
    ],
    ids=["healthy", "dkim-and-nameservers", "records-only", "all-timeouts", "nxdomain", "findings"],
)
def test_generated_reports_match_schema(responses, kwargs):
    assert errors(report_json(responses, **kwargs)) == []


def test_schema_rejects_contract_violations():
    report = report_json(healthy_responses())
    finding = next(f for f in report["findings"] if f["status"] == "pass")

    finding["severity"] = "high"  # only findings carry a severity
    assert errors(report)
    finding["severity"] = None

    del report["summary"]["errors"]
    assert errors(report)
    report["summary"]["errors"] = 0

    report["scan"]["nameservers"] = ["not-an-ip"]
    assert errors(report)
    report["scan"]["nameservers"] = []

    report["unexpected"] = True
    assert errors(report)


def test_schema_vocabularies_match_the_code():
    assert SCHEMA["properties"]["schema_version"]["const"] == SCHEMA_VERSION
    assert DEFS["recordType"]["enum"] == list(SUPPORTED_RECORD_TYPES)
    assert DEFS["dnsResult"]["properties"]["status"]["enum"] == [s.value for s in QueryStatus]
    assert DEFS["finding"]["properties"]["status"]["enum"] == [s.value for s in FindingStatus]
    assert DEFS["finding"]["properties"]["severity"]["enum"] == [
        *(s.value for s in Severity),
        None,
    ]
    assert SCHEMA["properties"]["scan"]["properties"]["status"]["enum"] == [
        s.value for s in ScanStatus
    ]
    assert SCHEMA["properties"]["scan"]["properties"]["checks"]["items"]["enum"] == list(
        SUPPORTED_CHECKS
    )


def test_every_rule_id_matches_the_schema_pattern():
    pattern = re.compile(DEFS["finding"]["properties"]["rule_id"]["pattern"])
    assert all(pattern.match(rule_id) for rule_id in RULES)
