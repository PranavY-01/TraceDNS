import io
import json
from datetime import datetime

import dns.resolver
import pytest
from rich.console import Console

from helpers import healthy_responses, make_resolver, txt
from tracedns import reporter
from tracedns.models import (
    DNSResult,
    FindingStatus,
    QueryStatus,
    ScanStatus,
    Severity,
    build_summary,
)
from tracedns.reporter import (
    THEME,
    ReportWriteError,
    build_dns_table,
    finding_label,
    render_banner,
    render_report,
    report_to_json,
    write_json_report,
)
from tracedns.rules import make_finding
from tracedns.scanner import ScanRequest, run_scan

ALL_RECORDS = ("A", "AAAA", "MX", "NS", "TXT")


def scan(responses=None, checks=("spf", "dmarc", "dkim"), selector=None, records=ALL_RECORDS):
    request = ScanRequest("example.com", records, checks, selector, 1.0)
    return run_scan(request, make_resolver(responses or healthy_responses()))


def plain_console(width=120):
    return Console(
        file=io.StringIO(),
        theme=THEME,
        width=width,
        color_system=None,
        force_terminal=False,
        highlight=False,
    )


def rendered(renderable_fn, *args, width=120):
    console = plain_console(width)
    renderable_fn(console, *args)
    return console.file.getvalue()


# ----------------------------------------------------------------- terminal


def test_findings_are_displayed_with_ids_evidence_and_recommendation():
    responses = healthy_responses()
    responses[("_dmarc.example.com", "TXT")] = [txt("v=DMARC1; p=none")]
    output = rendered(render_report, scan(responses))
    assert "DMARC-007" in output
    assert "monitoring-only" in output
    assert "Evidence" in output and "Recommendation" in output
    assert "v=DMARC1; p=none" in output
    assert "INFO" in output


@pytest.mark.parametrize(
    ("rule_id", "label", "style"),
    [
        ("SPF-004", "HIGH", "td.error"),
        ("SPF-001", "MEDIUM", "td.warning"),
        ("SPF-005", "LOW", "td.secondary"),
        ("SPF-006", "INFO", "td.muted"),
        ("SPF-100", "PASS", "td.success"),
        ("SPF-900", "ERROR", "td.error"),
        ("SPF-901", "INCONCLUSIVE", "td.warning"),
        ("DKIM-800", "SKIPPED", "td.muted"),
    ],
)
def test_severity_and_status_formatting(rule_id, label, style):
    assert finding_label(make_finding(rule_id, "example.com")) == (label, style)


def test_empty_result_sets_render():
    console = plain_console()
    console.print(build_dns_table(console, []))
    assert "No queries were run." in console.file.getvalue()

    report = scan(checks=())
    assert report.findings == []
    output = rendered(render_report, report)
    assert "Security assessment" not in output
    assert "Scan summary" in output


def test_failed_query_shows_error_in_table():
    responses = healthy_responses()
    responses[("example.com", "AAAA")] = dns.resolver.LifetimeTimeout(timeout=1.0, errors=[])
    output = rendered(render_report, scan(responses))
    assert "timeout" in output
    assert "No response within 1 seconds" in output
    assert "partial" in output


def test_untrusted_dns_text_is_not_interpreted():
    responses = healthy_responses()
    responses[("example.com", "TXT")] = [txt("[bold red]owned[/] \x1b[31mred")]
    console = Console(
        file=io.StringIO(), theme=THEME, width=200, color_system="truecolor", force_terminal=True
    )
    render_report(console, scan(responses, checks=()))
    output = console.file.getvalue()
    assert "[bold red]owned[/]" in output  # markup printed literally
    assert "\\x1b[31m" in output  # control character escaped
    assert "\x1b[31mred" not in output


def test_long_values_truncated_in_table_but_complete_in_json():
    long_key = "p=" + "A" * 600
    responses = healthy_responses()
    chunks = [long_key[i : i + 200] for i in range(0, len(long_key), 200)]
    responses[("s1._domainkey.example.com", "TXT")] = [txt(*chunks)]
    report = scan(responses, selector="s1")
    output = rendered(render_report, report, width=400)
    assert "(+422 chars, full value in JSON)" in output
    assert "A" * 400 not in output
    data = json.loads(report_to_json(report))
    dkim = next(r for r in data["dns_results"] if r["query_name"].startswith("s1."))
    assert dkim["records"] == [long_key]


def test_banner_contains_brand_and_hint():
    output = rendered(render_banner)
    assert "DNS INTELLIGENCE" in output and "SECURITY AUDITING" in output
    assert "v1.0.0" in output
    assert "tracedns scan <domain>" in output


# --------------------------------------------------------------------- JSON


def test_json_serialization_matches_schema():
    data = json.loads(report_to_json(scan(selector="s1")))
    assert list(data) == [
        "schema_version",
        "tool",
        "target",
        "scan",
        "dns_results",
        "findings",
        "summary",
    ]
    assert data["schema_version"] == "1.0"
    assert data["tool"] == {"name": "TraceDNS", "version": "1.0.0"}
    assert data["target"] == {"domain": "example.com"}
    scan_meta = data["scan"]
    assert scan_meta["status"] == "completed"
    assert scan_meta["record_types"] == list(ALL_RECORDS)
    assert scan_meta["checks"] == ["spf", "dmarc", "dkim"]
    assert datetime.fromisoformat(scan_meta["started_at"]).utcoffset().total_seconds() == 0
    assert isinstance(scan_meta["duration_seconds"], float)
    assert set(data["dns_results"][0]) == {
        "query_name",
        "record_type",
        "status",
        "records",
        "error",
    }
    assert set(data["findings"][0]) == {
        "id",
        "category",
        "check",
        "status",
        "severity",
        "title",
        "description",
        "evidence",
        "recommendation",
        "rule_id",
    }


def test_summary_counts_each_item_once():
    results = [
        DNSResult("example.com", "A", QueryStatus.SUCCESS, ["192.0.2.1"]),
        DNSResult("example.com", "AAAA", QueryStatus.NOT_FOUND),
        DNSResult("example.com", "TXT", QueryStatus.TIMEOUT, error="t"),
        DNSResult("_dmarc.example.com", "TXT", QueryStatus.NXDOMAIN),
    ]
    findings = [
        make_finding("SPF-900", "example.com"),
        make_finding("DMARC-001", "_dmarc.example.com"),
        make_finding("DKIM-800", "example.com"),
        make_finding("SPF-004", "x.example"),
        make_finding("SPF-006", "y.example"),
        make_finding("DMARC-100", "z.example"),
        make_finding("DMARC-901", "w.example"),
    ]
    summary = build_summary(results, findings)
    assert summary.queries_attempted == 4
    assert summary.queries_completed == 3
    assert summary.queries_failed == 1
    assert summary.assessments_total == 7
    assert summary.findings_total == 3
    assert summary.findings_by_severity == {"high": 1, "medium": 1, "low": 0, "info": 1}
    assert summary.passed == 1
    assert summary.errors == 1
    assert summary.inconclusive == 1
    assert summary.skipped == 1


def test_report_summary_matches_report_contents():
    report = scan()
    summary = report.summary
    assert summary.queries_attempted == len(report.dns_results)
    assert summary.assessments_total == len(report.findings)
    assert summary.findings_total == sum(
        1 for f in report.findings if f.status is FindingStatus.FINDING
    )


def test_scan_status_partial_and_failed():
    responses = healthy_responses()
    responses[("example.com", "MX")] = dns.resolver.LifetimeTimeout(timeout=1.0, errors=[])
    assert scan(responses).scan.status is ScanStatus.PARTIAL

    everything_times_out = {
        key: dns.resolver.LifetimeTimeout(timeout=1.0, errors=[]) for key in healthy_responses()
    }
    report = scan(everything_times_out, checks=())
    assert report.scan.status is ScanStatus.FAILED


def test_write_report_creates_valid_json(tmp_path):
    path = write_json_report(scan(), tmp_path / "report.json")
    assert json.loads(path.read_text(encoding="utf-8"))["target"]["domain"] == "example.com"
    assert list(tmp_path.iterdir()) == [path]


def test_existing_file_is_not_replaced_without_overwrite(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("keep me", encoding="utf-8")
    with pytest.raises(ReportWriteError, match="already exists"):
        write_json_report(scan(), path)
    assert path.read_text(encoding="utf-8") == "keep me"
    write_json_report(scan(), path, overwrite=True)
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == "1.0"


def test_missing_directory_is_a_clear_error(tmp_path):
    with pytest.raises(ReportWriteError, match="does not exist"):
        write_json_report(scan(), tmp_path / "missing" / "report.json")


def test_directory_target_is_rejected(tmp_path):
    with pytest.raises(ReportWriteError, match="is a directory"):
        write_json_report(scan(), tmp_path)


def test_write_failure_leaves_no_partial_files(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(reporter.os, "replace", fail)
    with pytest.raises(ReportWriteError, match="Permission denied"):
        write_json_report(scan(), tmp_path / "report.json")
    assert list(tmp_path.iterdir()) == []


def test_interrupted_write_leaves_no_partial_files(tmp_path, monkeypatch):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(reporter.os, "fsync", interrupt)
    with pytest.raises(KeyboardInterrupt):
        write_json_report(scan(), tmp_path / "report.json")
    assert list(tmp_path.iterdir()) == []


def test_severity_rank_order():
    assert [s.rank for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)] == [
        0,
        1,
        2,
        3,
    ]
