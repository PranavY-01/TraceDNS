import json
import os

import dns.resolver
import pytest
from typer.testing import CliRunner

from helpers import FakeBackend, healthy_responses, txt
from tracedns import cli
from tracedns.resolver import DNSResolver

runner = CliRunner()


@pytest.fixture
def backend(monkeypatch):
    """Route every CLI scan through a fake backend with healthy responses."""
    fake = FakeBackend(healthy_responses())
    monkeypatch.setattr(
        cli, "build_resolver", lambda timeout: DNSResolver(timeout=timeout, backend=fake)
    )
    return fake


def invoke(*args, **kwargs):
    return runner.invoke(cli.app, list(args), **kwargs)


def flat(text):
    """Collapse Rich's line wrapping so assertions can match whole phrases."""
    return " ".join(text.split())


def test_help():
    result = invoke("--help")
    assert result.exit_code == 0
    assert "scan" in result.stdout


def test_scan_help_lists_options():
    result = invoke("scan", "--help")
    assert result.exit_code == 0
    for option in ["--record", "--checks", "--dkim-selector", "--json", "--overwrite", "--timeout"]:
        assert option in result.stdout


def test_version():
    result = invoke("--version")
    assert result.exit_code == 0
    assert result.stdout.strip() == "TraceDNS 1.0.0"


def test_valid_scan_without_issues_exits_zero(backend):
    result = invoke("scan", "Example.com.")
    assert result.exit_code == cli.ExitCode.OK, result.output
    assert "example.com" in result.stdout
    assert "Scan summary" in result.stdout
    assert "DKIM-800" in result.stdout  # skipped, explained
    assert ("example.com", "A") in backend.calls


def test_invalid_domain_exits_two(backend):
    result = invoke("scan", "https://example.com/login")
    assert result.exit_code == cli.ExitCode.INVALID_INPUT
    assert "bare domain" in flat(result.stderr)
    assert backend.calls == []


def test_invalid_selector_exits_two(backend):
    result = invoke("scan", "example.com", "--dkim-selector", "bad selector")
    assert result.exit_code == cli.ExitCode.INVALID_INPUT
    assert backend.calls == []


def test_unknown_record_type_exits_two(backend):
    result = invoke("scan", "example.com", "--record", "A,CNAME")
    assert result.exit_code == cli.ExitCode.INVALID_INPUT
    assert "CNAME" in result.stderr


def test_selected_record_types(backend):
    result = invoke("scan", "example.com", "--record", "a", "--record", "MX", "--checks", "none")
    assert result.exit_code == 0, result.output
    assert backend.calls == [("example.com", "A"), ("example.com", "MX")]


def test_selected_checks_only_run_needed_queries(backend):
    result = invoke("scan", "example.com", "--record", "A", "--checks", "spf")
    assert result.exit_code == 0, result.output
    assert backend.calls == [("example.com", "A"), ("example.com", "TXT")]
    assert "DMARC" not in result.stdout


def test_checks_none_cannot_be_combined(backend):
    result = invoke("scan", "example.com", "--checks", "none,spf")
    assert result.exit_code == cli.ExitCode.INVALID_INPUT


def test_dkim_selector_adds_dkim_lookup(backend):
    result = invoke("scan", "example.com", "-c", "spf", "--dkim-selector", "S1")
    assert result.exit_code == 0, result.output
    assert ("s1._domainkey.example.com", "TXT") in backend.calls
    assert "DKIM-100" in result.stdout


def test_json_export(backend, tmp_path):
    path = tmp_path / "report.json"
    result = invoke("scan", "example.com", "--json", str(path))
    assert result.exit_code == 0, result.output
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target"]["domain"] == "example.com"
    assert data["summary"]["queries_attempted"] == len(data["dns_results"])
    assert "report.json" in result.stdout


def test_existing_report_requires_overwrite(backend, tmp_path):
    path = tmp_path / "report.json"
    path.write_text("{}", encoding="utf-8")
    result = invoke("scan", "example.com", "--json", str(path))
    assert result.exit_code == cli.ExitCode.INVALID_INPUT
    assert "--overwrite" in result.stderr
    assert backend.calls == []  # rejected before any query
    result = invoke("scan", "example.com", "--json", str(path), "--overwrite")
    assert result.exit_code == 0
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == "1.0"


def test_json_stdout_mode_contains_only_json(backend):
    result = invoke("scan", "example.com", "--json", "-")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)  # fails if anything decorative was printed
    assert data["tool"]["name"] == "TraceDNS"
    assert "TRACEDNS" not in result.stdout
    assert "Scan summary" not in result.stdout


def test_operational_error_exit_code(backend):
    backend.responses[("example.com", "TXT")] = dns.resolver.LifetimeTimeout(timeout=1.0, errors=[])
    result = invoke("scan", "example.com")
    assert result.exit_code == cli.ExitCode.OPERATIONAL_FAILURE
    assert "SPF-900" in result.stdout
    assert "partial" in result.stdout


def test_scan_with_findings_exit_code(backend):
    backend.responses[("_dmarc.example.com", "TXT")] = dns.resolver.NXDOMAIN()
    result = invoke("scan", "example.com")
    assert result.exit_code == cli.ExitCode.FINDINGS
    assert "DMARC-001" in result.stdout


def test_info_only_observations_do_not_change_exit_code(backend):
    backend.responses[("_dmarc.example.com", "TXT")] = [txt("v=DMARC1; p=none; rua=mailto:a@b.c")]
    result = invoke("scan", "example.com")
    assert result.exit_code == cli.ExitCode.OK
    assert "DMARC-007" in result.stdout


def test_nonexistent_domain_is_inconclusive(backend):
    backend.responses = {}
    backend.responses.update(
        {("nope.example", t): dns.resolver.NXDOMAIN() for t in ("A", "AAAA", "MX", "NS", "TXT")}
    )
    result = invoke("scan", "nope.example")
    assert result.exit_code == cli.ExitCode.FINDINGS
    assert "SPF-901" in result.stdout and "DMARC-901" in result.stdout


def test_ctrl_c_stops_cleanly_without_report(backend, tmp_path):
    backend.responses[("example.com", "MX")] = KeyboardInterrupt()
    path = tmp_path / "report.json"
    result = invoke("scan", "example.com", "--json", str(path))
    assert result.exit_code == cli.ExitCode.INTERRUPTED
    assert "interrupted" in result.stderr.lower()
    assert list(tmp_path.iterdir()) == []


def test_unwritable_report_is_operational_failure(backend, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("tracedns.reporter.os.replace", fail)
    result = invoke("scan", "example.com", "--json", str(tmp_path / "r.json"))
    assert result.exit_code == cli.ExitCode.OPERATIONAL_FAILURE
    assert "Permission denied" in result.stderr


def test_unexpected_error_has_no_traceback(backend, monkeypatch):
    def broken(*args, **kwargs):
        raise ZeroDivisionError("division by zero")

    monkeypatch.setattr(cli, "run_scan", broken)
    result = invoke("scan", "example.com")
    assert result.exit_code == cli.ExitCode.OPERATIONAL_FAILURE
    assert "Unexpected error" in result.stderr
    assert "Traceback" not in result.output


# ------------------------------------------------------------ welcome screen


def test_no_command_shows_banner_without_blocking(backend):
    result = invoke()
    assert result.exit_code == 0
    assert "SECURITY AUDITING" in result.stdout
    assert "Select an option" not in result.stdout
    assert backend.calls == []


def test_welcome_command_shows_banner(backend):
    result = invoke("welcome")
    assert result.exit_code == 0
    assert "DNS Security Analyzer" in result.stdout


def test_files_and_null_device_are_not_consoles(tmp_path):
    # On Windows, isatty() is True for NUL; it must still not count as a terminal.
    with open(os.devnull, "w") as null, open(tmp_path / "out.txt", "w") as file:
        assert not cli._is_console(null)
        assert not cli._is_console(file)
    assert not cli._is_console(object())


@pytest.fixture
def interactive(monkeypatch):
    monkeypatch.setattr(cli, "_is_interactive", lambda: True)


def test_menu_help_then_exit(backend, interactive):
    result = invoke(input="3\n4\n")
    assert result.exit_code == 0, result.output
    assert "Usage" in result.stdout
    assert "Goodbye." in result.stdout


def test_menu_rejects_invalid_choice(backend, interactive):
    result = invoke(input="9\n4\n")
    assert result.exit_code == 0
    assert "Please select one of the available options" in result.stdout


def test_menu_scan_routes_to_shared_workflow(backend, interactive):
    result = invoke(input="1\nnot a domain\nexample.com\ns1\n4\n")
    assert result.exit_code == 0, result.output
    assert "whitespace" in result.stderr
    assert ("s1._domainkey.example.com", "TXT") in backend.calls
    assert "Scan summary" in result.stdout


def test_menu_inspect_records_skips_checks(backend, interactive):
    result = invoke(input="2\nexample.com\n4\n")
    assert result.exit_code == 0, result.output
    assert ("_dmarc.example.com", "TXT") not in backend.calls
    assert ("example.com", "NS") in backend.calls


def test_menu_end_of_input_exits_cleanly(backend, interactive):
    result = invoke(input="")
    assert result.exit_code == cli.ExitCode.INTERRUPTED
    assert "Traceback" not in result.output
