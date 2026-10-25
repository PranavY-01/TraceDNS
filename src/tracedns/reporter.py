"""Terminal rendering (Rich) and JSON report serialization.

Rendering functions only read report objects; they never query DNS or
decide severity. Every string that originates from DNS is wrapped in a
:class:`rich.text.Text` (so it is never parsed as markup) after control
characters are escaped.
"""

from __future__ import annotations

import json
import os
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from rich import box
from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.status import Status
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from tracedns import __version__
from tracedns.models import (
    DNSResult,
    Finding,
    FindingStatus,
    QueryStatus,
    ScanReport,
    ScanStatus,
    Severity,
    to_jsonable,
)
from tracedns.scanner import ScanRequest, StageOutcome

SUBTITLE = "DNS INTELLIGENCE {dot} SECURITY AUDITING"
DESCRIPTION = "Inspect DNS records. Assess SPF, DMARC, and DKIM configuration."
MAX_TABLE_VALUE_LENGTH = 180

PALETTE = {
    "primary": "#E68A70",
    "secondary": "#64C7D8",
    "success": "#75D6A0",
    "warning": "#F0C36A",
    "error": "#F07878",
    "muted": "#8996A5",
    "text": "#E6EAF0",
}

# Each palette color is available as "td.<name>" and, in bold, "td.<name>.b".
THEME = Theme(
    {
        **{f"td.{name}": color for name, color in PALETTE.items()},
        **{f"td.{name}.b": f"bold {color}" for name, color in PALETTE.items()},
        "td.heading": f"bold {PALETTE['text']}",
    }
)

_LOGO_TRACE = ("▀█▀ █▀█ ▄▀█ █▀▀ █▀▀", " █  █▀▄ █▀█ █▄▄ ██▄")
_LOGO_DNS = ("█▀▄ █▄ █ █▀", "█▄▀ █ ▀█ ▄█")
_LOGO_ASCII = ("T R A C E", "D N S")


@dataclass(frozen=True)
class Glyphs:
    ok: str
    warning: str
    error: str
    skipped: str
    ready: str
    dot: str
    arrow: str
    empty: str


_UNICODE_GLYPHS = Glyphs("✓", "▲", "✗", "○", "●", "·", "›", "—")
_ASCII_GLYPHS = Glyphs("+", "!", "x", "-", "*", "|", ">", "-")


def make_console(*, stderr: bool = False) -> Console:
    """Create a themed console. Rich detects color support, NO_COLOR, and redirection."""
    return Console(theme=THEME, stderr=stderr, highlight=False)


def glyphs_for(console: Console) -> Glyphs:
    """Use Unicode symbols only when the output encoding can represent them."""
    return _UNICODE_GLYPHS if console.encoding.lower().startswith("utf") else _ASCII_GLYPHS


def safe_text(value: str, style: str = "") -> Text:
    """Wrap untrusted text for display, escaping control characters."""
    cleaned = "".join(
        char if unicodedata.category(char) != "Cc" else f"\\x{ord(char):02x}" for char in value
    )
    return Text(cleaned, style=style)


# --------------------------------------------------------------------- banner


def render_banner(console: Console) -> None:
    """Print the branded startup banner."""
    glyphs = glyphs_for(console)
    unicode_ok = glyphs is _UNICODE_GLYPHS
    logo = Text(justify="center")
    if unicode_ok:
        for left, right in zip(_LOGO_TRACE, _LOGO_DNS, strict=True):
            logo.append(left, style="td.primary.b")
            logo.append("   ")
            logo.append(right, style="td.secondary.b")
            logo.append("\n")
    else:
        logo.append(_LOGO_ASCII[0], style="td.primary.b")
        logo.append("   ")
        logo.append(_LOGO_ASCII[1], style="td.secondary.b")
        logo.append("\n")
    logo.append(SUBTITLE.format(dot=glyphs.dot), style="td.muted")

    console.print(
        Panel(
            Align.center(logo),
            box=box.ROUNDED,
            border_style="td.primary",
            padding=(1, 6),
            expand=False,
            subtitle=Text(f" v{__version__} ", style="td.muted"),
            subtitle_align="right",
        )
    )
    info = Text("  ")
    info.append("DNS Security Analyzer", style="td.heading")
    info.append(f"  {glyphs.dot}  v{__version__}\n", style="td.muted")
    info.append(f"  {DESCRIPTION}\n", style="td.text")
    info.append(f"  {glyphs.ready} ", style="td.success")
    info.append("Ready ", style="td.success")
    info.append(f"{glyphs.empty} run ", style="td.muted")
    info.append("tracedns scan <domain>", style="td.secondary")
    info.append(" or ", style="td.muted")
    info.append("tracedns --help", style="td.secondary")
    console.print(info)
    console.print()


def render_brand_line(console: Console) -> None:
    """Print the one-line brand header used before a direct scan."""
    glyphs = glyphs_for(console)
    line = Text()
    line.append("TRACEDNS", style="td.primary.b")
    line.append(f" v{__version__} {glyphs.dot} ", style="td.muted")
    line.append(SUBTITLE.format(dot=glyphs.dot), style="td.muted")
    console.print(line)


def render_menu(console: Console) -> None:
    """Print the interactive welcome menu options."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="td.primary.b", justify="right")
    table.add_column(style="td.text")
    table.add_column(style="td.muted")
    table.add_row("1", "Scan a domain", "records + SPF, DMARC, optional DKIM")
    table.add_row("2", "Inspect DNS records", "A, AAAA, MX, NS, TXT only")
    table.add_row("3", "Help and usage", "commands, options, exit codes")
    table.add_row("4", "Exit", "")
    console.print(
        Panel(
            table,
            title="Menu",
            title_align="left",
            box=box.ROUNDED,
            border_style="td.muted",
            expand=False,
            padding=(0, 2),
        )
    )


def render_usage(console: Console) -> None:
    """Print a short usage reference."""
    table = Table.grid(padding=(0, 3))
    table.add_column(style="td.secondary", no_wrap=True)
    table.add_column(style="td.text")
    rows = [
        ("tracedns scan example.com", "Records + SPF, DMARC (DKIM skipped)"),
        ("tracedns scan example.com -r A,MX", "Query only the listed record types"),
        ("tracedns scan example.com -c spf", "Run only the listed checks (or 'none')"),
        ("tracedns scan example.com -s selector1", "Also look up a DKIM selector"),
        ("tracedns scan example.com --json out.json", "Write a JSON report"),
        ("tracedns scan example.com --json -", "JSON only, to stdout"),
        ("tracedns --help / --version", "Full help / version"),
    ]
    for command, description in rows:
        table.add_row(command, description)
    codes = Text(
        "Exit codes: 0 no issues  1 issues found  2 invalid input  3 operational failure  "
        "130 interrupted",
        style="td.muted",
    )
    console.print(
        Panel(
            Group(table, Text(), codes),
            title="Usage",
            title_align="left",
            box=box.ROUNDED,
            border_style="td.muted",
            expand=False,
            padding=(0, 2),
        )
    )


# ------------------------------------------------------------------- progress


def render_scan_header(console: Console, request: ScanRequest) -> None:
    """Print the target and the operations about to run."""
    glyphs = glyphs_for(console)
    console.print()
    console.rule(Text(f" {request.domain} ", style="td.primary.b"), style="td.muted", align="left")
    line = Text("  ")
    line.append("records ", style="td.muted")
    line.append(", ".join(request.record_types), style="td.text")
    line.append(f"  {glyphs.dot}  checks ", style="td.muted")
    line.append(", ".join(request.checks) or "none", style="td.text")
    if request.dkim_selector:
        line.append(f"  {glyphs.dot}  selector ", style="td.muted")
        line.append(request.dkim_selector, style="td.text")
    line.append(f"  {glyphs.dot}  timeout ", style="td.muted")
    line.append(f"{request.timeout:g}s", style="td.text")
    if request.nameservers:
        line.append(f"  {glyphs.dot}  resolver ", style="td.muted")
        line.append(", ".join(request.nameservers), style="td.text")
    console.print(line)
    console.print()


class StageReporter:
    """Scan observer that shows a spinner while a stage runs and a line when it ends.

    The spinner is only used on interactive terminals; redirected output gets
    plain result lines.
    """

    _STYLES: ClassVar[dict[StageOutcome, tuple[str, str]]] = {
        StageOutcome.OK: ("ok", "td.success"),
        StageOutcome.WARNING: ("warning", "td.warning"),
        StageOutcome.ERROR: ("error", "td.error"),
        StageOutcome.SKIPPED: ("skipped", "td.muted"),
    }

    def __init__(self, console: Console) -> None:
        self.console = console
        self.glyphs = glyphs_for(console)
        self._status: Status | None = None

    def stage_started(self, stage: str) -> None:
        if self.console.is_terminal:
            self._status = self.console.status(
                Text(f"{stage}...", style="td.muted"), spinner="dots", spinner_style="td.secondary"
            )
            self._status.start()

    def stage_finished(self, stage: str, outcome: StageOutcome, detail: str) -> None:
        self.close()
        glyph_name, style = self._STYLES[outcome]
        line = Text("  ")
        line.append(getattr(self.glyphs, glyph_name), style=style)
        line.append(f" {stage:<24}", style="td.text")
        line.append(detail, style="td.muted")
        self.console.print(line)

    def close(self) -> None:
        if self._status is not None:
            self._status.stop()
            self._status = None


# --------------------------------------------------------------------- report

_QUERY_STATUS_STYLES = {
    QueryStatus.SUCCESS: ("found", "td.success"),
    QueryStatus.NOT_FOUND: ("no records", "td.muted"),
    QueryStatus.NXDOMAIN: ("nxdomain", "td.warning"),
    QueryStatus.TIMEOUT: ("timeout", "td.error"),
    QueryStatus.SERVFAIL: ("servfail", "td.error"),
    QueryStatus.REFUSED: ("refused", "td.error"),
    QueryStatus.ERROR: ("error", "td.error"),
}

_SEVERITY_STYLES = {
    Severity.HIGH: "td.error",
    Severity.MEDIUM: "td.warning",
    Severity.LOW: "td.secondary",
    Severity.INFO: "td.muted",
}

_STATUS_STYLES = {
    FindingStatus.PASS: "td.success",
    FindingStatus.ERROR: "td.error",
    FindingStatus.INCONCLUSIVE: "td.warning",
    FindingStatus.SKIPPED: "td.muted",
}

_SCAN_STATUS_STYLES = {
    ScanStatus.COMPLETED: "td.success",
    ScanStatus.PARTIAL: "td.warning",
    ScanStatus.FAILED: "td.error",
}


def finding_label(finding: Finding) -> tuple[str, str]:
    """Return the badge text and style for a finding (severity, or status if none)."""
    if finding.status is FindingStatus.FINDING and finding.severity is not None:
        return finding.severity.value.upper(), _SEVERITY_STYLES[finding.severity]
    return finding.status.value.upper(), _STATUS_STYLES[finding.status]


def render_report(console: Console, report: ScanReport, json_path: Path | None = None) -> None:
    """Render the DNS table, findings, and summary for a finished scan."""
    console.print()
    console.print(build_dns_table(console, report.dns_results))
    if report.findings:
        console.print()
        console.rule(
            Text(" Security assessment ", style="td.heading"), style="td.muted", align="left"
        )
        for finding in report.findings:
            console.print(build_finding_panel(console, finding))
    console.print()
    console.print(build_summary_panel(console, report, json_path))


def build_dns_table(console: Console, results: list[DNSResult]) -> Table:
    glyphs = glyphs_for(console)
    table = Table(
        title=Text("DNS records", style="td.heading"),
        title_justify="left",
        box=box.SIMPLE_HEAD,
        header_style="td.muted",
        border_style="td.muted",
        expand=True,
        pad_edge=False,
    )
    table.add_column("Type", style="td.secondary.b", no_wrap=True, width=5)
    table.add_column("Name", style="td.text", overflow="fold", ratio=3, min_width=18)
    table.add_column("Value", style="td.text", overflow="fold", ratio=5)
    table.add_column("Status", no_wrap=True, width=10)

    if not results:
        table.add_row("", "", Text("No queries were run.", style="td.muted"), "")
        return table
    for result in results:
        label, style = _QUERY_STATUS_STYLES[result.status]
        status = Text(label, style=style)
        name = safe_text(result.query_name)
        if not result.records:
            detail = result.error if result.status.failed and result.error else glyphs.empty
            table.add_row(result.record_type, name, safe_text(detail, "td.muted"), status)
            continue
        for index, record in enumerate(result.records):
            first = index == 0
            table.add_row(
                result.record_type if first else "",
                name if first else Text(""),
                _table_value(record),
                status if first else Text(""),
            )
    return table


def _table_value(record: str) -> Text:
    """Shorten very long values for the table; JSON always keeps the full value."""
    if len(record) <= MAX_TABLE_VALUE_LENGTH:
        return safe_text(record)
    text = safe_text(record[:MAX_TABLE_VALUE_LENGTH])
    text.append(
        f" ... (+{len(record) - MAX_TABLE_VALUE_LENGTH} chars, full value in JSON)",
        style="td.muted",
    )
    return text


def build_finding_panel(console: Console, finding: Finding) -> Panel:
    glyphs = glyphs_for(console)
    label, style = finding_label(finding)
    title = Text()
    title.append(f" {label} ", style=f"{style}.b")
    title.append(f" {finding.title} ", style="td.heading")

    parts: list[RenderableType] = [safe_text(finding.description, "td.text")]
    if finding.evidence:
        evidence = Table.grid(padding=(0, 1))
        evidence.add_column(style=style, no_wrap=True)
        evidence.add_column(style="td.text", overflow="fold")
        for line in finding.evidence:
            evidence.add_row(glyphs.arrow, safe_text(line))
        parts += [Text(), Text("Evidence", style="td.muted"), Padding(evidence, (0, 0, 0, 2))]
    if finding.status is not FindingStatus.PASS:
        parts += [
            Text(),
            Text("Recommendation", style="td.muted"),
            Padding(safe_text(finding.recommendation, "td.text"), (0, 0, 0, 2)),
        ]

    return Panel(
        Group(*parts),
        title=title,
        title_align="left",
        subtitle=Text(f" {finding.rule_id} {glyphs.dot} {finding.check} ", style="td.muted"),
        subtitle_align="right",
        box=box.ROUNDED,
        border_style=style,
        padding=(0, 1),
    )


def build_summary_panel(
    console: Console, report: ScanReport, json_path: Path | None = None
) -> Panel:
    glyphs = glyphs_for(console)
    summary = report.summary
    dot = f" {glyphs.dot} "
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="td.muted", no_wrap=True)
    # "fold" wraps long values such as a deep report path instead of truncating them.
    grid.add_column(style="td.text", overflow="fold")

    grid.add_row("Target", Text(report.target.domain, style="td.text.b"))
    grid.add_row(
        "Status",
        Text(report.scan.status.value, style=f"{_SCAN_STATUS_STYLES[report.scan.status]}.b"),
    )
    grid.add_row(
        "Queries",
        _counts(
            dot,
            [
                (summary.queries_attempted, "attempted", "td.text"),
                (summary.queries_completed, "completed", "td.success"),
                (summary.queries_failed, "failed", "td.error"),
            ],
        ),
    )
    grid.add_row(
        "Assessments",
        _counts(
            dot,
            [
                (summary.passed, "passed", "td.success"),
                (summary.findings_total, "findings", "td.warning"),
                (summary.errors, "errors", "td.error"),
                (summary.inconclusive, "inconclusive", "td.warning"),
                (summary.skipped, "skipped", "td.muted"),
            ],
        ),
    )
    grid.add_row(
        "Severity",
        _counts(
            dot,
            [
                (
                    summary.findings_by_severity[severity.value],
                    severity.value,
                    _SEVERITY_STYLES[severity],
                )
                for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
            ],
        ),
    )
    grid.add_row("Duration", f"{report.scan.duration_seconds:.2f}s")
    if json_path is not None:
        grid.add_row("Report", safe_text(str(json_path), "td.secondary"))
    return Panel(
        grid,
        title=Text(" Scan summary ", style="td.heading"),
        title_align="left",
        box=box.ROUNDED,
        border_style="td.primary",
        expand=False,
        padding=(0, 2),
    )


def _counts(separator: str, items: list[tuple[int, str, str]]) -> Text:
    text = Text()
    for index, (count, label, style) in enumerate(items):
        if index:
            text.append(separator, style="td.muted")
        text.append(str(count), style=f"{style}.b" if count else "td.muted")
        text.append(f" {label}", style="td.muted")
    return text


# ----------------------------------------------------------------------- JSON


class ReportWriteError(Exception):
    """Raised when a JSON report cannot be written."""


def report_to_json(report: ScanReport) -> str:
    """Serialize a report to JSON (ASCII-safe, stable field order)."""
    return json.dumps(to_jsonable(report), indent=2, ensure_ascii=True) + "\n"


def check_output_path(path: Path, overwrite: bool) -> None:
    """Validate a report destination before scanning, so failures surface early."""
    if path.is_dir():
        raise ReportWriteError(f"'{path}' is a directory.")
    if path.exists() and not overwrite:
        raise ReportWriteError(f"'{path}' already exists. Use --overwrite to replace it.")
    parent = path.parent if str(path.parent) else Path(".")
    if not parent.is_dir():
        raise ReportWriteError(f"Directory '{parent}' does not exist.")


def write_json_report(report: ScanReport, path: Path, overwrite: bool = False) -> Path:
    """Write the report atomically: a temporary file is written, then renamed.

    An interrupted or failed write never leaves a partial file at ``path``.
    """
    check_output_path(path, overwrite)
    payload = report_to_json(report)
    directory = path.parent if str(path.parent) else Path(".")
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=directory,
            prefix=".tracedns-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_name = handle.name
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        temp_name = None
    except OSError as exc:
        raise ReportWriteError(f"Could not write '{path}': {exc.strerror or exc}") from exc
    finally:
        if temp_name is not None:
            Path(temp_name).unlink(missing_ok=True)
    return path
