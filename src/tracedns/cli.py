"""Typer command-line interface for TraceDNS.

Exit codes:

* 0 - scan completed; no finding above INFO and no inconclusive check
* 1 - scan completed with at least one LOW/MEDIUM/HIGH finding or an
  inconclusive check
* 2 - invalid input (domain, selector, options, or report path)
* 3 - operational failure (a DNS query failed, so the scan is incomplete,
  or the report could not be written)
* 130 - interrupted with Ctrl+C
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from enum import IntEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

from tracedns import __version__
from tracedns.models import (
    SUPPORTED_CHECKS,
    SUPPORTED_RECORD_TYPES,
    FindingStatus,
    ScanReport,
    ScanStatus,
    Severity,
)
from tracedns.reporter import (
    ReportWriteError,
    StageReporter,
    check_output_path,
    glyphs_for,
    make_console,
    render_banner,
    render_brand_line,
    render_menu,
    render_report,
    render_scan_header,
    render_usage,
    report_to_json,
    write_json_report,
)
from tracedns.resolver import (
    DEFAULT_TIMEOUT_SECONDS,
    DNSResolver,
    InvalidNameError,
    normalize_domain,
    normalize_nameserver,
    normalize_selector,
)
from tracedns.scanner import ScanRequest, StageOutcome, run_scan

JSON_STDOUT = "-"
NO_CHECKS = "none"


class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1
    INVALID_INPUT = 2
    OPERATIONAL_FAILURE = 3
    INTERRUPTED = 130


class UsageError(Exception):
    """Invalid user input detected by TraceDNS (reported with exit code 2)."""


app = typer.Typer(
    name="tracedns",
    help="TraceDNS: DNS record analysis and email-security configuration assessment.",
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)


def build_resolver(timeout: float, nameservers: tuple[str, ...] = ()) -> DNSResolver:
    """Create the resolver used for scans. Tests replace this to avoid the network."""
    return DNSResolver(timeout=timeout, nameservers=nameservers)


def _tolerate_unencodable_output() -> None:
    """Replace characters the output encoding cannot represent instead of crashing.

    Relevant on Windows when output is redirected with a legacy code page and a
    DNS record contains characters outside it.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                continue


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"TraceDNS {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Inspect DNS records and assess SPF, DMARC, and DKIM configuration.

    Run without a command to open the welcome screen.
    """
    _tolerate_unencodable_output()
    if ctx.invoked_subcommand is None:
        raise typer.Exit(_welcome())


@app.command()
def welcome() -> None:
    """Show the welcome screen (and the interactive menu in a terminal)."""
    raise typer.Exit(_welcome())


@app.command()
def scan(
    domain: Annotated[str, typer.Argument(help="Domain to assess, e.g. example.com.")],
    record: Annotated[
        list[str] | None,
        typer.Option(
            "--record",
            "-r",
            metavar="TYPES",
            help="Record types to query: A, AAAA, MX, NS, TXT. Comma-separated or repeated. "
            "Default: all.",
        ),
    ] = None,
    checks: Annotated[
        list[str] | None,
        typer.Option(
            "--checks",
            "-c",
            metavar="CHECKS",
            help="Checks to run: spf, dmarc, dkim, or 'none'. Comma-separated or repeated. "
            "Default: spf, dmarc, dkim (DKIM is skipped without a selector).",
        ),
    ] = None,
    dkim_selector: Annotated[
        str | None,
        typer.Option(
            "--dkim-selector",
            "-s",
            metavar="SELECTOR",
            help="DKIM selector to look up (adds the dkim check).",
        ),
    ] = None,
    json_path: Annotated[
        str | None,
        typer.Option(
            "--json",
            "-j",
            metavar="PATH",
            help="Write a JSON report to PATH. Use '-' for JSON-only output on stdout.",
        ),
    ] = None,
    overwrite: Annotated[
        bool, typer.Option("--overwrite", help="Allow replacing an existing report file.")
    ] = False,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            "-t",
            min=0.5,
            max=60.0,
            help="Maximum seconds to wait for each DNS query.",
        ),
    ] = DEFAULT_TIMEOUT_SECONDS,
    nameserver: Annotated[
        list[str] | None,
        typer.Option(
            "--nameserver",
            "-n",
            metavar="IP",
            help="Resolver IP address to query instead of the system resolver. "
            "Comma-separated or repeated.",
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show tracebacks for unexpected errors.")
    ] = False,
) -> None:
    """Query DNS records and assess SPF, DMARC, and optional DKIM configuration."""
    err_console = make_console(stderr=True)
    json_stdout = json_path == JSON_STDOUT
    try:
        request = build_request(domain, record, checks, dkim_selector, timeout, nameserver)
        report_path = None if json_path in (None, JSON_STDOUT) else Path(json_path)
        if report_path is not None:
            check_output_path(report_path, overwrite)
    except (UsageError, InvalidNameError, ReportWriteError) as exc:
        _print_error(err_console, str(exc))
        raise typer.Exit(ExitCode.INVALID_INPUT) from None

    console = None if json_stdout else make_console()
    try:
        code = execute_scan(
            request,
            console=console,
            err_console=err_console,
            report_path=report_path,
            json_stdout=json_stdout,
            overwrite=overwrite,
        )
    except Exception as exc:  # last-resort guard: reported, never swallowed
        _print_error(err_console, f"Unexpected error: {type(exc).__name__}: {exc}")
        if verbose:
            err_console.print_exception()
        else:
            err_console.print(Text("Re-run with --verbose for details.", style="td.muted"))
        raise typer.Exit(ExitCode.OPERATIONAL_FAILURE) from None
    raise typer.Exit(code)


# ------------------------------------------------------------------ workflow


def build_request(
    domain: str,
    records: list[str] | None,
    checks: list[str] | None,
    dkim_selector: str | None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    nameservers: list[str] | None = None,
) -> ScanRequest:
    """Validate raw CLI values and build a :class:`ScanRequest`.

    Raises :class:`UsageError` or :class:`InvalidNameError` on invalid input.
    """
    normalized_domain = normalize_domain(domain)
    record_types = _parse_choices(records, SUPPORTED_RECORD_TYPES, str.upper, "record type")
    if checks and NO_CHECKS in _split(checks):
        if _split(checks) != [NO_CHECKS]:
            raise UsageError("'--checks none' cannot be combined with other checks.")
        selected_checks: tuple[str, ...] = ()
    else:
        selected_checks = _parse_choices(checks, SUPPORTED_CHECKS, str.lower, "check")

    selector = None
    if dkim_selector is not None:
        selector = normalize_selector(dkim_selector)
        if "dkim" not in selected_checks:
            selected_checks = tuple(c for c in SUPPORTED_CHECKS if c in {*selected_checks, "dkim"})

    resolvers: list[str] = []
    for value in nameservers or []:
        for item in value.split(","):
            if item.strip() and (address := normalize_nameserver(item)) not in resolvers:
                resolvers.append(address)
    return ScanRequest(
        normalized_domain, record_types, selected_checks, selector, timeout, tuple(resolvers)
    )


def _split(values: list[str]) -> list[str]:
    return [item.strip().lower() for value in values for item in value.split(",") if item.strip()]


def _parse_choices(
    values: list[str] | None,
    allowed: tuple[str, ...],
    normalize: Callable[[str], str],
    label: str,
) -> tuple[str, ...]:
    """Parse comma-separated/repeated values; return them in canonical order."""
    if not values:
        return allowed
    chosen = {
        normalize(item.strip()) for value in values for item in value.split(",") if item.strip()
    }
    unknown = sorted(chosen - set(allowed))
    if unknown:
        raise UsageError(
            f"Unknown {label}(s): {', '.join(unknown)}. Choose from: {', '.join(allowed)}."
        )
    if not chosen:
        raise UsageError(f"No {label} given.")
    return tuple(item for item in allowed if item in chosen)


def execute_scan(
    request: ScanRequest,
    *,
    console: Console | None,
    err_console: Console,
    report_path: Path | None = None,
    json_stdout: bool = False,
    overwrite: bool = False,
) -> int:
    """Run a scan, render it, optionally write JSON, and return the exit code.

    ``console`` is None in JSON-only mode, in which case nothing but the JSON
    document is written to stdout.
    """
    observer = None
    if console is not None:
        render_brand_line(console)
        render_scan_header(console, request)
        observer = StageReporter(console)
        observer.stage_finished("Validating target", StageOutcome.OK, request.domain)

    try:
        report = run_scan(request, build_resolver(request.timeout, request.nameservers), observer)
        written = None
        write_error = None
        if report_path is not None:
            try:
                written = write_json_report(report, report_path, overwrite)
            except ReportWriteError as exc:
                write_error = str(exc)
    except KeyboardInterrupt:
        if observer is not None:
            observer.close()
        _print_error(err_console, "Scan interrupted. No report was written.")
        return ExitCode.INTERRUPTED

    if json_stdout:
        sys.stdout.write(report_to_json(report))
        sys.stdout.flush()
    if console is not None:
        render_report(console, report, written)
    if write_error:
        _print_error(err_console, write_error)
        return ExitCode.OPERATIONAL_FAILURE
    return exit_code_for(report)


def exit_code_for(report: ScanReport) -> ExitCode:
    """Map a finished report to an exit code (see the module docstring)."""
    if report.scan.status is not ScanStatus.COMPLETED or report.summary.errors:
        return ExitCode.OPERATIONAL_FAILURE
    for finding in report.findings:
        if finding.status is FindingStatus.INCONCLUSIVE:
            return ExitCode.FINDINGS
        if finding.status is FindingStatus.FINDING and finding.severity is not Severity.INFO:
            return ExitCode.FINDINGS
    return ExitCode.OK


def _print_error(console: Console, message: str) -> None:
    glyphs = glyphs_for(console)
    line = Text()
    line.append(f"{glyphs.error} ", style="td.error.b")
    line.append(message, style="td.text")
    console.print(line)


# ------------------------------------------------------------- welcome menu


def _is_interactive() -> bool:
    return _is_console(sys.stdin) and _is_console(sys.stdout)


def _is_console(stream: object) -> bool:
    """True if ``stream`` is attached to a real terminal.

    On Windows, ``isatty()`` is also true for the NUL device, so the handle is
    additionally checked with ``GetConsoleMode``.
    """
    try:
        if not stream.isatty():  # type: ignore[attr-defined]
            return False
        if sys.platform != "win32":
            return True
        import ctypes
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())  # type: ignore[attr-defined]
        mode = ctypes.c_uint32()
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    except (AttributeError, OSError, ValueError):
        return False


def _welcome() -> int:
    console = make_console()
    render_banner(console)
    if not _is_interactive():
        return ExitCode.OK
    return run_menu(console, make_console(stderr=True))


def run_menu(console: Console, err_console: Console) -> int:
    """Interactive menu loop. Every scan goes through :func:`execute_scan`."""
    while True:
        render_menu(console)
        try:
            choice = Prompt.ask(
                Text("Select an option", style="td.primary"),
                choices=["1", "2", "3", "4"],
                console=console,
            )
            if choice == "4":
                console.print(Text("Goodbye.", style="td.muted"))
                return ExitCode.OK
            if choice == "3":
                render_usage(console)
                continue
            request = _prompt_request(console, err_console, with_checks=choice == "1")
        except (KeyboardInterrupt, EOFError):
            console.print()
            console.print(Text("Exiting TraceDNS.", style="td.muted"))
            return ExitCode.INTERRUPTED
        if request is not None:
            execute_scan(request, console=console, err_console=err_console)
            console.print()


def _prompt_request(
    console: Console, err_console: Console, with_checks: bool
) -> ScanRequest | None:
    """Ask for a domain (and optional selector). Blank domain returns to the menu.

    Each answer is validated as soon as it is entered and re-asked if invalid.
    """
    domain = _ask_valid(console, err_console, "Domain (blank to go back)", normalize_domain)
    if domain is None:
        return None
    selector = None
    if with_checks:
        selector = _ask_valid(
            console, err_console, "DKIM selector (blank to skip)", normalize_selector
        )
    return build_request(domain, None, None if with_checks else [NO_CHECKS], selector)


def _ask_valid(
    console: Console, err_console: Console, label: str, validate: Callable[[str], str]
) -> str | None:
    """Prompt until ``validate`` accepts the answer; blank input returns None."""
    while True:
        answer = Prompt.ask(
            Text(label, style="td.secondary"), console=console, default="", show_default=False
        )
        if not answer.strip():
            return None
        try:
            return validate(answer)
        except InvalidNameError as exc:
            _print_error(err_console, str(exc))


if __name__ == "__main__":  # pragma: no cover
    app()
