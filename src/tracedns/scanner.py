"""Scan orchestration: run queries, apply analyzers, and build the report.

This module holds the workflow shared by the ``scan`` command and the
interactive menu. It reports progress through a :class:`ScanObserver` so
that it never prints anything itself.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from tracedns import TOOL_NAME, __version__
from tracedns.analyzers import analyze_dkim, analyze_dmarc, analyze_spf
from tracedns.models import (
    SCHEMA_VERSION,
    DNSResult,
    Finding,
    FindingStatus,
    QueryStatus,
    ScanMeta,
    ScanReport,
    Severity,
    Target,
    ToolInfo,
    build_summary,
    scan_status_for,
)
from tracedns.resolver import DNSResolver, dkim_query_name, dmarc_query_name


class StageOutcome(StrEnum):
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


class ScanObserver(Protocol):
    """Receives progress events for the stages a scan actually runs."""

    def stage_started(self, stage: str) -> None: ...

    def stage_finished(self, stage: str, outcome: StageOutcome, detail: str) -> None: ...


class _NullObserver:
    def stage_started(self, stage: str) -> None:
        pass

    def stage_finished(self, stage: str, outcome: StageOutcome, detail: str) -> None:
        pass


@dataclass(frozen=True)
class ScanRequest:
    """A validated scan request. ``domain``, ``dkim_selector`` and ``nameservers`` are normalized.

    An empty ``nameservers`` tuple means the system resolver configuration.
    """

    domain: str
    record_types: tuple[str, ...]
    checks: tuple[str, ...]
    dkim_selector: str | None
    timeout: float
    nameservers: tuple[str, ...] = ()


class _QueryCache:
    """Runs each (name, type) query once and remembers results in query order."""

    def __init__(self, resolver: DNSResolver) -> None:
        self._resolver = resolver
        self._results: dict[tuple[str, str], DNSResult] = {}

    def get(self, name: str, record_type: str) -> DNSResult:
        key = (name, record_type)
        if key not in self._results:
            self._results[key] = self._resolver.query(name, record_type)
        return self._results[key]

    @property
    def results(self) -> list[DNSResult]:
        return list(self._results.values())


def run_scan(
    request: ScanRequest,
    resolver: DNSResolver,
    observer: ScanObserver | None = None,
) -> ScanReport:
    """Execute the requested queries and checks and return the report."""
    observer = observer or _NullObserver()
    started_at = datetime.now(UTC)
    start = time.perf_counter()
    cache = _QueryCache(resolver)
    findings: list[Finding] = []
    domain = request.domain

    stage = "Querying DNS records"
    observer.stage_started(stage)
    record_results = [cache.get(domain, record_type) for record_type in request.record_types]
    observer.stage_finished(stage, *_query_outcome(record_results))

    if "spf" in request.checks:
        stage = "Analyzing SPF"
        observer.stage_started(stage)
        spf_findings = analyze_spf(cache.get(domain, "TXT"))
        findings.extend(spf_findings)
        observer.stage_finished(stage, *_findings_outcome(spf_findings))

    target_exists = not any(
        result.query_name == domain and result.status is QueryStatus.NXDOMAIN
        for result in cache.results
    )

    if "dmarc" in request.checks:
        stage = "Analyzing DMARC"
        observer.stage_started(stage)
        dmarc_findings = analyze_dmarc(cache.get(dmarc_query_name(domain), "TXT"), target_exists)
        findings.extend(dmarc_findings)
        observer.stage_finished(stage, *_findings_outcome(dmarc_findings))

    if "dkim" in request.checks:
        stage = "DKIM selector lookup"
        observer.stage_started(stage)
        dkim_result = None
        if request.dkim_selector:
            dkim_result = cache.get(dkim_query_name(request.dkim_selector, domain), "TXT")
        dkim_findings = analyze_dkim(dkim_result, domain, target_exists)
        findings.extend(dkim_findings)
        observer.stage_finished(stage, *_findings_outcome(dkim_findings))

    stage = "Building report"
    observer.stage_started(stage)
    dns_results = cache.results
    report = ScanReport(
        schema_version=SCHEMA_VERSION,
        tool=ToolInfo(name=TOOL_NAME, version=__version__),
        target=Target(domain=domain),
        scan=ScanMeta(
            started_at=started_at,
            finished_at=datetime.now(UTC),
            duration_seconds=round(time.perf_counter() - start, 3),
            status=scan_status_for(dns_results),
            record_types=list(request.record_types),
            checks=list(request.checks),
            dkim_selector=request.dkim_selector,
            timeout_seconds=request.timeout,
            nameservers=list(request.nameservers),
        ),
        dns_results=dns_results,
        findings=findings,
        summary=build_summary(dns_results, findings),
    )
    observer.stage_finished(stage, StageOutcome.OK, f"{len(findings)} assessment result(s)")
    return report


def _query_outcome(results: list[DNSResult]) -> tuple[StageOutcome, str]:
    failed = sum(1 for result in results if result.status.failed)
    answered = sum(1 for result in results if result.status is QueryStatus.SUCCESS)
    detail = f"{len(results)} queries, {answered} with records"
    if failed:
        detail += f", {failed} failed"
    if failed == len(results):
        return StageOutcome.ERROR, detail
    return (StageOutcome.WARNING if failed else StageOutcome.OK), detail


def _findings_outcome(findings: list[Finding]) -> tuple[StageOutcome, str]:
    statuses = {finding.status for finding in findings}
    if FindingStatus.ERROR in statuses:
        return StageOutcome.ERROR, "query failed"
    if FindingStatus.SKIPPED in statuses:
        return StageOutcome.SKIPPED, "no selector supplied"
    if FindingStatus.INCONCLUSIVE in statuses:
        return StageOutcome.WARNING, "inconclusive"
    issues = [
        f for f in findings if f.status is FindingStatus.FINDING and f.severity is not Severity.INFO
    ]
    observations = sum(1 for f in findings if f.status is FindingStatus.FINDING) - len(issues)
    if issues:
        return StageOutcome.WARNING, f"{len(issues)} issue(s), {observations} observation(s)"
    if observations:
        return StageOutcome.OK, f"passed with {observations} observation(s)"
    return StageOutcome.OK, "passed"
