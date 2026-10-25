"""Result, finding, and report models shared by every TraceDNS layer.

Two status vocabularies are kept deliberately separate:

* :class:`QueryStatus` describes what happened to a single DNS query.
* :class:`FindingStatus` describes the outcome of a security assessment.

A query that times out is an operational failure; it is never turned into a
security finding with a severity.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, StrEnum
from typing import Any

# 1.1 adds scan.nameservers. See schema/report-1.1.json.
SCHEMA_VERSION = "1.1"

SUPPORTED_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT")
SUPPORTED_CHECKS: tuple[str, ...] = ("spf", "dmarc", "dkim")


class QueryStatus(StrEnum):
    """Outcome of one DNS query."""

    SUCCESS = "success"  # NOERROR with at least one record of the requested type
    NOT_FOUND = "not_found"  # NOERROR, but no records of the requested type
    NXDOMAIN = "nxdomain"  # the queried name does not exist
    TIMEOUT = "timeout"  # no response within the configured lifetime
    SERVFAIL = "servfail"  # resolver reported a server failure
    REFUSED = "refused"  # resolver refused the query
    ERROR = "error"  # any other operational failure

    @property
    def completed(self) -> bool:
        """True when DNS gave a definitive answer (records, no records, or no name)."""
        return self in (QueryStatus.SUCCESS, QueryStatus.NOT_FOUND, QueryStatus.NXDOMAIN)

    @property
    def failed(self) -> bool:
        """True when the query did not produce a definitive answer."""
        return not self.completed


class FindingStatus(StrEnum):
    """Outcome of one security assessment."""

    PASS = "pass"  # the basic checks for this area found no issue
    FINDING = "finding"  # a configuration issue or observation, with a severity
    ERROR = "error"  # the check could not run because a DNS query failed
    INCONCLUSIVE = "inconclusive"  # not enough evidence to assess
    SKIPPED = "skipped"  # the check was requested but lacked required input


class Severity(StrEnum):
    """Severity of a FINDING. Other statuses carry no severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)


class ScanStatus(StrEnum):
    """Overall outcome of a scan."""

    COMPLETED = "completed"  # every attempted query produced a definitive answer
    PARTIAL = "partial"  # at least one query failed and at least one completed
    FAILED = "failed"  # every attempted query failed


@dataclass(frozen=True)
class DNSResult:
    """The normalized result of one DNS query."""

    query_name: str
    record_type: str
    status: QueryStatus
    records: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class Finding:
    """One assessment result produced by an analyzer."""

    id: str
    category: str
    check: str
    status: FindingStatus
    severity: Severity | None
    title: str
    description: str
    evidence: list[str]
    recommendation: str
    rule_id: str


@dataclass(frozen=True)
class ToolInfo:
    name: str
    version: str


@dataclass(frozen=True)
class Target:
    domain: str


@dataclass(frozen=True)
class ScanMeta:
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    status: ScanStatus
    record_types: list[str]
    checks: list[str]
    dkim_selector: str | None
    timeout_seconds: float
    nameservers: list[str]  # empty means the system resolver configuration


@dataclass(frozen=True)
class Summary:
    """Counts derived from a report.

    * ``queries_*`` count DNS queries in ``dns_results``.
    * ``assessments_total`` counts every entry in ``findings``.
    * ``findings_total`` and ``findings_by_severity`` count only entries whose
      status is ``finding``.
    * ``passed``, ``errors``, ``inconclusive`` and ``skipped`` count entries in
      ``findings`` with the matching status.
    """

    queries_attempted: int
    queries_completed: int
    queries_failed: int
    assessments_total: int
    passed: int
    findings_total: int
    findings_by_severity: dict[str, int]
    errors: int
    inconclusive: int
    skipped: int


@dataclass(frozen=True)
class ScanReport:
    schema_version: str
    tool: ToolInfo
    target: Target
    scan: ScanMeta
    dns_results: list[DNSResult]
    findings: list[Finding]
    summary: Summary


def build_summary(dns_results: list[DNSResult], findings: list[Finding]) -> Summary:
    """Compute summary counts. Each query and each finding is counted once."""
    by_severity = {severity.value: 0 for severity in reversed(_SEVERITY_ORDER)}
    for finding in findings:
        if finding.status is FindingStatus.FINDING and finding.severity is not None:
            by_severity[finding.severity.value] += 1

    def count(status: FindingStatus) -> int:
        return sum(1 for finding in findings if finding.status is status)

    completed = sum(1 for result in dns_results if result.status.completed)
    return Summary(
        queries_attempted=len(dns_results),
        queries_completed=completed,
        queries_failed=len(dns_results) - completed,
        assessments_total=len(findings),
        passed=count(FindingStatus.PASS),
        findings_total=count(FindingStatus.FINDING),
        findings_by_severity=by_severity,
        errors=count(FindingStatus.ERROR),
        inconclusive=count(FindingStatus.INCONCLUSIVE),
        skipped=count(FindingStatus.SKIPPED),
    )


def scan_status_for(dns_results: list[DNSResult]) -> ScanStatus:
    """Derive the overall scan status from query outcomes."""
    failed = sum(1 for result in dns_results if result.status.failed)
    if failed == 0:
        return ScanStatus.COMPLETED
    if failed == len(dns_results):
        return ScanStatus.FAILED
    return ScanStatus.PARTIAL


def to_jsonable(value: Any) -> Any:
    """Convert models (dataclasses, enums, datetimes) into JSON-compatible values."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [to_jsonable(item) for item in value]
    return value
