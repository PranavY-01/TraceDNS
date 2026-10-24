"""Helpers shared by the analyzers."""

from __future__ import annotations

import re

from tracedns.models import DNSResult, Finding, FindingStatus, QueryStatus, Severity

_TAG_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def parse_tag_list(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Split a ``name=value; name=value`` record into tags.

    Returns ``(tags, malformed)`` where ``tags`` keeps the original order with
    lower-cased names and stripped values, and ``malformed`` lists segments
    that are not ``name=value`` pairs. Empty segments (such as a trailing
    semicolon) are ignored.
    """
    tags: list[tuple[str, str]] = []
    malformed: list[str] = []
    for segment in text.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        name, separator, value = segment.partition("=")
        name = name.strip()
        if not separator or not _TAG_NAME.match(name):
            malformed.append(segment)
            continue
        tags.append((name.lower(), value.strip()))
    return tags, malformed


def index_tags(tags: list[tuple[str, str]]) -> tuple[dict[str, str], list[str]]:
    """Map tag names to values, reporting duplicates (the first value wins)."""
    indexed: dict[str, str] = {}
    problems: list[str] = []
    for name, value in tags:
        if name in indexed:
            problems.append(f"Duplicate tag '{name}'.")
            continue
        indexed[name] = value
    return indexed, problems


def query_evidence(result: DNSResult) -> str:
    """Describe a query outcome in one line of evidence."""
    line = f"{result.record_type} {result.query_name}: {result.status.value}"
    if result.error:
        line += f" ({result.error})"
    return line


def absence_evidence(result: DNSResult, marker: str) -> str:
    """Explain why no matching record was found in a completed query."""
    if result.status is QueryStatus.NXDOMAIN:
        return f"{result.query_name} does not exist (NXDOMAIN)."
    if not result.records:
        return f"{result.query_name} has no TXT records."
    return (
        f"{result.query_name} has {len(result.records)} TXT record(s); none begin with '{marker}'."
    )


def has_issue(findings: list[Finding]) -> bool:
    """True if any finding is above INFO severity."""
    return any(
        finding.status is FindingStatus.FINDING
        and finding.severity is not None
        and finding.severity is not Severity.INFO
        for finding in findings
    )
