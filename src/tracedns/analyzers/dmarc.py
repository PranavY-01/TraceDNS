"""Basic DMARC analysis of the TXT records at ``_dmarc.<domain>``.

Implemented checks (and nothing more):

* missing record (only when the query completed) and multiple candidate
  records (records beginning with ``v=DMARC``, case-insensitive);
* the version tag must be exactly ``v=DMARC1``;
* ``p`` must be present and one of ``none``, ``quarantine``, ``reject``;
* malformed segments, duplicate tags, and invalid ``sp``, ``pct``,
  ``adkim`` and ``aspf`` values;
* observations: ``p=none``, ``pct`` below 100, no ``rua``, and ``sp=none``
  under an enforcing ``p``.

Tags are parsed without assuming any order after the version tag.
Not implemented: organizational-domain fallback, report URI validation,
external-destination verification, or alignment testing of real mail.
"""

from __future__ import annotations

import re

from tracedns.analyzers.common import (
    absence_evidence,
    has_issue,
    index_tags,
    parse_tag_list,
    query_evidence,
)
from tracedns.models import DNSResult, Finding
from tracedns.rules import make_finding

DMARC_VERSION = "DMARC1"
POLICIES = frozenset({"none", "quarantine", "reject"})
ALIGNMENT_MODES = frozenset({"r", "s"})
# RFC 7489's grammar allows whitespace around "=" in the version tag.
_CANDIDATE = re.compile(r"^\s*v\s*=\s*dmarc", re.IGNORECASE)


def is_dmarc_candidate(text: str) -> bool:
    """True if ``text`` looks like an attempt at a DMARC record."""
    return _CANDIDATE.match(text) is not None


def analyze_dmarc(result: DNSResult, target_exists: bool = True) -> list[Finding]:
    """Assess the DMARC configuration in the ``_dmarc`` TXT query result.

    ``target_exists`` is False when another query showed that the scanned
    domain itself does not exist; the check is then inconclusive.
    """
    name = result.query_name
    if not target_exists:
        return [make_finding("DMARC-901", name, [query_evidence(result)])]
    if result.status.failed:
        return [make_finding("DMARC-900", name, [query_evidence(result)])]

    candidates = [record for record in result.records if is_dmarc_candidate(record)]
    if not candidates:
        return [make_finding("DMARC-001", name, [absence_evidence(result, "v=DMARC1")])]
    if len(candidates) > 1:
        return [make_finding("DMARC-002", name, [f"DMARC record: {r}" for r in candidates])]
    return _analyze_record(name, candidates[0])


def _analyze_record(name: str, record: str) -> list[Finding]:
    evidence = f"DMARC record: {record}"
    pairs, malformed = parse_tag_list(record)

    version = pairs[0] if pairs else None
    if version is None or version[0] != "v" or version[1] != DMARC_VERSION:
        observed = f"'{version[0]}={version[1]}'" if version else "none"
        return [make_finding("DMARC-003", name, [evidence, f"Version tag observed: {observed}"])]

    tags, problems = index_tags(pairs)
    problems = [f"Malformed segment '{segment}'." for segment in malformed] + problems
    findings: list[Finding] = []

    policy = tags.get("p")
    if policy is None:
        findings.append(make_finding("DMARC-004", name, [evidence]))
    elif policy.lower() not in POLICIES:
        findings.append(make_finding("DMARC-005", name, [evidence, f"Observed: p={policy}"]))
    policy_value = policy.lower() if policy and policy.lower() in POLICIES else None

    subdomain_policy = tags.get("sp")
    if subdomain_policy is not None and subdomain_policy.lower() not in POLICIES:
        problems.append(f"'sp={subdomain_policy}' is not none, quarantine, or reject.")
    for tag in ("adkim", "aspf"):
        if tag in tags and tags[tag].lower() not in ALIGNMENT_MODES:
            problems.append(f"'{tag}={tags[tag]}' must be 'r' or 's'.")
    pct = _parse_pct(tags.get("pct"), problems)

    if problems:
        findings.append(make_finding("DMARC-006", name, [evidence, *problems]))

    enforcing = policy_value in ("quarantine", "reject")
    if policy_value == "none":
        findings.append(make_finding("DMARC-007", name, [evidence]))
    if enforcing and pct is not None and pct < 100:
        findings.append(make_finding("DMARC-008", name, [evidence, f"Observed: pct={pct}"]))
    if enforcing and subdomain_policy is not None and subdomain_policy.lower() == "none":
        findings.append(make_finding("DMARC-010", name, [evidence]))
    if not tags.get("rua"):
        findings.append(make_finding("DMARC-009", name, [evidence]))

    if policy_value and not has_issue(findings):
        findings.insert(0, make_finding("DMARC-100", name, [evidence]))
    return findings


def _parse_pct(raw: str | None, problems: list[str]) -> int | None:
    if raw is None:
        return None
    if not raw.isdigit() or int(raw) > 100:
        problems.append(f"'pct={raw}' must be an integer from 0 to 100.")
        return None
    return int(raw)
