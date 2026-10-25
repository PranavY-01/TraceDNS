"""Basic DMARC analysis of the TXT records at ``_dmarc.<domain>``.

Checks follow RFC 9989 (DMARC, May 2026), which obsoletes RFC 7489.
Implemented checks (and nothing more):

* missing record (only when the query completed) and multiple candidate
  records (records beginning with ``v=DMARC``, case-insensitive);
* the version tag must be exactly ``v=DMARC1``;
* ``p`` should be present; ``p``, ``sp`` and ``np`` must be one of ``none``,
  ``quarantine``, ``reject``;
* malformed segments, duplicate tags, and invalid ``adkim``, ``aspf``,
  ``t``, ``psd`` and ``fo`` values, and ``rua``/``ruf`` entries that are not
  URIs (or ``mailto:`` URIs without an address);
* observations: ``p=none``, no ``rua``, ``sp=none`` or ``np=none`` under an
  enforcing ``p``, test mode (``t=y``), and the tags RFC 9989 removed
  (``pct``, ``rf``, ``ri``).

Tags are parsed without assuming any order after the version tag.
Not implemented: the RFC 9989 DNS tree walk to the organizational domain,
external report-destination verification, or alignment testing of real mail.
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
POLICY_TAGS = ("p", "sp", "np")
LEGACY_TAGS = ("pct", "rf", "ri")  # removed by RFC 9989
ALIGNMENT_MODES = frozenset({"r", "s"})
TEST_MODES = frozenset({"y", "n"})
PSD_VALUES = frozenset({"y", "n", "u"})
FAILURE_OPTIONS = frozenset({"0", "1", "d", "s"})
REPORT_TAGS = ("rua", "ruf")

# DMARC's record grammar allows whitespace around "=" in the version tag.
_CANDIDATE = re.compile(r"^\s*v\s*=\s*dmarc", re.IGNORECASE)
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:\S+$")


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

    if "p" not in tags:
        findings.append(make_finding("DMARC-004", name, [evidence]))
    invalid_policies = [
        f"Observed: {tag}={tags[tag]}"
        for tag in POLICY_TAGS
        if tag in tags and tags[tag].lower() not in POLICIES
    ]
    if invalid_policies:
        findings.append(make_finding("DMARC-005", name, [evidence, *invalid_policies]))

    problems += _choice_problems(tags, "adkim", ALIGNMENT_MODES)
    problems += _choice_problems(tags, "aspf", ALIGNMENT_MODES)
    problems += _choice_problems(tags, "t", TEST_MODES)
    problems += _choice_problems(tags, "psd", PSD_VALUES)
    problems += _failure_option_problems(tags.get("fo"))
    for tag in REPORT_TAGS:
        problems += _uri_problems(tag, tags.get(tag, ""))
    if problems:
        findings.append(make_finding("DMARC-006", name, [evidence, *problems]))

    policy = _valid_policy(tags, "p")
    enforcing = policy in ("quarantine", "reject")
    if policy == "none":
        findings.append(make_finding("DMARC-007", name, [evidence]))
    if enforcing and _valid_policy(tags, "sp") == "none":
        findings.append(make_finding("DMARC-010", name, [evidence]))
    if enforcing and _valid_policy(tags, "np") == "none":
        findings.append(make_finding("DMARC-013", name, [evidence]))
    if enforcing and tags.get("t", "").lower() == "y":
        findings.append(make_finding("DMARC-012", name, [evidence]))
    legacy = [f"Observed: {tag}={tags[tag]}" for tag in LEGACY_TAGS if tag in tags]
    if legacy:
        findings.append(make_finding("DMARC-011", name, [evidence, *legacy]))
    if not tags.get("rua"):
        findings.append(make_finding("DMARC-009", name, [evidence]))

    if policy and not has_issue(findings):
        findings.insert(0, make_finding("DMARC-100", name, [evidence]))
    return findings


def _valid_policy(tags: dict[str, str], tag: str) -> str | None:
    """Return the lower-cased policy value of ``tag`` if present and valid."""
    value = tags.get(tag, "").lower()
    return value if value in POLICIES else None


def _choice_problems(tags: dict[str, str], tag: str, allowed: frozenset[str]) -> list[str]:
    if tag not in tags or tags[tag].lower() in allowed:
        return []
    choices = ", ".join(f"'{value}'" for value in sorted(allowed))
    return [f"'{tag}={tags[tag]}' must be one of {choices}."]


def _failure_option_problems(raw: str | None) -> list[str]:
    if raw is None:
        return []
    options = [option.strip().lower() for option in raw.split(":")]
    if all(option in FAILURE_OPTIONS for option in options):
        return []
    return [f"'fo={raw}' must be '0', '1', 'd' or 's' (colon-separated)."]


def _uri_problems(tag: str, raw: str) -> list[str]:
    """Check that each comma-separated reporting entry is a URI."""
    if not raw:
        return []
    problems = []
    for entry in (item.strip() for item in raw.split(",")):
        uri = entry.split("!", 1)[0]  # RFC 7489 allowed a "!size" suffix
        if not _URI.match(uri):
            problems.append(
                f"'{tag}' entry '{entry}' is not a URI (for example 'mailto:reports@example.com')."
            )
        elif uri.lower().startswith("mailto:") and "@" not in uri:
            problems.append(f"'{tag}' entry '{entry}' is not a valid mailto: address.")
    return problems
