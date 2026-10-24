"""Selector-based DKIM key record lookup and basic checks.

The record at ``<selector>._domainkey.<domain>`` is checked for:

* presence (only when the query completed) and multiple TXT records;
* a ``v`` tag, if present, that is first and equal to ``DKIM1``;
* a ``p`` tag that is present, non-empty (empty means revoked), and valid
  base64;
* a ``k`` tag, if present, of ``rsa`` or ``ed25519``;
* the testing flag ``t=y``.

A key record shows only that a selector is published. It does not prove the
domain signs mail with it or that signatures verify. Selectors are never
guessed.
"""

from __future__ import annotations

import base64
import binascii

from tracedns.analyzers.common import (
    has_issue,
    index_tags,
    parse_tag_list,
    query_evidence,
)
from tracedns.models import DNSResult, Finding
from tracedns.rules import make_finding

DKIM_VERSION = "DKIM1"
KEY_TYPES = frozenset({"rsa", "ed25519"})


def analyze_dkim(
    result: DNSResult | None, domain: str, target_exists: bool = True
) -> list[Finding]:
    """Assess the DKIM key record for a selector.

    ``result`` is None when no selector was supplied; the check is skipped.
    """
    if result is None:
        return [make_finding("DKIM-800", domain)]
    name = result.query_name
    if not target_exists:
        return [make_finding("DKIM-901", name, [query_evidence(result)])]
    if result.status.failed:
        return [make_finding("DKIM-900", name, [query_evidence(result)])]
    if not result.records:
        return [make_finding("DKIM-001", name, [query_evidence(result)])]
    if len(result.records) > 1:
        return [make_finding("DKIM-006", name, [f"TXT record: {r}" for r in result.records])]
    return _analyze_record(name, result.records[0])


def _analyze_record(name: str, record: str) -> list[Finding]:
    evidence = f"DKIM record: {record}"
    pairs, malformed = parse_tag_list(record)
    tags, problems = index_tags(pairs)
    problems = [f"Malformed segment '{segment}'." for segment in malformed] + problems
    findings: list[Finding] = []

    if "v" in tags and (pairs[0][0] != "v" or tags["v"] != DKIM_VERSION):
        problems.append(f"'v={tags['v']}' must be the first tag and equal '{DKIM_VERSION}'.")
    if "k" in tags and tags["k"].lower() not in KEY_TYPES:
        problems.append(f"'k={tags['k']}' is not a recognized key type (rsa, ed25519).")

    key = tags.get("p")
    key_valid = False
    if key is None:
        findings.append(make_finding("DKIM-002", name, [evidence]))
    elif not "".join(key.split()):
        findings.append(make_finding("DKIM-004", name, [evidence]))
    elif _is_base64("".join(key.split())):
        key_valid = True
    else:
        problems.append("'p=' is not valid base64.")

    if problems:
        findings.append(make_finding("DKIM-003", name, [evidence, *problems]))
    flags = {flag.strip().lower() for flag in tags.get("t", "").split(":")}
    if "y" in flags:
        findings.append(make_finding("DKIM-005", name, [evidence]))

    if key_valid and not has_issue(findings):
        findings.insert(0, make_finding("DKIM-100", name, [evidence]))
    return findings


def _is_base64(value: str) -> bool:
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return True
