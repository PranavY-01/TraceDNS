"""Basic SPF analysis of a domain's TXT records.

Implemented checks (and nothing more):

* identify records beginning with ``v=spf1`` (case-insensitive);
* missing record (only when the TXT query completed) and multiple records;
* basic term syntax: known mechanism names, qualifiers, required or
  forbidden arguments, ip4/ip6 networks, CIDR lengths, duplicate
  ``redirect``/``exp`` modifiers;
* the qualifier on ``all`` (``+``, ``?``, ``~``, ``-``), a missing ``all`` and
  ``redirect``, terms placed after ``all``, and use of ``ptr``.

Not implemented: following ``include``/``redirect``, the 10-lookup limit,
macro expansion, or evaluating whether a given host is authorized.
"""

from __future__ import annotations

import ipaddress
import re

from tracedns.analyzers.common import absence_evidence, has_issue, query_evidence
from tracedns.models import DNSResult, Finding, QueryStatus
from tracedns.rules import make_finding

SPF_VERSION = "v=spf1"
MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})

_DIRECTIVE = re.compile(r"^(?P<qualifier>[+\-~?]?)(?P<name>[A-Za-z0-9]+)(?P<rest>.*)$")
_MODIFIER = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9_.\-]*)=(?P<value>.*)$")
_DUAL_CIDR = re.compile(r"^(?::(?P<domain>[^/]+))?(?:/(?P<v4>\d+))?(?://(?P<v6>\d+))?$")
_UNIQUE_MODIFIERS = frozenset({"redirect", "exp"})


def is_spf_record(text: str) -> bool:
    """True if ``text`` begins with the SPF version marker as a whole term."""
    lowered = text.lower()
    return lowered == SPF_VERSION or lowered.startswith(SPF_VERSION + " ")


def analyze_spf(result: DNSResult) -> list[Finding]:
    """Assess the SPF configuration found in a domain's TXT query result."""
    domain = result.query_name
    if result.status is QueryStatus.NXDOMAIN:
        return [make_finding("SPF-901", domain, [query_evidence(result)])]
    if result.status.failed:
        return [make_finding("SPF-900", domain, [query_evidence(result)])]

    records = [record for record in result.records if is_spf_record(record)]
    if not records:
        return [make_finding("SPF-001", domain, [absence_evidence(result, SPF_VERSION)])]
    if len(records) > 1:
        return [make_finding("SPF-002", domain, [f"SPF record: {r}" for r in records])]
    return _analyze_record(domain, records[0])


def _analyze_record(domain: str, record: str) -> list[Finding]:
    evidence = f"SPF record: {record}"
    terms = record.split()[1:]
    findings: list[Finding] = []

    invalid: list[str] = []
    seen_modifiers: set[str] = set()
    all_index: int | None = None
    all_qualifier = ""
    redirect_term: str | None = None
    ptr_terms: list[str] = []
    after_all: list[str] = []

    for index, term in enumerate(terms):
        problem = _term_problem(term, seen_modifiers)
        if problem:
            invalid.append(f"'{term}': {problem}")
            continue
        modifier = _MODIFIER.match(term)
        if modifier:
            if modifier["name"].lower() == "redirect":
                redirect_term = term
            continue
        directive = _DIRECTIVE.match(term)
        assert directive is not None  # guaranteed by _term_problem
        name = directive["name"].lower()
        if all_index is not None:
            after_all.append(term)
        if name == "all" and all_index is None:
            all_index = index
            all_qualifier = directive["qualifier"]
        elif name == "ptr":
            ptr_terms.append(term)

    if invalid:
        findings.append(make_finding("SPF-003", domain, [evidence, *invalid]))

    if all_index is not None:
        rule = {"": "SPF-004", "+": "SPF-004", "?": "SPF-005", "~": "SPF-006"}.get(all_qualifier)
        if rule:
            findings.append(make_finding(rule, domain, [evidence]))
        ignored = list(after_all)
        if redirect_term:
            ignored.append(redirect_term)
        if ignored:
            findings.append(
                make_finding("SPF-008", domain, [evidence, *(f"Ignored: {t}" for t in ignored)])
            )
    elif redirect_term is None:
        findings.append(make_finding("SPF-007", domain, [evidence]))

    if ptr_terms:
        findings.append(make_finding("SPF-009", domain, [evidence, *ptr_terms]))

    if not has_issue(findings):
        findings.insert(0, make_finding("SPF-100", domain, [evidence]))
    return findings


def _term_problem(term: str, seen_modifiers: set[str]) -> str | None:
    """Return a reason if ``term`` fails basic SPF syntax, otherwise None."""
    modifier = _MODIFIER.match(term)
    if modifier:
        name = modifier["name"].lower()
        if name in _UNIQUE_MODIFIERS:
            if name in seen_modifiers:
                return f"'{name}' modifier appears more than once"
            seen_modifiers.add(name)
            if not modifier["value"]:
                return f"'{name}' modifier requires a domain"
        return None

    directive = _DIRECTIVE.match(term)
    if not directive:
        return "not a valid mechanism or modifier"
    name = directive["name"].lower()
    rest = directive["rest"]
    if name not in MECHANISMS:
        return f"unknown mechanism '{directive['name']}'"
    if name == "all":
        return "'all' takes no argument" if rest else None
    if name in ("include", "exists"):
        return None if rest.startswith(":") and len(rest) > 1 else f"'{name}' requires ':domain'"
    if name == "ptr":
        return None if rest == "" or (rest.startswith(":") and len(rest) > 1) else "bad argument"
    if name in ("a", "mx"):
        return _dual_cidr_problem(rest)
    return _ip_problem(name, rest)


def _dual_cidr_problem(rest: str) -> str | None:
    match = _DUAL_CIDR.match(rest)
    if not match:
        return "expected optional ':domain', '/cidr4' and '//cidr6'"
    if match["v4"] is not None and int(match["v4"]) > 32:
        return "IPv4 prefix length must be 0-32"
    if match["v6"] is not None and int(match["v6"]) > 128:
        return "IPv6 prefix length must be 0-128"
    return None


def _ip_problem(name: str, rest: str) -> str | None:
    if not rest.startswith(":") or len(rest) == 1:
        return f"'{name}' requires ':address' or ':network/prefix'"
    address, _, prefix = rest[1:].partition("/")
    version = 4 if name == "ip4" else 6
    limit = 32 if version == 4 else 128
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return f"'{address}' is not a valid IPv{version} address"
    if parsed.version != version:
        return f"'{address}' is not a valid IPv{version} address"
    if prefix and (not prefix.isdigit() or int(prefix) > limit):
        return f"prefix length must be 0-{limit}"
    if "/" in rest[1:] and not prefix:
        return "missing prefix length after '/'"
    return None
