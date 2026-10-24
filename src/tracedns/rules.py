"""Central catalog of assessment rules.

Every finding is created through :func:`make_finding`, which takes its
status, severity, title, and recommendation from :data:`RULES`. Analyzers
supply only the subject, evidence, and optional extra detail, so wording and
severity stay consistent and the UI never decides severity on its own.
"""

from __future__ import annotations

from dataclasses import dataclass

from tracedns.models import Finding, FindingStatus, Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    check: str
    status: FindingStatus
    severity: Severity | None
    title: str
    description: str
    recommendation: str


_EMAIL = "email-authentication"


def _rule(
    rule_id: str,
    check: str,
    status: FindingStatus,
    severity: Severity | None,
    title: str,
    description: str,
    recommendation: str,
) -> Rule:
    if (status is FindingStatus.FINDING) != (severity is not None):
        raise ValueError(f"{rule_id}: only FINDING rules carry a severity")
    return Rule(rule_id, _EMAIL, check, status, severity, title, description, recommendation)


_F = FindingStatus
_S = Severity

_RULE_LIST: tuple[Rule, ...] = (
    # ---------------------------------------------------------------- SPF
    _rule(
        "SPF-001",
        "spf",
        _F.FINDING,
        _S.MEDIUM,
        "No SPF record published",
        "The TXT query for the domain succeeded, but no record begins with 'v=spf1'. "
        "Receivers have no SPF policy describing which hosts may send mail for this domain.",
        "Publish a single TXT record beginning with 'v=spf1' that lists your legitimate "
        "sending sources and ends with '-all' or '~all'. If the domain sends no mail, "
        "publish 'v=spf1 -all'.",
    ),
    _rule(
        "SPF-002",
        "spf",
        _F.FINDING,
        _S.MEDIUM,
        "Multiple SPF records published",
        "More than one TXT record begins with 'v=spf1'. RFC 7208 section 4.5 requires "
        "receivers to return a 'permerror' result in this case, so SPF evaluation fails "
        "for every message.",
        "Merge the mechanisms into one SPF record and delete the others.",
    ),
    _rule(
        "SPF-003",
        "spf",
        _F.FINDING,
        _S.MEDIUM,
        "SPF record contains invalid terms",
        "One or more terms do not match the basic SPF term syntax checked by TraceDNS. "
        "Receivers may return 'permerror' for a record they cannot parse.",
        "Correct or remove the listed terms. Check mechanism names, qualifiers, and the "
        "format of ip4/ip6 networks.",
    ),
    _rule(
        "SPF-004",
        "spf",
        _F.FINDING,
        _S.HIGH,
        "SPF policy permits all senders",
        "The record ends with '+all' (or a bare 'all', which defaults to '+'). This states "
        "that every host on the internet is an authorized sender, so SPF provides no "
        "protection for this domain.",
        "Replace '+all' with '-all' (fail) or '~all' (softfail) after listing your "
        "legitimate sending sources.",
    ),
    _rule(
        "SPF-005",
        "spf",
        _F.FINDING,
        _S.LOW,
        "SPF policy ends with neutral '?all'",
        "'?all' asks receivers to treat unlisted senders as neutral, which makes no "
        "assertion about them.",
        "Once your sending sources are listed, consider '~all' or '-all'.",
    ),
    _rule(
        "SPF-006",
        "spf",
        _F.FINDING,
        _S.INFO,
        "SPF policy ends with softfail '~all'",
        "'~all' asks receivers to treat unlisted senders as suspicious but not to reject "
        "them outright. This is a common deliberate choice, often paired with DMARC.",
        "No change is required. Consider '-all' if you are confident every sending source "
        "is listed.",
    ),
    _rule(
        "SPF-007",
        "spf",
        _F.FINDING,
        _S.LOW,
        "SPF record has no 'all' mechanism or redirect",
        "Without a terminating 'all' mechanism or a 'redirect' modifier, unmatched senders "
        "receive the default 'neutral' result.",
        "End the record with '-all' or '~all', or use 'redirect=' to delegate to another "
        "SPF policy.",
    ),
    _rule(
        "SPF-008",
        "spf",
        _F.FINDING,
        _S.INFO,
        "SPF terms after 'all' are ignored",
        "Mechanisms placed after 'all' are never evaluated, and a 'redirect' modifier is "
        "ignored when 'all' is present.",
        "Move the listed terms before 'all' or remove them.",
    ),
    _rule(
        "SPF-009",
        "spf",
        _F.FINDING,
        _S.LOW,
        "SPF record uses the 'ptr' mechanism",
        "RFC 7208 section 5.5 says 'ptr' should not be used. It is slow, unreliable, and "
        "some receivers ignore it.",
        "Replace 'ptr' with explicit 'ip4', 'ip6', 'a', or 'include' mechanisms.",
    ),
    _rule(
        "SPF-100",
        "spf",
        _F.PASS,
        None,
        "SPF record passed basic checks",
        "Exactly one SPF record was found and no issues were detected by TraceDNS's basic "
        "checks. Includes and redirects are not followed, so this is not a full SPF "
        "evaluation.",
        "No action required.",
    ),
    _rule(
        "SPF-900",
        "spf",
        _F.ERROR,
        None,
        "SPF check could not run",
        "The TXT query for the domain failed, so the presence of an SPF record could not "
        "be determined. This is an operational failure, not evidence of a missing record.",
        "Re-run the scan, increase --timeout, or check network and resolver connectivity.",
    ),
    _rule(
        "SPF-901",
        "spf",
        _F.INCONCLUSIVE,
        None,
        "SPF check inconclusive: domain does not exist",
        "The DNS returned NXDOMAIN for the domain, so there is no SPF configuration to assess.",
        "Confirm the domain name is spelled correctly.",
    ),
    # -------------------------------------------------------------- DMARC
    _rule(
        "DMARC-001",
        "dmarc",
        _F.FINDING,
        _S.MEDIUM,
        "No DMARC record published",
        "The query for the _dmarc name completed, but no record begins with 'v=DMARC1'. "
        "Receivers have no DMARC policy for this name. If this is a subdomain, a policy "
        "at the organizational domain may still apply; TraceDNS V1 does not perform that "
        "fallback lookup.",
        "Publish a TXT record at _dmarc.<domain>, for example "
        "'v=DMARC1; p=none; rua=mailto:dmarc-reports@<domain>', then move towards "
        "'p=quarantine' or 'p=reject' once reports confirm legitimate mail passes.",
    ),
    _rule(
        "DMARC-002",
        "dmarc",
        _F.FINDING,
        _S.MEDIUM,
        "Multiple DMARC records published",
        "More than one TXT record at the _dmarc name begins with 'v=DMARC'. RFC 7489 "
        "section 6.6.3 says receivers then apply no DMARC policy.",
        "Keep exactly one DMARC record and delete the others.",
    ),
    _rule(
        "DMARC-003",
        "dmarc",
        _F.FINDING,
        _S.MEDIUM,
        "DMARC version tag is invalid",
        "A DMARC record must begin with 'v=DMARC1'. Receivers discard records with any "
        "other version value.",
        "Make the first tag exactly 'v=DMARC1'.",
    ),
    _rule(
        "DMARC-004",
        "dmarc",
        _F.FINDING,
        _S.MEDIUM,
        "DMARC policy tag is missing",
        "The record has no 'p=' tag, which DMARC requires. Receivers may ignore the record "
        "or treat it as 'p=none'.",
        "Add a policy tag: 'p=none', 'p=quarantine', or 'p=reject'.",
    ),
    _rule(
        "DMARC-005",
        "dmarc",
        _F.FINDING,
        _S.MEDIUM,
        "DMARC policy value is invalid",
        "The 'p=' tag must be 'none', 'quarantine', or 'reject'.",
        "Set 'p=' to one of 'none', 'quarantine', or 'reject'.",
    ),
    _rule(
        "DMARC-006",
        "dmarc",
        _F.FINDING,
        _S.LOW,
        "DMARC record contains malformed tags",
        "Some tags are malformed, duplicated, or have values outside the range TraceDNS "
        "checks. Receivers may ignore these tags and fall back to defaults.",
        "Correct the listed tags. Tags are 'name=value' pairs separated by semicolons.",
    ),
    _rule(
        "DMARC-007",
        "dmarc",
        _F.FINDING,
        _S.INFO,
        "DMARC policy is monitoring-only (p=none)",
        "'p=none' asks receivers to take no action on failing mail. This is a normal "
        "first stage while collecting reports, and is not a vulnerability by itself.",
        "Review aggregate reports, then move to 'p=quarantine' or 'p=reject' once "
        "legitimate mail passes DMARC.",
    ),
    _rule(
        "DMARC-008",
        "dmarc",
        _F.FINDING,
        _S.INFO,
        "DMARC policy applies to a subset of mail (pct below 100)",
        "The 'pct' tag limits the policy to a percentage of failing messages; the rest are "
        "treated as if the policy were one step weaker.",
        "Raise 'pct' to 100 (or remove the tag) once the policy has been validated.",
    ),
    _rule(
        "DMARC-009",
        "dmarc",
        _F.FINDING,
        _S.INFO,
        "DMARC aggregate reporting is not configured",
        "There is no 'rua=' tag, so you will not receive aggregate reports showing which "
        "sources send mail using this domain.",
        "Add 'rua=mailto:<address>' to receive aggregate reports.",
    ),
    _rule(
        "DMARC-010",
        "dmarc",
        _F.FINDING,
        _S.INFO,
        "DMARC subdomain policy is weaker than the domain policy",
        "The 'sp=none' tag asks receivers to take no action for subdomains, even though "
        "the domain itself has an enforcing policy.",
        "If subdomains should be protected, set 'sp=' to 'quarantine' or 'reject', or "
        "remove it to inherit 'p='.",
    ),
    _rule(
        "DMARC-100",
        "dmarc",
        _F.PASS,
        None,
        "DMARC record passed basic checks",
        "Exactly one DMARC record was found with a valid version and policy. This is a "
        "basic syntax and policy check, not a full DMARC conformance test.",
        "No action required.",
    ),
    _rule(
        "DMARC-900",
        "dmarc",
        _F.ERROR,
        None,
        "DMARC check could not run",
        "The TXT query for the _dmarc name failed, so the presence of a DMARC record could "
        "not be determined. This is an operational failure, not evidence of a missing "
        "record.",
        "Re-run the scan, increase --timeout, or check network and resolver connectivity.",
    ),
    _rule(
        "DMARC-901",
        "dmarc",
        _F.INCONCLUSIVE,
        None,
        "DMARC check inconclusive: domain does not exist",
        "The DNS returned NXDOMAIN for the target domain, so there is no DMARC "
        "configuration to assess.",
        "Confirm the domain name is spelled correctly.",
    ),
    # --------------------------------------------------------------- DKIM
    _rule(
        "DKIM-001",
        "dkim",
        _F.FINDING,
        _S.LOW,
        "No DKIM record found for the selector",
        "The query completed but no TXT record exists at this selector. This shows only "
        "that this selector is not published; the domain may sign mail with a different "
        "selector.",
        "Confirm the selector in the 'DKIM-Signature: s=' header of a message sent from "
        "the domain, or publish the key your mail provider supplies.",
    ),
    _rule(
        "DKIM-002",
        "dkim",
        _F.FINDING,
        _S.MEDIUM,
        "DKIM record has no public key tag",
        "A DKIM key record must contain a 'p=' tag with the public key.",
        "Republish the key record exactly as supplied by your mail provider.",
    ),
    _rule(
        "DKIM-003",
        "dkim",
        _F.FINDING,
        _S.LOW,
        "DKIM record contains malformed tags",
        "Some tags are malformed or have values outside the range TraceDNS checks.",
        "Correct the listed tags. Republishing the record supplied by your mail provider "
        "usually resolves this.",
    ),
    _rule(
        "DKIM-004",
        "dkim",
        _F.FINDING,
        _S.LOW,
        "DKIM key for the selector is revoked",
        "The 'p=' tag is empty, which RFC 6376 defines as a revoked key. Signatures using "
        "this selector will not verify.",
        "If the selector is still in use, publish its current public key. Otherwise no "
        "action is needed.",
    ),
    _rule(
        "DKIM-005",
        "dkim",
        _F.FINDING,
        _S.INFO,
        "DKIM key is in testing mode (t=y)",
        "'t=y' tells verifiers the domain is testing DKIM, and some verifiers treat "
        "failures leniently.",
        "Remove 't=y' once DKIM signing has been validated.",
    ),
    _rule(
        "DKIM-006",
        "dkim",
        _F.FINDING,
        _S.LOW,
        "Multiple TXT records found for the selector",
        "More than one TXT record exists at the selector name. Verifiers may pick either "
        "record, which makes verification unpredictable.",
        "Keep a single key record per selector.",
    ),
    _rule(
        "DKIM-100",
        "dkim",
        _F.PASS,
        None,
        "DKIM key record found for the selector",
        "A key record with a public key was found. This does not prove that the domain's "
        "mail is signed with this selector or that signatures verify.",
        "No action required.",
    ),
    _rule(
        "DKIM-800",
        "dkim",
        _F.SKIPPED,
        None,
        "DKIM check skipped: no selector supplied",
        "DKIM selectors cannot be reliably discovered from DNS, so TraceDNS only checks "
        "DKIM for a selector you supply.",
        "Re-run with --dkim-selector <selector>. The selector appears in the 's=' tag of "
        "a message's DKIM-Signature header.",
    ),
    _rule(
        "DKIM-900",
        "dkim",
        _F.ERROR,
        None,
        "DKIM check could not run",
        "The TXT query for the selector failed, so the presence of a DKIM record could "
        "not be determined. This is an operational failure, not evidence of a missing "
        "record.",
        "Re-run the scan, increase --timeout, or check network and resolver connectivity.",
    ),
    _rule(
        "DKIM-901",
        "dkim",
        _F.INCONCLUSIVE,
        None,
        "DKIM check inconclusive: domain does not exist",
        "The DNS returned NXDOMAIN for the target domain, so there is no DKIM "
        "configuration to assess.",
        "Confirm the domain name is spelled correctly.",
    ),
)

RULES: dict[str, Rule] = {rule.rule_id: rule for rule in _RULE_LIST}


def make_finding(
    rule_id: str,
    subject: str,
    evidence: list[str] | None = None,
    detail: str | None = None,
) -> Finding:
    """Create a finding from a catalog rule.

    ``subject`` is the DNS name the finding concerns; it makes the finding ID
    stable and unique within a report (for example ``SPF-002:example.com``).
    ``detail`` is appended to the rule's standard description.
    """
    rule = RULES[rule_id]
    description = rule.description if not detail else f"{rule.description} {detail}"
    return Finding(
        id=f"{rule.rule_id}:{subject}",
        category=rule.category,
        check=rule.check,
        status=rule.status,
        severity=rule.severity,
        title=rule.title,
        description=description,
        evidence=list(evidence or []),
        recommendation=rule.recommendation,
        rule_id=rule.rule_id,
    )
