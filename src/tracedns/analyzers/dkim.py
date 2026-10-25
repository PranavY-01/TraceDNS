"""Selector-based DKIM key record lookup and basic checks.

The record at ``<selector>._domainkey.<domain>`` is checked for:

* presence (only when the query completed) and multiple TXT records;
* a ``v`` tag, if present, that is first and equal to ``DKIM1``;
* a ``p`` tag that is present, non-empty (empty means revoked), and valid
  base64;
* a ``k`` tag, if present, of ``rsa`` or ``ed25519``;
* the key itself: an RSA key must be a DER-encoded public key (a
  SubjectPublicKeyInfo or a bare RSAPublicKey) whose modulus size is reported
  against RFC 8301 (under 1024 bits is unusable, under 2048 is weak); an
  Ed25519 key must be 32 bytes;
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
RSA_MINIMUM_BITS = 1024  # RFC 8301 section 3.2: smaller keys must not be accepted
RSA_RECOMMENDED_BITS = 2048  # RFC 8301 section 3.2: signers should use at least this
ED25519_KEY_BYTES = 32  # RFC 8463 section 4
_RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1
_DER_SEQUENCE, _DER_INTEGER, _DER_BIT_STRING, _DER_OID = 0x30, 0x02, 0x03, 0x06


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

    key = "".join(tags["p"].split()) if "p" in tags else None
    key_type = tags.get("k", "rsa").lower()
    key_detail: str | None = None
    if key is None:
        findings.append(make_finding("DKIM-002", name, [evidence]))
    elif not key:
        findings.append(make_finding("DKIM-004", name, [evidence]))
    elif (der := _decode_base64(key)) is None:
        problems.append("'p=' is not valid base64.")
    elif key_type in KEY_TYPES:
        key_detail, rule = _assess_key(key_type, der)
        if rule:
            findings.append(make_finding(rule, name, [evidence, key_detail]))

    if problems:
        findings.append(make_finding("DKIM-003", name, [evidence, *problems]))
    flags = {flag.strip().lower() for flag in tags.get("t", "").split(":")}
    if "y" in flags:
        findings.append(make_finding("DKIM-005", name, [evidence]))

    usable = key_detail is not None and not any(
        f.rule_id in ("DKIM-007", "DKIM-009") for f in findings
    )
    if usable and not has_issue(findings):
        findings.insert(0, make_finding("DKIM-100", name, [evidence, key_detail]))
    return findings


def _assess_key(key_type: str, der: bytes) -> tuple[str, str | None]:
    """Describe a decoded key and return the rule it triggers, if any."""
    if key_type == "ed25519":
        if len(der) == ED25519_KEY_BYTES:
            return "Ed25519 key (32 bytes).", None
        return f"Decoded key is {len(der)} bytes; Ed25519 keys are 32 bytes.", "DKIM-007"
    bits = rsa_key_bits(der)
    if bits is None:
        return "The decoded value is not a DER-encoded RSA public key.", "DKIM-007"
    detail = f"RSA key size: {bits} bits."
    if bits < RSA_MINIMUM_BITS:
        return detail, "DKIM-009"
    if bits < RSA_RECOMMENDED_BITS:
        return detail, "DKIM-008"
    return detail, None


def rsa_key_bits(der: bytes) -> int | None:
    """Return the modulus size of a DER RSA public key, or None if it cannot be parsed.

    Accepts a SubjectPublicKeyInfo (what DKIM records normally contain) or a
    bare PKCS#1 RSAPublicKey.
    """
    try:
        tag, body, end = _read_der(der, 0)
        if tag != _DER_SEQUENCE or end != len(der):
            return None
        first_tag, first, position = _read_der(body, 0)
        if first_tag == _DER_INTEGER:
            return _rsa_public_key_bits(body)
        if first_tag != _DER_SEQUENCE:
            return None
        oid_tag, oid, _ = _read_der(first, 0)
        bit_tag, bit_string, end = _read_der(body, position)
        if oid_tag != _DER_OID or oid != _RSA_ENCRYPTION_OID:
            return None
        if bit_tag != _DER_BIT_STRING or end != len(body) or bit_string[:1] != b"\x00":
            return None
        inner_tag, inner, inner_end = _read_der(bit_string, 1)
        if inner_tag != _DER_SEQUENCE or inner_end != len(bit_string):
            return None
        return _rsa_public_key_bits(inner)
    except ValueError:
        return None


def _rsa_public_key_bits(body: bytes) -> int | None:
    """Parse the contents of ``RSAPublicKey ::= SEQUENCE { modulus, publicExponent }``."""
    modulus_tag, modulus, position = _read_der(body, 0)
    exponent_tag, exponent, end = _read_der(body, position)
    if modulus_tag != _DER_INTEGER or exponent_tag != _DER_INTEGER or end != len(body):
        return None
    if not modulus or not exponent or modulus[0] & 0x80:  # must be positive
        return None
    return int.from_bytes(modulus, "big").bit_length() or None


def _read_der(data: bytes, position: int) -> tuple[int, bytes, int]:
    """Read one DER element at ``position``; return (tag, contents, next position)."""
    if position + 2 > len(data):
        raise ValueError("truncated DER element")
    tag, length = data[position], data[position + 1]
    position += 2
    if length & 0x80:
        size = length & 0x7F
        if not 1 <= size <= 4 or position + size > len(data):
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[position : position + size], "big")
        position += size
    end = position + length
    if end > len(data):
        raise ValueError("DER element runs past the end of the data")
    return tag, data[position:end], end


def _decode_base64(value: str) -> bytes | None:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
