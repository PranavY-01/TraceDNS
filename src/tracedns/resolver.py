"""DNS name validation and query execution.

All DNS traffic goes through :class:`DNSResolver`, which wraps dnspython,
applies finite timeouts, and converts every outcome (records, no records,
NXDOMAIN, timeout, SERVFAIL, REFUSED, or another failure) into a
:class:`~tracedns.models.DNSResult`. dnspython exceptions never escape.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from typing import Any, Protocol

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

from tracedns.models import SUPPORTED_RECORD_TYPES, DNSResult, QueryStatus

DEFAULT_TIMEOUT_SECONDS = 5.0
# Upper bound for one nameserver attempt; the overall lifetime is the user timeout.
MAX_ATTEMPT_TIMEOUT_SECONDS = 2.0

MAX_NAME_LENGTH = 253
MAX_LABEL_LENGTH = 63

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_URL_CHARACTERS = ("://", "/", "\\", "?", "#", "@", ":")


class InvalidNameError(ValueError):
    """Raised when a domain name or DKIM selector fails validation."""


def normalize_domain(raw: str) -> str:
    """Validate and normalize a domain name supplied by the user.

    Accepts fully qualified names such as ``example.com`` (case-insensitive,
    optional trailing dot, internationalized names converted to their ASCII
    form). Rejects URLs, paths, ports, IP addresses, and single-label names.
    """
    value = (raw or "").strip()
    if not value:
        raise InvalidNameError("Domain name is empty.")
    for marker in _URL_CHARACTERS:
        if marker in value:
            raise InvalidNameError(
                f"'{raw}' looks like a URL or contains '{marker}'. "
                "Enter a bare domain name such as example.com."
            )
    if value.endswith("."):
        value = value[:-1]
    if any(char.isspace() for char in value):
        raise InvalidNameError(f"'{raw}' contains whitespace.")
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise InvalidNameError(
                f"'{raw}' is not a valid internationalized domain name."
            ) from exc
    value = value.lower()

    labels = value.split(".")
    if len(labels) < 2:
        raise InvalidNameError(
            f"'{raw}' is a single-label name. Enter a fully qualified domain such as example.com."
        )
    _check_labels(labels, raw, _HOST_LABEL)
    if labels[-1].isdigit():
        raise InvalidNameError(f"'{raw}' looks like an IP address, not a domain name.")
    if len(value) > MAX_NAME_LENGTH:
        raise InvalidNameError(f"'{raw}' is longer than {MAX_NAME_LENGTH} characters.")
    return value


def normalize_selector(raw: str) -> str:
    """Validate and normalize a DKIM selector.

    Selectors are one or more dot-separated labels of letters, digits, and
    hyphens (for example ``google``, ``selector1`` or ``s1.mail``).
    """
    value = (raw or "").strip().lower()
    if not value:
        raise InvalidNameError("DKIM selector is empty.")
    labels = value.split(".")
    _check_labels(labels, raw, _HOST_LABEL, kind="DKIM selector")
    return value


def normalize_nameserver(raw: str) -> str:
    """Validate a resolver address given with ``--nameserver``.

    Only literal IPv4 or IPv6 addresses are accepted, so choosing a resolver
    never itself requires a DNS lookup.
    """
    value = (raw or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise InvalidNameError(
            f"'{raw}' is not an IP address. --nameserver takes a resolver IP such as 1.1.1.1."
        ) from exc


def dkim_query_name(selector: str, domain: str) -> str:
    """Build ``<selector>._domainkey.<domain>`` and enforce the name length limit."""
    name = f"{selector}._domainkey.{domain}"
    if len(name) > MAX_NAME_LENGTH:
        raise InvalidNameError(
            f"DKIM query name '{name}' is longer than {MAX_NAME_LENGTH} characters."
        )
    return name


def dmarc_query_name(domain: str) -> str:
    return f"_dmarc.{domain}"


def _check_labels(
    labels: list[str], raw: str, pattern: re.Pattern[str], kind: str = "domain name"
) -> None:
    for label in labels:
        if not label:
            raise InvalidNameError(f"'{raw}' contains an empty label (consecutive dots).")
        if len(label) > MAX_LABEL_LENGTH:
            raise InvalidNameError(
                f"Label '{label}' in '{raw}' is longer than {MAX_LABEL_LENGTH} characters."
            )
        if not pattern.match(label):
            raise InvalidNameError(
                f"'{raw}' is not a valid {kind}: label '{label}' may contain only letters, "
                "digits, and hyphens, and cannot start or end with a hyphen."
            )


class ResolverBackend(Protocol):
    """The subset of :class:`dns.resolver.Resolver` that TraceDNS uses."""

    def resolve(self, qname: Any, rdtype: Any, *, search: bool) -> Iterable[Any]: ...


class DNSResolver:
    """Run DNS queries with finite timeouts and normalized results.

    ``nameservers`` replaces the system resolver configuration with specific
    resolver IP addresses (already validated with :func:`normalize_nameserver`).
    ``backend`` can be any object with a dnspython-compatible ``resolve``
    method; tests inject a fake so the suite never touches the network.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        backend: ResolverBackend | None = None,
        nameservers: Sequence[str] = (),
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout
        self.nameservers = tuple(nameservers)
        self._backend = backend
        self._configuration_error: str | None = None
        if backend is None:
            try:
                # With explicit nameservers the system configuration is not needed.
                resolver = dns.resolver.Resolver(configure=not self.nameservers)
            except (dns.resolver.NoResolverConfiguration, OSError) as exc:
                self._configuration_error = f"No usable resolver configuration: {exc}"
            else:
                if self.nameservers:
                    resolver.nameservers = list(self.nameservers)
                resolver.lifetime = timeout
                resolver.timeout = min(timeout, MAX_ATTEMPT_TIMEOUT_SECONDS)
                resolver.cache = None
                self._backend = resolver

    def query(self, name: str, record_type: str) -> DNSResult:
        """Query ``name`` for ``record_type`` and return a normalized result."""
        record_type = record_type.upper()
        if record_type not in SUPPORTED_RECORD_TYPES:
            raise ValueError(f"Unsupported record type: {record_type}")
        if self._backend is None:
            return DNSResult(name, record_type, QueryStatus.ERROR, error=self._configuration_error)

        try:
            answer = self._backend.resolve(
                dns.name.from_text(name), dns.rdatatype.from_text(record_type), search=False
            )
            records = [normalize_rdata(record_type, rdata) for rdata in answer]
        except dns.resolver.NXDOMAIN:
            return DNSResult(name, record_type, QueryStatus.NXDOMAIN, error="Name does not exist.")
        except dns.resolver.NoAnswer:
            return DNSResult(name, record_type, QueryStatus.NOT_FOUND)
        except dns.exception.Timeout:
            return DNSResult(
                name,
                record_type,
                QueryStatus.TIMEOUT,
                error=f"No response within {self.timeout:g} seconds.",
            )
        except dns.resolver.NoNameservers as exc:
            return _classify_no_nameservers(name, record_type, exc)
        except (dns.exception.DNSException, OSError, UnicodeError) as exc:
            return DNSResult(
                name, record_type, QueryStatus.ERROR, error=f"{type(exc).__name__}: {exc}"
            )
        except Exception as exc:  # reported as an ERROR result, not swallowed
            return DNSResult(
                name,
                record_type,
                QueryStatus.ERROR,
                error=f"Unexpected {type(exc).__name__}: {exc}",
            )

        if not records:
            return DNSResult(name, record_type, QueryStatus.NOT_FOUND)
        return DNSResult(
            name, record_type, QueryStatus.SUCCESS, records=_sorted(record_type, records)
        )


def _sorted(record_type: str, records: list[str]) -> list[str]:
    """Order records deterministically; MX records sort by numeric preference."""
    if record_type == "MX":
        return sorted(records, key=lambda value: (int(value.split(" ", 1)[0]), value))
    return sorted(records)


def _classify_no_nameservers(
    name: str, record_type: str, exc: dns.resolver.NoNameservers
) -> DNSResult:
    """Map dnspython's 'all nameservers failed' error to SERVFAIL, REFUSED, or ERROR.

    dnspython records each failed attempt as a tuple whose fourth element is
    either the rcode text (``"SERVFAIL"``, ``"REFUSED"``) or an exception.
    """
    reasons: list[str] = []
    for attempt in exc.kwargs.get("errors", []) or []:
        if isinstance(attempt, tuple) and len(attempt) >= 4:
            reasons.append(str(attempt[3]))
    if reasons and all(reason == "REFUSED" for reason in reasons):
        status = QueryStatus.REFUSED
        message = "The resolver refused the query."
    elif "SERVFAIL" in reasons:
        status = QueryStatus.SERVFAIL
        message = "The resolver reported a server failure (SERVFAIL)."
    elif "REFUSED" in reasons:
        status = QueryStatus.REFUSED
        message = "The resolver refused the query."
    else:
        status = QueryStatus.ERROR
        detail = "; ".join(reasons) if reasons else "no nameserver answered"
        message = f"All nameservers failed: {detail}"
    return DNSResult(name, record_type, status, error=message)


def normalize_rdata(record_type: str, rdata: Any) -> str:
    """Convert one dnspython rdata object into a stable text value.

    TXT character-strings are concatenated without separators, which is how
    SPF, DMARC, and DKIM consumers reassemble records longer than 255 bytes.
    Bytes that are not valid UTF-8 are kept as backslash escapes.
    """
    if record_type in ("A", "AAAA"):
        return str(rdata.address)
    if record_type == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text(omit_final_dot=True)}"
    if record_type == "NS":
        return rdata.target.to_text(omit_final_dot=True)
    if record_type == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="backslashreplace")
    return rdata.to_text()
