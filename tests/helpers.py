"""Test helpers: real dnspython rdata builders and a fake resolver backend."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from tracedns.models import DNSResult, QueryStatus
from tracedns.resolver import DNSResolver


def rdata(record_type: str, text: str) -> Any:
    """Build a real dnspython rdata object from zone-file text."""
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(record_type), text)


def txt(*strings: str) -> Any:
    """Build a TXT rdata with one or more character-strings."""
    return rdata("TXT", " ".join(f'"{s}"' for s in strings))


def no_nameservers(name: str, record_type: str, reasons: Iterable[Any]) -> Exception:
    """Build dnspython's 'all nameservers failed' exception with given rcodes/errors."""
    request = dns.message.make_query(name, record_type)
    errors = [("192.0.2.53", False, 53, reason, None) for reason in reasons]
    return dns.resolver.NoNameservers(request=request, errors=errors)


class FakeBackend:
    """Stands in for dns.resolver.Resolver.

    ``responses`` maps ``(name, TYPE)`` to a list of rdata objects or to an
    exception instance to raise. Unlisted queries raise NoAnswer.
    """

    def __init__(self, responses: dict[tuple[str, str], Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    def resolve(self, qname: Any, rdtype: Any, *, search: bool) -> list[Any]:
        key = (qname.to_text(omit_final_dot=True), dns.rdatatype.to_text(rdtype))
        self.calls.append(key)
        response = self.responses.get(key)
        if response is None:
            raise dns.resolver.NoAnswer()
        if isinstance(response, BaseException):
            raise response
        return list(response)


def make_resolver(responses: dict[tuple[str, str], Any]) -> DNSResolver:
    return DNSResolver(timeout=1.0, backend=FakeBackend(responses))


def long_txt(value: str, size: int = 200) -> Any:
    """Build a TXT rdata, splitting ``value`` into character-strings of at most ``size`` bytes."""
    return txt(*(value[i : i + size] for i in range(0, len(value), size)))


# Real public keys generated with OpenSSL (public material only; no private keys kept).
RSA_2048_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2eQ1RHEuKdQuVJD2YWD0Uepb7XxGWJYHeQyW519Pjz9o8GwH"
    "TK4QWElDzpGNgBnwIJrnnRzBBKoHuGb/7yRCoTCcRc32sgzr5LFnFJnFzm5TcLenf2p5+2xA3ieXKOZdS+BogP/dsDgQ"
    "pE/FlXg9RTU5vEzj8lAZWREpEzsY9+GocQz3i4t+8N46YFaDeiizECk8V0GqoxKfNhs190PaZKVHxPDQL4sWzv7F3btW"
    "VYOyZTwYWbD5Ly+FKh8XQeU5G0RP8uMiaHXl7+BcJ6Rox/PJIWkyYcSrPD3RHVSg2bpEUD4hgin3W+CbFh4QZoLWyUV2"
    "UGnU1sjD8lFS7t+8tQIDAQAB"
)
RSA_2048_PKCS1_KEY = (  # the same key as a bare PKCS#1 RSAPublicKey
    "MIIBCgKCAQEA2eQ1RHEuKdQuVJD2YWD0Uepb7XxGWJYHeQyW519Pjz9o8GwHTK4QWElDzpGNgBnwIJrnnRzBBKoHuGb/"
    "7yRCoTCcRc32sgzr5LFnFJnFzm5TcLenf2p5+2xA3ieXKOZdS+BogP/dsDgQpE/FlXg9RTU5vEzj8lAZWREpEzsY9+Go"
    "cQz3i4t+8N46YFaDeiizECk8V0GqoxKfNhs190PaZKVHxPDQL4sWzv7F3btWVYOyZTwYWbD5Ly+FKh8XQeU5G0RP8uMi"
    "aHXl7+BcJ6Rox/PJIWkyYcSrPD3RHVSg2bpEUD4hgin3W+CbFh4QZoLWyUV2UGnU1sjD8lFS7t+8tQIDAQAB"
)
RSA_1024_KEY = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYNOhN/pK/SiUUBolbm0Q3xPUfSgTAHpAnD/Ve7bwH7MqBOZjk/Pln"
    "qmBsUsgyfAxjv2PvW6ueBgXw6tlMZAEJkDfb5pJEvzHx9k9e01qqHOTsNn8oCdevc/dGpUKQOV0QVzTAYB316iS7mtMO"
    "DJkIgNheh/W8//X6kvVpEA3x1wIDAQAB"
)
RSA_512_KEY = (
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALQlxSb7ri2dIcGt0lC54/UIf7kF4KIfGqkKrPYD2+INBLbT/8NwE1u1gOgi"
    "js2Al3XnTZuKJg4OzPWlQY5SjpMCAwEAAQ=="
)
ED25519_KEY = "+9xKa7zNYGK0RfE63lSsgR79nSv5TfJDjEcLG+gT1eY="


def healthy_responses(domain: str = "example.com") -> dict[tuple[str, str], Any]:
    """A well-configured domain using documentation addresses."""
    return {
        (domain, "A"): [rdata("A", "192.0.2.10")],
        (domain, "AAAA"): [rdata("AAAA", "2001:db8::10")],
        (domain, "MX"): [rdata("MX", f"10 mail.{domain}.")],
        (domain, "NS"): [rdata("NS", f"ns1.{domain}."), rdata("NS", f"ns2.{domain}.")],
        (domain, "TXT"): [
            txt("v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all"),
            txt("google-site-verification=abc123"),
        ],
        (f"_dmarc.{domain}", "TXT"): [txt(f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}")],
        (f"s1._domainkey.{domain}", "TXT"): [long_txt(f"v=DKIM1; k=rsa; p={RSA_2048_KEY}")],
    }


def txt_result(
    *records: str, name: str = "example.com", status: QueryStatus = QueryStatus.SUCCESS
) -> DNSResult:
    """A TXT DNSResult for analyzer tests."""
    if records and status is QueryStatus.SUCCESS:
        return DNSResult(name, "TXT", status, records=list(records))
    if not records and status is QueryStatus.SUCCESS:
        status = QueryStatus.NOT_FOUND
    return DNSResult(name, "TXT", status, error=None if status.completed else "simulated failure")
