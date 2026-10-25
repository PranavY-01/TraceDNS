import dns.exception
import dns.resolver
import pytest

from helpers import FakeBackend, make_resolver, no_nameservers, rdata, txt
from tracedns.models import QueryStatus
from tracedns.resolver import (
    DNSResolver,
    InvalidNameError,
    dkim_query_name,
    normalize_domain,
    normalize_nameserver,
    normalize_selector,
)


def query(responses, name="example.com", record_type="A"):
    return make_resolver(responses).query(name, record_type)


def test_successful_query_returns_records():
    result = query({("example.com", "A"): [rdata("A", "192.0.2.1")]})
    assert result.status is QueryStatus.SUCCESS
    assert result.records == ["192.0.2.1"]
    assert result.error is None


def test_multiple_records_are_sorted_deterministically():
    result = query(
        {
            ("example.com", "MX"): [
                rdata("MX", "20 b.example.com."),
                rdata("MX", "5 a.example.com."),
            ]
        },
        record_type="MX",
    )
    assert result.records == ["5 a.example.com", "20 b.example.com"]


def test_ns_records_drop_trailing_dot():
    result = query({("example.com", "NS"): [rdata("NS", "ns1.example.net.")]}, record_type="NS")
    assert result.records == ["ns1.example.net"]


def test_empty_answer_is_not_found():
    result = query({("example.com", "A"): dns.resolver.NoAnswer()})
    assert result.status is QueryStatus.NOT_FOUND
    assert result.records == []


def test_empty_rrset_is_not_found():
    result = query({("example.com", "A"): []})
    assert result.status is QueryStatus.NOT_FOUND


def test_nxdomain():
    result = query({("example.com", "A"): dns.resolver.NXDOMAIN()})
    assert result.status is QueryStatus.NXDOMAIN
    assert result.status.completed


def test_timeout_is_an_operational_failure():
    result = query({("example.com", "A"): dns.resolver.LifetimeTimeout(timeout=1.0, errors=[])})
    assert result.status is QueryStatus.TIMEOUT
    assert result.status.failed
    assert "1 seconds" in result.error


def test_servfail():
    result = query({("example.com", "A"): no_nameservers("example.com", "A", ["SERVFAIL"])})
    assert result.status is QueryStatus.SERVFAIL


def test_refused():
    result = query({("example.com", "A"): no_nameservers("example.com", "A", ["REFUSED"])})
    assert result.status is QueryStatus.REFUSED


def test_mixed_servfail_and_refused_reports_servfail():
    exc = no_nameservers("example.com", "A", ["REFUSED", "SERVFAIL"])
    assert query({("example.com", "A"): exc}).status is QueryStatus.SERVFAIL


def test_network_unavailable_is_error():
    exc = no_nameservers("example.com", "A", [OSError("Network is unreachable")])
    result = query({("example.com", "A"): exc})
    assert result.status is QueryStatus.ERROR
    assert "Network is unreachable" in result.error


def test_unexpected_dns_exception_is_error():
    result = query({("example.com", "A"): dns.exception.DNSException("boom")})
    assert result.status is QueryStatus.ERROR


def test_unexpected_non_dns_exception_is_reported_not_raised():
    result = query({("example.com", "A"): RuntimeError("bug")})
    assert result.status is QueryStatus.ERROR
    assert "RuntimeError" in result.error


def test_txt_chunks_are_concatenated_without_separator():
    result = query(
        {("example.com", "TXT"): [txt("v=spf1 include:a.example", ".net -all")]}, record_type="TXT"
    )
    assert result.records == ["v=spf1 include:a.example.net -all"]


def test_txt_invalid_utf8_is_preserved_as_escapes():
    record = rdata("TXT", r'"bad\255byte"')
    result = query({("example.com", "TXT"): [record]}, record_type="TXT")
    assert result.records == ["bad\\xffbyte"]


def test_unsupported_record_type_rejected():
    with pytest.raises(ValueError):
        make_resolver({}).query("example.com", "CNAME")


def test_queries_use_absolute_names_without_search():
    backend = FakeBackend({})
    DNSResolver(timeout=1.0, backend=backend).query("example.com", "A")
    assert backend.calls == [("example.com", "A")]


def test_real_resolver_has_finite_timeouts():
    resolver = DNSResolver(timeout=3.0)
    backend = resolver._backend
    assert backend.lifetime == 3.0
    assert backend.timeout <= 2.0


def test_explicit_nameservers_replace_system_configuration():
    resolver = DNSResolver(timeout=3.0, nameservers=["192.0.2.53", "2001:db8::53"])
    assert [str(ns) for ns in resolver._backend.nameservers] == ["192.0.2.53", "2001:db8::53"]
    assert resolver._backend.lifetime == 3.0


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1.1.1.1", "1.1.1.1"), (" 2001:DB8::1 ", "2001:db8::1"), ("::1", "::1")],
)
def test_normalize_nameserver_accepts_ip_addresses(raw, expected):
    assert normalize_nameserver(raw) == expected


@pytest.mark.parametrize("raw", ["", "dns.google", "1.1.1", "1.1.1.1:53", "https://1.1.1.1"])
def test_normalize_nameserver_rejects_non_ips(raw):
    with pytest.raises(InvalidNameError):
        normalize_nameserver(raw)


# -------------------------------------------------------------- validation


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  mail.example.co.uk ", "mail.example.co.uk"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_normalize_domain_accepts(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "https://example.com",
        "example.com/path",
        "example.com?q=1",
        "user@example.com",
        "example.com:443",
        "localhost",
        "exa mple.com",
        "-bad.example.com",
        "bad-.example.com",
        "under_score.example.com",
        "example..com",
        "192.0.2.1",
        "a" * 64 + ".com",
        ".".join(["a" * 60] * 5),
    ],
)
def test_normalize_domain_rejects(raw):
    with pytest.raises(InvalidNameError):
        normalize_domain(raw)


def test_selector_validation():
    assert normalize_selector("Selector1") == "selector1"
    assert normalize_selector("s1.mail") == "s1.mail"
    for bad in ["", "sel ector", "sel/ector", "-s1", "s1..x", "s1;rm"]:
        with pytest.raises(InvalidNameError):
            normalize_selector(bad)


def test_dkim_query_name_enforces_length():
    assert dkim_query_name("s1", "example.com") == "s1._domainkey.example.com"
    with pytest.raises(InvalidNameError):
        dkim_query_name("s" * 63, ".".join(["a" * 60] * 3) + ".com")
