# Changelog

All notable changes to TraceDNS are recorded here. The project follows [semantic versioning](https://semver.org/).

## [1.1.0] — 2026-10-25

Addresses the findings of the V1 repository review.

### Changed
- **DMARC checks now follow RFC 9989** (DMARC, May 2026), which obsoletes RFC 7489.
  - `pct`, `rf` and `ri` were removed by RFC 9989 and are now reported as legacy tags (**DMARC-011**, info). `pct` values are no longer validated.
  - A record without `p=` is **low** severity instead of medium (**DMARC-004**), because RFC 9989 treats it as `p=none`.
  - Invalid `sp=` or `np=` values are now **medium** (**DMARC-005**, previously reported as a low-severity malformed tag), because RFC 9989 §4.10.1 handles them the same way as an invalid `p=`.
  - Rule descriptions cite RFC 9989 (multiple records: §4.10; version tag: §4.7). The organizational-domain limitation now refers to the RFC 9989 DNS tree walk.
- **SPF-001 evidence wording.** "None starts with the 'v=spf1' version term" replaces "none begin with 'v=spf1'", which was literally untrue for records such as `v=spf1-all`.
- **JSON schema version 1.1**: adds `scan.nameservers`.

### Added
- **DMARC (RFC 9989 tags):**
  - `np` validation; `np=none` under an enforcing policy is reported (**DMARC-013**, info).
  - `t` validation; `t=y` under an enforcing policy is reported (**DMARC-012**, info).
  - `psd` and `fo` validation.
  - `rua`/`ruf` entries must be URIs, and `mailto:` entries must contain an address.
- **SPF:** more than 10 DNS-lookup terms at the top level of a record (**SPF-010**, medium; RFC 7208 §4.6.4). This is a lower bound, because included records are not fetched.
- **DKIM key checks:** RSA keys are parsed (SubjectPublicKeyInfo or PKCS#1) and Ed25519 keys are length-checked.
  - Unparseable key: **DKIM-007**, medium.
  - RSA key under 2048 bits: **DKIM-008**, low.
  - RSA key under 1024 bits: **DKIM-009**, medium (RFC 8301).
- **`--nameserver / -n IP`** sends queries to a specific resolver instead of the system one. Repeatable and comma-separated; IP addresses only.
- **`schema/report-1.1.json`**, a JSON Schema for reports. Tests validate the sample report and generated reports against it, and keep its vocabularies in sync with the code.
- **GitHub Actions CI:** lint, format, and tests on Python 3.11–3.13 on Ubuntu and Windows.
- **Screenshots** in `docs/images/`, captured from live runs with `scripts/capture_screenshots.py`.
- **`scripts/generate_sample_report.py`** regenerates `examples/sample-report.json` from the test fixtures.

### Removed
- **DMARC-008** ("pct below 100"). Superseded by DMARC-011, because RFC 9989 removed `pct`. The ID is retired and will not be reused.

### Fixed
- On Windows, the `NUL` device was treated as an interactive terminal, so `tracedns > NUL` (or a CI job with stdin on `NUL`) waited at the menu.

## [1.0.0] — 2026-10-24

First release:
- A, AAAA, MX, NS, and TXT queries with distinct query statuses.
- Basic SPF and DMARC checks, and selector-based DKIM lookup.
- Rich terminal interface, JSON reports, and exit codes.
- Offline test suite.
