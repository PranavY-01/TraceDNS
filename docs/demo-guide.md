# TraceDNS developer demo guide

A hands-on walkthrough of TraceDNS for developers and contributors. Each scenario runs a real command, shows the expected result, and points to the code and tests responsible for that behaviour. It's useful for onboarding, for code reviews, and for checking that a change hasn't altered behaviour.

> Looking for a non-technical introduction? See the [user guide](user-guide.md).

Expected results were recorded from live runs on 24 October 2026. Scenarios marked **live** depend on public DNS for `example.com`, which can change. Scenarios marked **offline** use the test fixtures and always behave the same way.

---

## 0. Environment setup

```powershell
git clone https://github.com/PranavY-01/TraceDNS.git
cd TraceDNS
python -m venv .venv
.venv\Scripts\Activate.ps1            # Linux/macOS: source .venv/bin/activate
python -m pip install -e ".[dev]"     # runtime + pytest + ruff, editable install
```

Verify the toolchain:

```powershell
tracedns --version        # TraceDNS 1.1.0
python -m pytest -q       # 232 passed
ruff check .              # All checks passed!
ruff format --check .     # all files already formatted
```

To read exit codes, use `$LASTEXITCODE` in PowerShell or `echo $?` in bash. Use a terminal at least 100 columns wide so tables don't wrap.

**Target domains.** The live scenarios use only `example.com` (reserved by IANA for documentation) and `nothing-here.example` (reserved TLD). Use domains you own or are authorized to assess for anything else.

## Code map

| Concern | Module | Tests |
|---|---|---|
| CLI options, validation, exit codes, menu | `src/tracedns/cli.py` | `tests/test_cli.py` |
| Scan workflow, query de-duplication | `src/tracedns/scanner.py` | `tests/test_reporter.py`, `tests/test_cli.py` |
| Name validation, DNS queries, status mapping | `src/tracedns/resolver.py` | `tests/test_resolver.py` |
| SPF / DMARC / DKIM analysis | `src/tracedns/analyzers/` | `tests/test_spf.py`, `test_dmarc.py`, `test_dkim.py` |
| Rule IDs, severities, remediation text | `src/tracedns/rules.py` | covered through the analyzer tests |
| Data model, summary counts, scan status | `src/tracedns/models.py` | `tests/test_reporter.py` |
| Rich rendering, atomic JSON writes | `src/tracedns/reporter.py` | `tests/test_reporter.py` |
| Report contract | `schema/report-1.1.json` | `tests/test_schema.py` |
| Fake DNS backend, test keys, network guard | `tests/helpers.py`, `tests/conftest.py` | – |
| Sample report, screenshots | `scripts/generate_sample_report.py`, `scripts/capture_screenshots.py` | – |
| CI | `.github/workflows/ci.yml` | runs Ruff + the suite on 3.11–3.13, Ubuntu and Windows |

Full design notes are in [architecture.md](architecture.md). Release notes are in [CHANGELOG.md](../CHANGELOG.md).

---

## Scenarios

### 1. Entry points (live terminal)

```powershell
tracedns              # banner + interactive menu (type 3, then 4)
tracedns welcome      # same screen as an explicit command
tracedns --help
tracedns scan --help
```

**Expect:** the banner and a four-option menu. Option 3 prints the usage table and option 4 exits with code 0. Run with stdout redirected (`tracedns > out.txt`) and the banner prints without waiting for input.

**Code path:** `cli.main` (callback with `invoke_without_command=True`) → `_welcome` → `run_menu`. Menu scans call the same `execute_scan` as the `scan` command. Interactivity is decided by `_is_interactive()` (stdin and stdout are both TTYs).

**Tests:** `test_no_command_shows_banner_without_blocking`, `test_menu_*`. The menu tests patch `_is_interactive` and feed input through `CliRunner`.

### 2. Baseline scan (live)

```powershell
tracedns scan example.com
```

**Expect:** stage lines (`✓ Querying DNS records  5 queries, 5 with records`, `✓ Analyzing SPF  passed`, `✓ Analyzing DMARC  passed with 1 observation(s)`, `○ DKIM selector lookup  no selector supplied`), then a records table, then panels **PASS** SPF-100, **PASS** DMARC-100, **INFO** DMARC-009, **SKIPPED** DKIM-800. Exit code **0**.

**What it demonstrates**
- Each stage line comes from a `ScanObserver` event (`reporter.StageReporter`). The scanner itself never prints.
- `scanner._QueryCache` runs each `(name, type)` pair once. SPF reuses the TXT answer already fetched for the records table, which is why 6 queries run for 5 record types plus DMARC.
- INFO findings don't affect the exit code. See `cli.exit_code_for`.

### 3. DKIM with a supplied selector (live)

```powershell
tracedns scan example.com --dkim-selector default
```

**Expect:** a **LOW** finding, DKIM-004 *DKIM key for the selector is revoked* (evidence `v=DKIM1; p=`). Exit code **1**.

**Code path:** `resolver.normalize_selector` → `resolver.dkim_query_name` (enforces the 253-character limit) → `analyzers.dkim._analyze_record`. Passing `--dkim-selector` adds `dkim` to the checks (`cli.build_request`).

**Tests:** `tests/test_dkim.py`, including `test_record_contents_are_treated_as_data`.

### 4. Input validation (live, but no queries sent)

```powershell
tracedns scan https://example.com/login     # URL rejected
tracedns scan localhost                     # single-label rejected
tracedns scan example.com -r CNAME          # unsupported type
tracedns scan example.com -c none,spf       # 'none' can't be combined
```

**Expect:** one `✗` line on stderr each, and exit code **2**.

**Code path:** `resolver.normalize_domain` / `normalize_selector` raise `InvalidNameError`; `cli._parse_choices` raises `UsageError`. Both are caught in `cli.scan` before a resolver is created.

**Tests:** `test_normalize_domain_rejects` (16 cases), `test_invalid_domain_exits_two`. The CLI tests also assert `backend.calls == []`, proving nothing was queried.

### 5. Non-existent target (live)

```powershell
tracedns scan nothing-here.example
```

**Expect:** every row `nxdomain`; **INCONCLUSIVE** SPF-901 and DMARC-901; **SKIPPED** DKIM-800. Scan status `completed` (NXDOMAIN is a definitive answer). Exit code **1**.

**Design point:** `scanner.run_scan` sets `target_exists = False` when any query at the domain itself returns NXDOMAIN. The DMARC and DKIM analyzers then return `*-901` instead of "missing record" findings.

### 6. Narrow queries (live)

```powershell
tracedns scan example.com -r A,MX -c none
tracedns scan example.com -r A -r AAAA -c spf
```

**Expect:** the first runs exactly 2 queries and no assessments. The second runs A, AAAA, and the TXT query that SPF needs.

**Tests:** `test_selected_record_types`, `test_selected_checks_only_run_needed_queries`. Both assert the exact list of backend calls.

### 7. JSON output (live)

```powershell
tracedns scan example.com --json demo-report.json                # exit 0
tracedns scan example.com --json demo-report.json                # exit 2: already exists
tracedns scan example.com --json demo-report.json --overwrite    # exit 0
Remove-Item demo-report.json
```

JSON-only mode (stdout carries nothing but the document):

```powershell
$r = tracedns scan example.com --json - | ConvertFrom-Json
$r.scan.status                                   # completed
$r.findings | Select-Object rule_id, status, severity
```

Linux/macOS: `tracedns scan example.com --json - | jq '.summary'`

**Code path:** `reporter.check_output_path` runs before the scan. `reporter.write_json_report` writes a temp file in the target directory, fsyncs it, then calls `os.replace`, and cleans up the temp file on any `BaseException`. `models.to_jsonable` handles dataclasses, enums, and datetimes. In JSON-only mode `execute_scan` receives `console=None`.

**Tests:** `test_json_serialization_matches_schema`, `test_existing_file_is_not_replaced_without_overwrite`, `test_interrupted_write_leaves_no_partial_files`, `test_json_stdout_mode_contains_only_json`.

### 8. Failure paths (offline)

These can't be triggered reliably against real DNS, so run the tests that exercise them:

```powershell
python -m pytest tests/test_resolver.py -v -k "timeout or servfail or refused or nxdomain or network"
python -m pytest tests/test_cli.py -v -k "exit_code or ctrl_c or json_stdout or no_command"
```

**Expect:** `7 passed`, then `6 passed`.

| Outcome | dnspython signal | `QueryStatus` | Check result | Exit |
|---|---|---|---|---|
| Timeout | `LifetimeTimeout` | `timeout` | `*-900` error | 3 |
| SERVFAIL | `NoNameservers` with `"SERVFAIL"` | `servfail` | `*-900` error | 3 |
| REFUSED | `NoNameservers` with `"REFUSED"` | `refused` | `*-900` error | 3 |
| Network down | `NoNameservers` with `OSError` | `error` | `*-900` error | 3 |
| Ctrl+C | `KeyboardInterrupt` | – | no report written | 130 |

Mapping lives in `DNSResolver.query` and `_classify_no_nameservers`.

### 9. Untrusted-data handling (offline)

```powershell
python -m pytest tests/test_reporter.py -v -k "untrusted or long_values"
python -m pytest tests/test_dkim.py -v -k "treated_as_data"
```

**What it demonstrates:** TXT content such as `[bold red]` or raw escape sequences is never interpreted. `reporter.safe_text` escapes control characters and wraps values in `rich.text.Text`, so Rich markup isn't parsed. Long values are shortened in the table but kept complete in JSON.

### 10. Choosing the resolver (live)

```powershell
tracedns scan example.com -r A,NS -c none --nameserver 1.1.1.1
tracedns scan example.com -n 9.9.9.9,2620:fe::fe --json - | ConvertFrom-Json | Select-Object -ExpandProperty scan
tracedns scan example.com -n dns.google      # exit 2: IP addresses only
```

**Expect:** the header line ends with `resolver 1.1.1.1`, and the JSON `scan.nameservers` lists the normalized addresses (an empty list means the system resolver). A hostname is rejected with exit code 2 before any query is sent.

**Code path:** `resolver.normalize_nameserver` (uses `ipaddress`, so choosing a resolver never needs a DNS lookup) → `cli.build_request` (deduplicates the addresses) → `DNSResolver(nameservers=...)`, which uses `dns.resolver.Resolver(configure=False)`, so a machine with a broken resolver configuration can still scan.

**Tests:** `python -m pytest tests/test_cli.py -k nameserver` (3 passed) and `test_explicit_nameservers_replace_system_configuration`.

### 11. Standards checks (offline)

```powershell
python -m pytest tests/test_dmarc.py -v -k "rfc_9989 or test_mode or non_existent or report or subdomain"
python -m pytest tests/test_spf.py -v -k "lookup or glued or never_evaluated"
python -m pytest tests/test_dkim.py -v -k "rsa or ed25519 or pkcs1"
```

**Expect:** `18 passed`, `5 passed`, `9 passed`.

| Area | Behaviour | Where |
|---|---|---|
| DMARC (RFC 9989) | `pct`/`rf`/`ri` are reported as legacy tags (DMARC-011). `t=y` with an enforcing policy is reported (DMARC-012), as is `np=none` (DMARC-013). Invalid `sp`/`np` are as serious as an invalid `p` (DMARC-005). A missing `p` is LOW, because RFC 9989 treats it as `p=none` | `analyzers/dmarc.py` |
| SPF lookup limit | Counts `include`, `a`, `mx`, `ptr`, `exists` before `all`, plus `redirect` only when there's no `all`. More than 10 gives SPF-010 | `analyzers/spf.py` (`LOOKUP_MECHANISMS`) |
| DKIM keys | A minimal DER reader returns the RSA modulus size from a SubjectPublicKeyInfo or a PKCS#1 key. Under 1024 bits gives DKIM-009, under 2048 gives DKIM-008, unparseable gives DKIM-007. Ed25519 keys must be 32 bytes | `analyzers/dkim.py` (`rsa_key_bits`) |

The DKIM fixtures in `tests/helpers.py` are real public keys generated with OpenSSL. To check the parser against fresh keys:

```bash
openssl genrsa 3072 | openssl rsa -pubout -outform DER | python -c "import sys; from tracedns.analyzers.dkim import rsa_key_bits; print(rsa_key_bits(sys.stdin.buffer.read()))"   # 3072
```

### 12. Report schema (offline)

```powershell
python -m pytest tests/test_schema.py -v
```

**Expect:** `11 passed`. The suite validates `examples/sample-report.json` and six generated scenarios against `schema/report-1.1.json`, checks that contract violations are rejected (for example, a severity on a `pass`), and fails if the schema's enums drift from `models.py`. Any change to the report layout needs a new `SCHEMA_VERSION`, a new schema file, and a regenerated sample (`python scripts/generate_sample_report.py`).

### 13. Debugging aids

- `--verbose` prints a traceback for unexpected internal errors. Without it, the user sees a single line and exit code 3 (`test_unexpected_error_has_no_traceback`).
- `--timeout 0.5` to `60` sets the per-query lifetime. Each nameserver attempt is capped at 2 seconds (`resolver.MAX_ATTEMPT_TIMEOUT_SECONDS`).
- `NO_COLOR=1` disables colors. If the output encoding isn't UTF-8, ASCII glyphs are used automatically (`reporter.glyphs_for`).

---

## Using it in scripts and CI

Exit codes are designed for automation:

| Code | Meaning |
|---|---|
| 0 | Completed; nothing above INFO |
| 1 | Completed with a LOW/MEDIUM/HIGH finding or an inconclusive check |
| 2 | Invalid input or report path; nothing queried |
| 3 | DNS query failure (`partial`/`failed` scan), report write failure, or an unexpected error |
| 130 | Interrupted |

Example check that fails a pipeline on anything above INFO:

```bash
tracedns scan your-domain.example --json - > tracedns.json
status=$?
if [ "$status" -ne 0 ]; then echo "TraceDNS exit code $status"; exit "$status"; fi
```

## Adding or changing a rule

1. Add or edit the entry in `rules._RULE_LIST`. The status and severity are set there, and `_rule` rejects a severity on non-FINDING rules.
2. Emit it from the analyzer with `make_finding("<RULE-ID>", subject, evidence)`.
3. Add analyzer tests for both the triggering case and a near miss.
4. Update the rule catalog table in [architecture.md](architecture.md#rule-catalog) and add an entry to [CHANGELOG.md](../CHANGELOG.md). Never reuse a retired rule ID (for example, `DMARC-008`).
5. Run `python -m pytest -q`, `ruff check .`, and `ruff format --check .`. CI runs the same checks on every push.
6. If the change is visible in the terminal, refresh the screenshots with `python scripts/capture_screenshots.py`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `tracedns` not recognized | Virtual environment not active | Activate `.venv`, or call `.venv\Scripts\tracedns.exe` |
| `Activate.ps1` blocked | PowerShell execution policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Every query `timeout`, scan `failed` | No DNS or network access | Expected operational-failure path (exit code 3). Offline scenarios 8, 9, 11 and 12 still work |
| Live output differs from this guide | `example.com` DNS changed | Compare behaviour, not exact records |
| `+ x !` instead of `✓ ✗ ▲` | Output encoding isn't UTF-8 | ASCII fallback by design; use Windows Terminal for Unicode |
| `CategoryInfo … RemoteException` around errors | PowerShell 5.1 formatting of redirected stderr (`2>&1`) | Don't redirect stderr when reading errors interactively |
| `ModuleNotFoundError: helpers` when running tests | pytest run outside the repo root | Run from the repo root; `pythonpath = ["tests"]` in `pyproject.toml` |
