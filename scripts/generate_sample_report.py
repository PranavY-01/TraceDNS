"""Regenerate examples/sample-report.json from the controlled test fixtures.

The sample is illustrative: it is produced by running the real scanner against
the fake DNS backend in tests/helpers.py (documentation addresses, no network).

    python scripts/generate_sample_report.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from helpers import healthy_responses, make_resolver, txt  # noqa: E402
from tracedns.models import SUPPORTED_CHECKS, SUPPORTED_RECORD_TYPES  # noqa: E402
from tracedns.reporter import write_json_report  # noqa: E402
from tracedns.scanner import ScanRequest, run_scan  # noqa: E402

OUTPUT = ROOT / "examples" / "sample-report.json"


def main() -> None:
    responses = healthy_responses()
    responses[("example.com", "TXT")] = [
        txt("v=spf1 include:_spf.example.net ~all"),
        txt("google-site-verification=abc123"),
    ]
    responses[("_dmarc.example.com", "TXT")] = [txt("v=DMARC1; p=none")]
    request = ScanRequest("example.com", SUPPORTED_RECORD_TYPES, SUPPORTED_CHECKS, "s1", 5.0)
    report = run_scan(request, make_resolver(responses))
    write_json_report(report, OUTPUT, overwrite=True)
    print(f"Wrote {OUTPUT.relative_to(ROOT)}: {[f.rule_id for f in report.findings]}")


if __name__ == "__main__":
    main()
