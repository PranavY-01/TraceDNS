"""Capture terminal screenshots of real TraceDNS runs as SVG files in docs/images/.

Each image is the unedited output of the ``tracedns`` command running against
live DNS, recorded with Rich's SVG export (the same renderer that draws the
terminal). Live DNS changes over time, so re-run this after visible changes:

    python scripts/capture_screenshots.py

Only reserved documentation names are scanned (example.com, *.example).
"""

from __future__ import annotations

import io
import sys
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.terminal_theme import TerminalTheme

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tracedns import cli  # noqa: E402
from tracedns.reporter import PALETTE, THEME  # noqa: E402

OUTPUT_DIR = ROOT / "docs" / "images"
WIDTH = 100

# (file name, window title, tracedns arguments)
SHOTS: list[tuple[str, str, list[str]]] = [
    ("welcome", "tracedns", ["welcome"]),
    ("scan-clean", "tracedns scan example.com", ["scan", "example.com"]),
    (
        "scan-findings",
        "tracedns scan example.com --dkim-selector default",
        ["scan", "example.com", "--dkim-selector", "default"],
    ),
    (
        "scan-nxdomain",
        "tracedns scan nothing-here.example",
        ["scan", "nothing-here.example"],
    ),
    (
        "invalid-input",
        "tracedns scan https://example.com/login",
        ["scan", "https://example.com/login"],
    ),
]


def _rgb(hex_color: str) -> tuple[int, int, int]:
    value = hex_color.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


DARK_THEME = TerminalTheme(
    background=(15, 17, 22),
    foreground=_rgb(PALETTE["text"]),
    normal=[
        (15, 17, 22),
        _rgb(PALETTE["error"]),
        _rgb(PALETTE["success"]),
        _rgb(PALETTE["warning"]),
        _rgb(PALETTE["secondary"]),
        _rgb(PALETTE["primary"]),
        _rgb(PALETTE["secondary"]),
        _rgb(PALETTE["text"]),
    ],
)


def capture(arguments: list[str]) -> tuple[Console, int]:
    """Run the real CLI with both of its consoles recording into one buffer."""
    console = Console(
        file=io.StringIO(),
        record=True,
        width=WIDTH,
        theme=THEME,
        color_system="truecolor",
        force_terminal=False,  # no spinner frames in the recording
        legacy_windows=False,  # render as a modern (VT) terminal, not the legacy Windows console
        highlight=False,
    )
    original = cli.make_console
    cli.make_console = lambda *, stderr=False: console
    try:
        cli.app(args=arguments, prog_name="tracedns")
        code = 0
    except SystemExit as exit_:
        code = int(exit_.code or 0)
    finally:
        cli.make_console = original
    return console, code


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    for name, title, arguments in SHOTS:
        console, code = capture(arguments)
        path = OUTPUT_DIR / f"{name}.svg"
        console.save_svg(str(path), title=title, theme=DARK_THEME)
        print(f"{path.relative_to(ROOT)}  (exit {code})")
    print(f"Captured from live runs on {stamp}.")


if __name__ == "__main__":
    main()
