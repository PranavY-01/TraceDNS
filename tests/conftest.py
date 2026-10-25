"""Shared fixtures: a guard against real network access, and plain (uncoloured) output."""

from __future__ import annotations

import socket
from typing import Any

import pytest
import typer.rich_utils


@pytest.fixture(autouse=True)
def plain_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep test output free of ANSI colour codes, even on CI runners.

    Typer forces a colour terminal for help screens when GITHUB_ACTIONS,
    FORCE_COLOR or PY_COLORS is set (read once, at import), and Rich honours
    FORCE_COLOR. Colour codes split words such as "--record", so assertions
    on the text would fail only in CI.
    """
    for name in ("FORCE_COLOR", "PY_COLORS", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(typer.rich_utils, "FORCE_TERMINAL", False)


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly if any test tries to open a real network connection."""

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("Network access is disabled in tests")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "sendto", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
