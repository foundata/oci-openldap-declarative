"""Command-line options shared by the unit and integration suites."""

from __future__ import annotations

import pytest

MODES = ("conclear", "conclear-generator", "conclear-runtime", "developer-build")


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("openldap", "OpenLDAP container suites")
    group.addoption(
        "--mode",
        choices=MODES,
        default=None,
        help="image source for tests/integration: exact ConClear layouts or a "
        "non-release developer build",
    )
    group.addoption(
        "--run-dir",
        default=None,
        help="existing directory for isolated Podman storage in developer-build "
        "mode; defaults to a pytest temporary directory",
    )
