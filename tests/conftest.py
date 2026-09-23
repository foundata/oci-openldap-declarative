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
    group.addoption(
        "--run-benchmarks",
        action="store_true",
        help="run resource workloads against the selected images",
    )
    group.addoption(
        "--run-application-tests",
        action="store_true",
        help="run the opt-in DokuWiki LDAP consumer test",
    )
    group.addoption(
        "--dokuwiki-image-layout",
        default=None,
        help="cached OCI layout with a dokuwiki tag; must match the pinned platform digest",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if not config.getoption("--run-benchmarks"):
        for item in items:
            if "benchmark" in item.keywords:
                item.add_marker(pytest.mark.skip(reason="requires --run-benchmarks"))
    if not config.getoption("--run-application-tests"):
        for item in items:
            if "application" in item.keywords:
                item.add_marker(
                    pytest.mark.skip(reason="requires --run-application-tests")
                )
