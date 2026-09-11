"""Validate limits before they can become OpenLDAP configuration values."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[2] / "scripts/common.sh"


@pytest.mark.parametrize("name", ["LDAP_SEARCH_SIZE_LIMIT", "LDAP_SEARCH_TIME_LIMIT"])
@pytest.mark.parametrize(
    ("value", "valid"),
    [
        (None, True),
        ("1", True),
        ("500", True),
        ("2147483647", True),
        ("unlimited", True),
        ("", False),
        ("0", False),
        ("-1", False),
        ("01", False),
        ("1.5", False),
        (" 1", False),
        ("1\n", False),
        ("1\nolcAccess: to * by * write", False),
        ("2147483648", False),
        ("9" * 100, False),
        ("unlimited\n", False),
    ],
)
def test_search_limit_values(name: str, value: str | None, valid: bool) -> None:
    environment = {
        key: item
        for key, item in os.environ.items()
        if key not in {"LDAP_SEARCH_SIZE_LIMIT", "LDAP_SEARCH_TIME_LIMIT"}
    }
    if value is not None:
        environment[name] = value
    result = subprocess.run(
        ["sh", "-c", '. "$1"; validate_search_limits', "sh", str(COMMON)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    assert result.returncode == (0 if valid else 64)
    if not valid:
        assert name in result.stderr
