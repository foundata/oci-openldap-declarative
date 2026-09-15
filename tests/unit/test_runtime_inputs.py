"""Retired inputs fail explicitly; the base-DN input is only an assertion."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[2] / "scripts/common.sh"


def validate(
    function: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", "-c", '. "$1"; "$2" "dc=example,dc=org"', "sh", str(COMMON), function],
        env={
            key: value
            for key, value in os.environ.items()
            if not key.startswith("LDAP_")
        }
        | environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )


@pytest.mark.parametrize("name", ["LDAP_ADMIN_PASSWORD", "LDAP_DOMAIN", "LDAP_BASE_DN"])
@pytest.mark.parametrize("value", ["", "TEST-ONLY-do-not-log"])
def test_removed_runtime_inputs_are_rejected(name: str, value: str) -> None:
    result = validate("validate_runtime_configuration", {name: value})
    assert result.returncode == 64 and name in result.stderr
    assert "TEST-ONLY" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    ("value", "status"),
    [
        (None, 0),
        ("dc=example,dc=org", 0),
        ("", 64),
        ("dc=wrong", 64),
        ("DC=example,DC=org", 64),
    ],
)
def test_expected_base_dn_is_an_exact_assertion(value: str | None, status: int) -> None:
    result = validate(
        "validate_expected_base_dn",
        {} if value is None else {"LDAP_EXPECTED_BASE_DN": value},
    )
    assert result.returncode == status
    if status:
        assert "LDAP_EXPECTED_BASE_DN" in result.stderr
