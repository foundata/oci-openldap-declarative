"""The password helper shares snapshot hashing and never echoes invalid input."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from argon2 import PasswordHasher

ROOT = Path(__file__).resolve().parents[2]


def run_helper(value: bytes, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "generator.password", *arguments],
        input=value,
        capture_output=True,
        cwd=ROOT,
        check=False,
        timeout=10,
    )


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
@pytest.mark.parametrize(
    "password",
    ["TEST-ONLY-password", " leading and trailing ", "x" * 4094, "caf\u00e9"],
)
def test_password_helper_outputs_a_usable_verifier(
    password: str, ending: bytes
) -> None:
    result = run_helper(password.encode() + ending)
    assert result.returncode == 0 and not result.stderr
    verifier = result.stdout.decode().rstrip("\n")
    assert verifier.startswith("{ARGON2}$argon2id$v=19$m=19456,t=2,p=1$")
    assert PasswordHasher().verify(verifier.removeprefix("{ARGON2}"), password)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"\n",
        b"\r\n",
        b"TEST-ONLY\nsecond",
        b"TEST-ONLY\x00",
        b"TEST-ONLY\r",
        b"TEST-ONLY\xff",
        b"x" * 4097,
    ],
)
def test_password_helper_rejects_invalid_input_without_echoing(value: bytes) -> None:
    result = run_helper(value)
    assert result.returncode == 2 and not result.stdout
    assert b"ERROR:" in result.stderr and b"TEST-ONLY" not in result.stderr


def test_password_helper_does_not_accept_secret_arguments() -> None:
    result = run_helper(b"", "TEST-ONLY-secret-argument")
    assert result.returncode == 2 and not result.stdout
    assert b"TEST-ONLY" not in result.stderr


def test_password_helper_help_needs_no_input() -> None:
    result = run_helper(b"", "--help")
    assert result.returncode == 0 and b"Usage: openldap-password" in result.stdout


def test_password_helper_generates_fresh_salts() -> None:
    assert (
        run_helper(b"TEST-ONLY-password").stdout
        != run_helper(b"TEST-ONLY-password").stdout
    )
