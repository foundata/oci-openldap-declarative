"""Check the shared health/status probe independently of LDIF DN spelling."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[2] / "scripts/common.sh"


@pytest.mark.parametrize(
    ("output", "search_status", "expected"),
    [
        ("dn: dc=example,dc=org\n", 0, 0),
        ("dn:: ZGM9ZXhhbXBsZSxkYz1vcmc=\n", 0, 0),
        ("dn: dc=example,\n dc=org\n", 0, 0),
        ("", 0, 1),
        ("dn: dc=example,dc=org\n", 32, 1),
    ],
)
def test_probe_requires_a_successful_base_lookup(
    tmp_path: Path, output: str, search_status: int, expected: int
) -> None:
    search = tmp_path / "ldapsearch"
    search.write_text(
        '#!/usr/bin/env sh\nprintf "%s" "$TEST_LDIF"\nexit "$TEST_LDAP_STATUS"\n',
        encoding="utf-8",
    )
    search.chmod(0o700)
    result = subprocess.run(
        [
            "sh",
            "-c",
            '. "$1"; ldap_is_available "$2"',
            "probe",
            str(COMMON),
            "DC=example,dc=org",
        ],
        env={
            **os.environ,
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "TEST_LDIF": output,
            "TEST_LDAP_STATUS": str(search_status),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == expected, result.stdout + result.stderr
