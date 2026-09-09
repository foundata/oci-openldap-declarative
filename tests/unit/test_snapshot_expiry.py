"""Check the final offline acceptance deadline without changing the host clock."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[2] / "scripts/common.sh"


@pytest.mark.parametrize(
    ("now", "clock_status", "expires", "expected"),
    [
        (1735689719, 0, "2025-01-01T00:02:00Z", 0),
        (1735689720, 0, "2025-01-01T00:02:00Z", 78),
        (1735689721, 0, "2025-01-01T00:02:00Z", 78),
        (1735689719, 1, "2025-01-01T00:02:00Z", 70),
        (1735689719, 0, "invalid", 70),
    ],
)
def test_final_deadline_check(
    tmp_path: Path, now: int, clock_status: int, expires: str, expected: int
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"expires_at": expires}), encoding="utf-8")
    clock = tmp_path / "date"
    clock.write_text(
        '#!/usr/bin/env sh\nprintf "%s\\n" "$TEST_NOW"\nexit "$TEST_CLOCK_STATUS"\n',
        encoding="utf-8",
    )
    clock.chmod(0o700)
    result = subprocess.run(
        [
            "sh",
            "-c",
            '. "$1"; check_snapshot_expiry "$2"',
            "expiry",
            str(COMMON),
            str(manifest),
        ],
        env={
            **os.environ,
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "TEST_NOW": str(now),
            "TEST_CLOCK_STATUS": str(clock_status),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == expected, result.stdout + result.stderr
