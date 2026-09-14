"""The public preflight command resolves its implementation and has no positional inputs."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/preflight-snapshot.sh"


@pytest.mark.parametrize(
    ("arguments", "status"),
    [
        (("--help",), 0),
        (("-h",), 0),
        (("unexpected-secret",), 64),
        (("--help", "extra"), 64),
    ],
)
def test_preflight_public_link_help_and_usage(
    tmp_path: Path, arguments: tuple[str, ...], status: int
) -> None:
    command = tmp_path / "openldap-preflight"
    command.symlink_to(SCRIPT)
    scratch = tmp_path / "scratch"
    result = subprocess.run(
        ["sh", str(command), *arguments],
        env={**os.environ, "LDAP_RUNTIME_DIR": str(scratch)},
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == status, result.stderr
    assert "Usage: openldap-preflight" in result.stdout + result.stderr
    assert "unexpected-secret" not in result.stdout + result.stderr
    assert not scratch.exists()
