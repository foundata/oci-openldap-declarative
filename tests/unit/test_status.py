"""Keep health enforcement and the public JSON status contract in agreement."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


@pytest.mark.parametrize(
    ("now", "ldap_code", "damage", "state", "status_code", "health_code"),
    [
        (1735689600, 0, "", "healthy", 0, 0),
        (1735689659, 0, "", "healthy", 0, 0),
        (1735689660, 0, "", "soft-expired", 1, 0),
        (1735689719, 0, "", "soft-expired", 1, 0),
        (1735689720, 0, "", "expired", 2, 1),
        (1735689600, 81, "", "unavailable", 2, 1),
        (1735689660, 81, "", "unavailable", 2, 1),
        (1735689720, 81, "", "expired", 2, 1),
        (1735689600, 0, "missing", "unavailable", 2, 1),
        (1735689600, 0, "symlink", "unavailable", 2, 1),
        (1735689600, 0, "syntax", "unavailable", 2, 1),
        (1735689600, 0, "revision", "unavailable", 2, 1),
        (1735689600, 0, "generated_at", "unavailable", 2, 1),
        (1735689600, 0, "soft_expires_at", "unavailable", 2, 1),
        (1735689600, 0, "expires_at", "unavailable", 2, 1),
    ],
)
def test_status_and_health_share_deadlines_and_availability(
    tmp_path: Path,
    now: int,
    ldap_code: int,
    damage: str,
    state: str,
    status_code: int,
    health_code: int,
) -> None:
    manifest = {
        "service_id": "test-service",
        "revision": 7,
        "base_dn": "DC=example,dc=org",
        "generated_at": "2025-01-01T00:00:00Z",
        "soft_expires_at": "2025-01-01T00:01:00Z",
        "expires_at": "2025-01-01T00:02:00Z",
    }
    if damage == "revision":
        manifest["revision"] = -1
    elif damage in ("generated_at", "soft_expires_at", "expires_at"):
        manifest[damage] = (
            "2025-01-01T00:03:00Z" if damage != "expires_at" else "invalid"
        )
    active = tmp_path / "active-manifest.json"
    active.write_text(json.dumps(manifest))
    if damage == "missing":
        active.unlink()
    elif damage == "symlink":
        target = tmp_path / "target"
        active.rename(target)
        active.symlink_to(target)
    elif damage == "syntax":
        active.write_text("{")
    for name, script in {
        "date": 'printf "%s\\n" "$TEST_NOW"',
        "ldapsearch": 'printf "dn: dc=example,dc=org\\n"; exit "$TEST_LDAP_CODE"',
    }.items():
        executable = tmp_path / name
        executable.write_text("#!/usr/bin/env sh\n" + script + "\n")
        executable.chmod(0o700)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "LDAP_RUNTIME_DIR": str(tmp_path),
        "TEST_NOW": str(now),
        "TEST_LDAP_CODE": str(ldap_code),
    }
    status = subprocess.run(
        [str(SCRIPTS / "status.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    health = subprocess.run(
        ["sh", str(SCRIPTS / "healthcheck.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert status.returncode == status_code, status.stdout + status.stderr
    document = json.loads(status.stdout)
    assert document["state"] == state
    assert health.returncode == health_code, health.stdout + health.stderr
    if not damage:
        assert document["seconds_until_hard_expiry"] == 1735689720 - now
        assert "7" in health.stdout + health.stderr
    if state == "soft-expired":
        assert "soft" in health.stderr
