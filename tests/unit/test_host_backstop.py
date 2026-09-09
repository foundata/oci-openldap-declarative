"""Exercise the rootless host backstop against a fake Podman."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKSTOP = ROOT / "examples/systemd/openldap-expiry-backstop"
HEALTH_CALL = "exec test-directory /usr/local/lib/openldap-declarative/healthcheck.sh"
STOP_CALL = "stop --time 10 test-directory"
FAKE_PODMAN = """#!/usr/bin/env sh
set -u

printf '%s\\n' "$*" >>"${PODMAN_CALLS}"

case "${1:-} ${2:-} ${3:-} ${4:-}" in
  'container exists test-directory ')
    [ "${CONTAINER_EXISTS}" = true ]
    ;;
  'container inspect --format {{.State.Running}}')
    printf '%s\\n' "${CONTAINER_RUNNING}"
    ;;
  'container inspect --format {{.Image}}')
    image_id=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    printf '%s\\n' "${image_id}"
    ;;
  'run --rm --network none')
    [ "${SNAPSHOT_VALID}" = true ]
    ;;
  'exec test-directory /usr/local/lib/openldap-declarative/healthcheck.sh ')
    [ "${CONTAINER_HEALTHY}" = true ]
    ;;
  'stop --time 10 test-directory')
    exit 0
    ;;
  *)
    exit 2
    ;;
esac
"""


@dataclass(frozen=True)
class BackstopResult:
    returncode: int
    calls: list[str]


class Backstop:
    """Run the backstop script with a fake Podman that records its calls."""

    def __init__(self, workspace: Path) -> None:
        self.snapshot = workspace / "snapshot"
        self.snapshot.mkdir()
        self.public_key = workspace / "snapshot.pub"
        self.public_key.write_text("test public key\n", encoding="utf-8")
        self.fake_podman = workspace / "podman"
        self.fake_podman.write_text(FAKE_PODMAN, encoding="utf-8")
        self.fake_podman.chmod(0o700)
        self.calls = workspace / "calls"

    def run(
        self, *, exists: bool, running: bool, snapshot_valid: bool, healthy: bool
    ) -> BackstopResult:
        self.calls.write_text("", encoding="utf-8")
        environment = {
            **os.environ,
            "CONTAINER_EXISTS": str(exists).lower(),
            "CONTAINER_RUNNING": str(running).lower(),
            "SNAPSHOT_VALID": str(snapshot_valid).lower(),
            "CONTAINER_HEALTHY": str(healthy).lower(),
            "PODMAN_CALLS": str(self.calls),
            "PODMAN": str(self.fake_podman),
        }
        completed = subprocess.run(
            [
                str(BACKSTOP),
                "test-directory",
                str(self.snapshot),
                str(self.public_key),
                "test-service",
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        calls = self.calls.read_text(encoding="utf-8").splitlines()
        return BackstopResult(completed.returncode, calls)


@pytest.fixture
def backstop(tmp_path: Path) -> Backstop:
    return Backstop(tmp_path)


def test_healthy_signed_snapshot_is_accepted_without_stopping(
    backstop: Backstop,
) -> None:
    result = backstop.run(exists=True, running=True, snapshot_valid=True, healthy=True)

    assert result.returncode == 0
    assert any(
        call.startswith("run --rm --network none --read-only") for call in result.calls
    ), "host snapshot verifier was not isolated from the network"
    assert HEALTH_CALL in result.calls
    assert not any(call.startswith("stop --time") for call in result.calls)


@pytest.mark.parametrize(
    ("running", "snapshot_valid", "healthy", "stopped", "health_checked"),
    [
        pytest.param(True, False, True, True, False, id="invalid-snapshot"),
        pytest.param(True, True, False, True, True, id="unhealthy-container"),
        pytest.param(False, False, False, False, False, id="stopped-container"),
    ],
)
def test_unsafe_states_fail_and_stop_only_running_containers(
    backstop: Backstop,
    running: bool,
    snapshot_valid: bool,
    healthy: bool,
    stopped: bool,
    health_checked: bool,
) -> None:
    result = backstop.run(
        exists=True, running=running, snapshot_valid=snapshot_valid, healthy=healthy
    )

    assert result.returncode == 1
    assert (STOP_CALL in result.calls) is stopped
    assert (HEALTH_CALL in result.calls) is health_checked


def test_missing_container_is_reported(backstop: Backstop) -> None:
    result = backstop.run(
        exists=False, running=False, snapshot_valid=False, healthy=False
    )

    assert result.returncode == 1
    assert result.calls == ["container exists test-directory"]


@pytest.mark.parametrize("target", ["snapshot", "public_key"])
@pytest.mark.parametrize("condition", ["missing", "symlink", "unreadable"])
def test_invalid_trust_paths_stop_a_running_container(
    backstop: Backstop, target: str, condition: str
) -> None:
    path: Path = getattr(backstop, target)
    if condition == "unreadable":
        if os.geteuid() == 0:
            pytest.skip("root can read permission-restricted inputs")
        path.chmod(0)
    else:
        moved = path.with_name(f"{path.name}-original")
        path.rename(moved)
        if condition == "symlink":
            path.symlink_to(moved)
    try:
        result = backstop.run(
            exists=True, running=True, snapshot_valid=True, healthy=True
        )
        assert result.returncode == 66
        assert result.calls[-1] == STOP_CALL
        assert HEALTH_CALL not in result.calls
        assert not any(call.startswith("run ") for call in result.calls)
    finally:
        if condition == "unreadable":
            path.chmod(0o700 if path.is_dir() else 0o600)


@pytest.mark.parametrize("exists", [True, False])
def test_missing_trust_input_does_not_stop_an_inactive_target(
    backstop: Backstop, exists: bool
) -> None:
    backstop.public_key.unlink()
    result = backstop.run(
        exists=exists, running=False, snapshot_valid=False, healthy=False
    )
    assert result.returncode == 1
    assert STOP_CALL not in result.calls
