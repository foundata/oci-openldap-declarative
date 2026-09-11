"""Readiness helpers shared by the container suites."""

from __future__ import annotations

import time

import pytest

from tests.integration.harness import Podman

LIB = "/usr/local/lib/openldap-declarative"
LDAP_URI = "ldap://127.0.0.1:1389"
LDAPI_URI = "ldapi://%2Frun%2Fopenldap%2Fldapi"
READINESS_DEADLINE = 20.0
POLL_INTERVAL = 0.25


def wait_until_healthy(podman: Podman, name: str) -> None:
    deadline = time.monotonic() + READINESS_DEADLINE
    while time.monotonic() < deadline:
        if podman.state(name) != "running":
            pytest.fail(f"{name} stopped before becoming healthy:\n{podman.logs(name)}")
        if podman.exec(name, f"{LIB}/healthcheck.sh", check=False).returncode == 0:
            return
        time.sleep(POLL_INTERVAL)
    pytest.fail(f"{name} did not become healthy:\n{podman.logs(name)}")


def wait_until_initializing(podman: Podman, name: str) -> None:
    deadline = time.monotonic() + READINESS_DEADLINE
    while time.monotonic() < deadline:
        if podman.state(name) != "running":
            pytest.fail(f"{name} stopped before initializing:\n{podman.logs(name)}")
        if "Starting snapshot initialization for directory" in podman.logs(name):
            return
        time.sleep(POLL_INTERVAL)
    pytest.fail(f"{name} did not start initializing:\n{podman.logs(name)}")


def assert_build_artifacts_absent(podman: Podman, image: str, volume: str) -> None:
    """Verified plaintext and initialization temp files must not outlive a run."""
    podman.run_container(
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--entrypoint",
        "sh",
        "--mount",
        f"type=volume,source={volume},destination=/inspect,ro",
        image,
        "-c",
        "test ! -e /inspect/verified-snapshot && test ! -e /inspect/verified-files "
        "&& test ! -e /inspect/root-password "
        '&& ! find /inspect -maxdepth 1 \\( -name "config.*" -o -name "directory.*" '
        '-o -name "group-memberships.*" -o -name "user-memberships.*" '
        '-o -name "normalized-memberships.*" '
        '-o -name "password-values.*" \\) | grep -q .',
    )
