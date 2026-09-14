"""Check the documented network and shared-pod variants with Quadlet's parser."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parents[2] / "examples/quadlet"
GENERATOR = Path("/usr/lib/systemd/user-generators/podman-user-generator")


@pytest.mark.parametrize("shared_pod", [False, True])
def test_quadlet_uses_shared_environment_and_namespace_owner(
    tmp_path: Path, shared_pod: bool
) -> None:
    if not GENERATOR.is_file():
        pytest.skip("Quadlet generator is not installed")
    for path in EXAMPLES.iterdir():
        if path.suffix in {".container", ".volume", ".network", ".pod"}:
            shutil.copyfile(path, tmp_path / path.name)
    definition = tmp_path / "openldap-example.container"
    if shared_pod:
        source = definition.read_text()
        for line in (
            "UserNS=keep-id:uid=1001,gid=1001\n",
            "Network=openldap-example.network\n",
            "NetworkAlias=ldap\n",
        ):
            assert line in source
            source = source.replace(line, "")
        definition.write_text(
            source.replace("[Container]\n", "[Container]\nPod=example-app.pod\n")
        )
    result = subprocess.run(
        [str(GENERATOR), "-user", "-dryrun"],
        env={**os.environ, "QUADLET_UNIT_DIRS": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    command = next(
        line.removeprefix("ExecStart=")
        for line in result.stdout.splitlines()
        if line.startswith("ExecStart=") and "--name openldap-example " in line
    )
    arguments = shlex.split(command)
    assert arguments[arguments.index("--env-file") + 1].endswith(
        "/example-app/ldap.env"
    )
    assert arguments[arguments.index("--user") + 1] == "1001:1001"
    if shared_pod:
        assert "--pod" in arguments or "--pod-id-file" in arguments
        assert "--network" not in arguments and "--userns" not in arguments
    else:
        assert arguments[arguments.index("--userns") + 1] == "keep-id:uid=1001,gid=1001"
        assert arguments[arguments.index("--network") + 1] == "openldap-example"
