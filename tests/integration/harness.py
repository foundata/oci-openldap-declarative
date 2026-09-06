"""Isolated Podman storage, resource journaling and exact image inputs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

COMMAND_TIMEOUT = 300
BUILD_TIMEOUT = 1800
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
OWNER_MARKER = ".openldap-test-owner"


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selinux_enforcing() -> bool:
    enforce = Path("/sys/fs/selinux/enforce")
    try:
        return enforce.read_text(encoding="utf-8").strip() == "1"
    except OSError:
        return False


@dataclass
class Store:
    """One run's isolated Podman storage below an external base directory."""

    base: Path
    suite: str
    run_key: str = field(init=False)
    prefix: str = field(init=False)
    manifest: Path = field(init=False)
    workspace: Path = field(init=False)
    root: Path = field(init=False)
    runroot: Path = field(init=False)
    storage_conf: Path = field(init=False)

    def __post_init__(self) -> None:
        key_input = f"{self.base}/{self.suite}".encode()
        self.run_key = hashlib.sha256(key_input).hexdigest()[:12]
        self.prefix = f"openldap-{self.suite}-{self.run_key}"
        self.manifest = self.base / f"{self.suite}-resources.md"
        self.workspace = self.base / f"{self.suite}-workspace"
        self.root = self.base / f"{self.suite}-podman-root"
        self.runroot = self.base / f"{self.suite}-podman-runroot"
        self.storage_conf = self.base / f"{self.suite}-storage.conf"

    def create(self) -> None:
        planned = (
            self.manifest,
            self.workspace,
            self.root,
            self.runroot,
            self.storage_conf,
        )
        for path in planned:
            if path.exists() or path.is_symlink():
                pytest.fail(f"refusing to reuse test path: {path}")
        os.umask(0o077)
        self.manifest.write_text(
            "# OpenLDAP integration resource manifest\n\n"
            f"Run key: {self.run_key}\n\n"
            "Timestamp | Kind | Identifier\n--- | --- | ---\n",
            encoding="utf-8",
        )
        self.record("directory", str(self.workspace))
        self.workspace.mkdir(mode=0o700)
        (self.workspace / OWNER_MARKER).write_text(
            f"{self.run_key}\n", encoding="utf-8"
        )
        self.record("podman-storage", str(self.root))
        self.record("podman-runroot", str(self.runroot))
        for path in (self.root, self.runroot):
            path.mkdir(mode=0o700)
            (path / OWNER_MARKER).write_text(f"{self.run_key}\n", encoding="utf-8")
        self._label_storage()
        self.storage_conf.write_text(
            "[storage]\n"
            'driver = "overlay"\n'
            f'graphroot = "{self.root}"\n'
            f'runroot = "{self.runroot}"\n',
            encoding="utf-8",
        )

    def _label_storage(self) -> None:
        if not selinux_enforcing():
            return
        reference = Path.home() / ".local/share/containers/storage/overlay"
        if not reference.is_dir() or reference.is_symlink():
            pytest.fail(f"SELinux reference storage is unavailable: {reference}")
        for name in (
            "artifacts",
            "overlay",
            "overlay-containers",
            "overlay-images",
            "overlay-layers",
        ):
            path = self.root / name
            path.mkdir(mode=0o700)
            subprocess.run(
                ["chcon", f"--reference={reference}", str(path)],
                check=True,
                timeout=COMMAND_TIMEOUT,
            )

    def record(self, kind: str, identifier: str) -> None:
        with self.manifest.open("a", encoding="utf-8") as stream:
            stream.write(f"{iso_timestamp(utc_now())} | {kind} | {identifier}\n")

    def owned(self, path: Path) -> bool:
        marker = path / OWNER_MARKER
        if not path.is_dir() or path.is_symlink():
            return True
        if not marker.is_file() or marker.is_symlink():
            return False
        return marker.read_text(encoding="utf-8").strip() == self.run_key

    def inspect_command(self) -> str:
        return f"podman --root {self.root} --runroot {self.runroot} ps --all"

    def finish(self, podman_binary: str) -> None:
        for path in (self.workspace, self.root, self.runroot):
            if not self.owned(path):
                pytest.fail(
                    f"refusing to remove path without the run ownership marker: {path}"
                )
        subprocess.run(
            [
                podman_binary,
                "--root",
                str(self.root),
                "--runroot",
                str(self.runroot),
                "system",
                "reset",
                "--force",
            ],
            check=True,
            capture_output=True,
            timeout=COMMAND_TIMEOUT,
        )
        for path in (self.workspace, self.root, self.runroot):
            shutil.rmtree(path, ignore_errors=True)
        self.storage_conf.unlink(missing_ok=True)


class Podman:
    """Run Podman against the isolated store and journal created resources."""

    def __init__(self, store: Store) -> None:
        binary = shutil.which("podman")
        if binary is None:
            pytest.fail("podman is not available")
        self.binary = binary
        self.store = store

    def run(
        self,
        *arguments: str,
        check: bool = True,
        timeout: int = COMMAND_TIMEOUT,
        stdin: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            self.binary,
            "--root",
            str(self.store.root),
            "--runroot",
            str(self.store.runroot),
            *arguments,
        ]
        completed = subprocess.run(
            command,
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if check and completed.returncode != 0:
            pytest.fail(
                f"podman {' '.join(arguments)} failed with status "
                f"{completed.returncode}\n{completed.stdout}\n{completed.stderr}"
            )
        return completed

    def output(self, *arguments: str, timeout: int = COMMAND_TIMEOUT) -> str:
        return self.run(*arguments, timeout=timeout).stdout.strip()

    def transient_name(self) -> str:
        name = f"{self.store.prefix}-run-{secrets.token_hex(6)}"
        self.plan_container(name)
        return name

    def run_container(
        self,
        *arguments: str,
        check: bool = True,
        timeout: int = COMMAND_TIMEOUT,
        stdin: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a named, journaled container from `podman run` arguments."""
        return self.run(
            "run",
            "--name",
            self.transient_name(),
            *arguments,
            check=check,
            timeout=timeout,
            stdin=stdin,
        )

    def plan_container(self, name: str) -> None:
        if self.run("container", "exists", name, check=False).returncode == 0:
            pytest.fail(f"Podman container name collision: {name}")
        self.store.record("container", name)

    def plan_volume(self, name: str) -> None:
        if self.run("volume", "exists", name, check=False).returncode == 0:
            pytest.fail(f"Podman volume name collision: {name}")
        self.store.record("volume", name)

    def create_volume(self, name: str) -> None:
        self.plan_volume(name)
        self.run("volume", "create", name)

    def volume_exists(self, name: str) -> bool:
        return self.run("volume", "exists", name, check=False).returncode == 0

    def container_exists(self, name: str) -> bool:
        return self.run("container", "exists", name, check=False).returncode == 0

    def logs(self, name: str) -> str:
        completed = self.run("logs", name, check=False)
        return completed.stdout + completed.stderr

    def inspect(self, name: str, template: str) -> str:
        return self.output("inspect", name, "--format", template)

    def state(self, name: str) -> str:
        return self.inspect(name, "{{.State.Status}}")

    def wait(self, name: str, timeout: int = 180) -> int:
        completed = self.run("wait", name, timeout=timeout)
        return int(completed.stdout.strip())

    def stop(self, name: str, seconds: int = 3) -> None:
        self.run("stop", "--time", str(seconds), name)

    def exec(
        self, name: str, *arguments: str, check: bool = True, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            "exec",
            *(["-i"] if stdin is not None else []),
            name,
            *arguments,
            check=check,
            stdin=stdin,
        )

    def exec_output(self, name: str, *arguments: str) -> str:
        return self.exec(name, *arguments).stdout

    def import_image(
        self, role: str, image_id: str, image_name: str, input_manifest: Path
    ) -> None:
        """Import one exact OCI layout named by the ConClear input manifest."""
        with input_manifest.open(encoding="utf-8") as stream:
            document = json.load(stream)
        if role == "primary":
            record = document["primary"]
        else:
            candidates = [
                item for item in document["dependencies"] if item["imageId"] == image_id
            ]
            if len(candidates) != 1:
                pytest.fail(f"exact image input is missing: {image_id}")
            record = candidates[0]
        if record["imageId"] != image_id:
            pytest.fail(f"exact image input has the wrong image ID: {image_id}")
        layout = Path(record["layout"])
        expected_digest = record["digest"]
        if not layout.is_dir() or not DIGEST_PATTERN.match(expected_digest):
            pytest.fail(f"exact image input is malformed: {image_id}")
        self.store.record("oci-layout", f"{layout}@{expected_digest}")
        self.store.record("imported-image", image_name)
        pulled = self.output(
            "pull", "--quiet", f"oci:{layout}:qualified", timeout=BUILD_TIMEOUT
        )
        identifier = pulled.splitlines()[-1]
        self.run("tag", identifier, image_name)
        observed = self.inspect_image(image_name, "{{.Digest}}")
        if observed != expected_digest:
            pytest.fail(
                f"imported digest {observed} differs from declared digest "
                f"{expected_digest}"
            )

    def inspect_image(self, image_name: str, template: str) -> str:
        return self.output("image", "inspect", image_name, "--format", template)

    def build_image(
        self, image_name: str, project: Path, containerfile: Path | None = None
    ) -> None:
        revision = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=COMMAND_TIMEOUT,
        ).stdout.strip()
        self.store.record("developer-image", image_name)
        file_arguments = ["--file", str(containerfile)] if containerfile else []
        self.run(
            "build",
            "--pull=always",
            "--tag",
            image_name,
            *file_arguments,
            "--build-arg",
            f"IMAGE_CREATED={iso_timestamp(utc_now())}",
            "--build-arg",
            f"IMAGE_REVISION={revision}",
            "--build-arg",
            "IMAGE_VERSION=developer-test",
            str(project),
            timeout=BUILD_TIMEOUT,
        )
