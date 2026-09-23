"""Check cleanup ownership and configuration without invoking Podman."""

from __future__ import annotations

import json
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from tests.integration import harness
from tests.integration.harness import Podman, Store


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Store:
    monkeypatch.setattr(harness, "selinux_enforcing", lambda: False)
    store = Store(tmp_path, "unit")
    store.create()
    return store


def test_runtime_paths_and_locks_are_private(isolated: Store) -> None:
    storage = tomllib.loads(isolated.storage_conf.read_text())["storage"]
    engine = tomllib.loads(isolated.containers_conf.read_text())["engine"]
    assert storage["graphroot"] == str(isolated.root)
    assert storage["runroot"] == str(isolated.runroot)
    assert engine["tmp_dir"] == str(isolated.tmpdir)
    assert engine["static_dir"] == str(isolated.root / "libpod")
    assert engine["volume_path"] == str(isolated.root / "volumes")
    assert engine["lock_type"] == "file"
    assert set(isolated.environment()) == {
        "CONTAINERS_STORAGE_CONF",
        "CONTAINERS_CONF_OVERRIDE",
    }


def test_symlinks_never_prove_directory_ownership(isolated: Store) -> None:
    link = isolated.base / "link"
    link.symlink_to(isolated.workspace, target_is_directory=True)
    assert not isolated.owned(link)
    link.unlink()
    link.symlink_to(isolated.base / "missing", target_is_directory=True)
    assert not isolated.owned(link)


@pytest.mark.parametrize("platform", [None, "", "linux/amd64", "linux/arm64"])
@pytest.mark.parametrize(
    "arguments",
    [
        ("run", "image"),
        ("create", "image"),
        ("exec", "container", "true"),
        ("inspect", "container"),
        ("build", "."),
        ("volume", "create", "volume"),
        ("pod", "create", "--name", "pod"),
    ],
)
def test_platform_is_forwarded_only_when_launching_containers(
    isolated: Store,
    monkeypatch: pytest.MonkeyPatch,
    platform: str | None,
    arguments: tuple[str, ...],
) -> None:
    if platform is None:
        monkeypatch.delenv("CC_PLATFORM", raising=False)
    else:
        monkeypatch.setenv("CC_PLATFORM", platform)
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(shutil, "which", lambda name: "/unused/podman")
    monkeypatch.setattr(subprocess, "run", run)
    Podman(isolated).run(*arguments)
    assert len(calls) == 1
    command = calls[0]
    if platform and arguments[0] in {"run", "create"}:
        assert command.count("--platform") == 1
        assert command[command.index("--platform") + 1] == platform
    else:
        assert "--platform" not in command
    if arguments[0] in {"run", "create"}:
        assert command[command.index("--label") + 1] == (
            f"{harness.OWNER_LABEL}={isolated.run_key}"
        )


@pytest.mark.parametrize("resource", ["container", "volume"])
def test_cleanup_refuses_unlabelled_resources_before_deletion(
    isolated: Store, monkeypatch: pytest.MonkeyPatch, resource: str
) -> None:
    isolated.record(resource, "known-name")
    calls: list[tuple[str, ...]] = []

    def output(self: Podman, *arguments: str, **kwargs: object) -> str:
        if arguments[0] == "ps":
            return json.dumps(
                [{"Id": "container-id"}] if resource == "container" else []
            )
        if arguments[:2] == ("volume", "ls"):
            return json.dumps(
                [{"Name": "known-name", "Labels": {}}] if resource == "volume" else []
            )
        assert arguments == ("inspect", "container-id")
        return json.dumps([{"Name": "known-name", "Config": {"Labels": {}}}])

    def run(
        self: Podman, *arguments: str, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return subprocess.CompletedProcess(list(arguments), 0, "", "")

    monkeypatch.setattr(shutil, "which", lambda name: "/unused/podman")
    monkeypatch.setattr(Podman, "output", output)
    monkeypatch.setattr(Podman, "run", run)
    with pytest.raises(pytest.fail.Exception, match=f"unowned {resource}"):
        isolated.finish("/unused/podman")
    assert calls == []
    assert isolated.workspace.is_dir()


def test_cleanup_removes_owned_namespace_dependents_first(
    isolated: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("wiki", "ldap"):
        isolated.record("container", name)
    existing = {"wiki-id", "ldap-id"}
    removals: list[tuple[str, ...]] = []

    def output(self: Podman, *arguments: str, **kwargs: object) -> str:
        if arguments[0] == "ps":
            return json.dumps([{"Id": "wiki-id"}, {"Id": "ldap-id"}])
        if arguments[:2] == ("volume", "ls"):
            return "[]"
        assert arguments[0] == "inspect"
        return json.dumps(
            [
                {
                    "Name": arguments[1].removesuffix("-id"),
                    "Config": {"Labels": {harness.OWNER_LABEL: isolated.run_key}},
                }
            ]
        )

    def run(
        self: Podman, *arguments: str, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        code = 0
        if arguments[:2] == ("container", "exists"):
            code = 0 if arguments[2] in existing else 1
        elif arguments[0] == "rm":
            removals.append(arguments)
            assert arguments == ("rm", "--force", "--depend", "--", "wiki-id")
            existing.clear()
        else:
            assert arguments[0] == "unshare"
        return subprocess.CompletedProcess(list(arguments), code, "", "")

    monkeypatch.setattr(shutil, "which", lambda name: "/unused/podman")
    monkeypatch.setattr(Podman, "output", output)
    monkeypatch.setattr(Podman, "run", run)
    isolated.finish("/unused/podman")
    assert len(removals) == 1
    assert not isolated.workspace.exists()
