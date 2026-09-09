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
