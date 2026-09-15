"""Initialization publishes valid private definitions without replacing user files."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
import yaml

from generator.generate import parse_directory
from generator.initialize import initialize
from scripts.directory_data import ConfigurationError

SETTINGS = {"directory_id": "test-app", "base_dn": "dc=example,dc=org"}


# Verifies: IP0008
def test_initialize_generates_valid_fresh_identities(tmp_path: Path) -> None:
    seen: set[str] = set()
    for name in ("first.yaml", "second.yaml"):
        path = tmp_path / name
        initialize(path, **SETTINGS)
        assert path.stat().st_mode & 0o777 == 0o600
        directory = parse_directory(path)
        identifiers = {
            directory.entry_uuid,
            *directory.users,
            *directory.groups,
            *directory.bind_accounts,
        }
        assert len(identifiers) == 4 and None not in identifiers
        assert not identifiers & seen
        for identifier in identifiers:
            assert identifier is not None and uuid.UUID(identifier).version == 4
            seen.add(identifier)
        user = next(iter(directory.users.values()))
        group = next(iter(directory.groups.values()))
        assert group.members == (user.entry_uuid,)
        source = yaml.safe_load(path.read_text())
        assert source["users"][0]["password_hash_file"] == "/run/credentials/alice.hash"
        assert (
            source["bind_accounts"][0]["password_hash_file"]
            == "/run/credentials/application.hash"
        )
        assert (
            "password:" not in path.read_text()
            and "password_hash:" not in path.read_text()
        )
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "first.yaml",
        "second.yaml",
    ]


@pytest.mark.parametrize("kind", ["file", "directory", "symlink", "dangling"])
# Verifies: IP0008
def test_initialize_never_overwrites(tmp_path: Path, kind: str) -> None:
    target = tmp_path / "target"
    target.write_text("keep")
    output = tmp_path / "directory.yaml"
    if kind == "file":
        output.write_text("existing")
    elif kind == "directory":
        output.mkdir()
    else:
        output.symlink_to(target if kind == "symlink" else tmp_path / "missing")
    with pytest.raises(ConfigurationError, match="already exists"):
        initialize(output, **SETTINGS)
    assert target.read_text() == "keep"
    if kind == "file":
        assert output.read_text() == "existing"
    assert not list(tmp_path.glob(".openldap-init-*"))


@pytest.mark.parametrize(
    "settings",
    [
        {"directory_id": "invalid target"},
        {"base_dn": "o=Example"},
        {"base_dn": "broken"},
        {"organization": ""},
        {"username": "../unsafe"},
        {"bind_username": "ALICE"},
        {"groupname": "unsafe/name"},
    ],
)
# Verifies: IP0008
def test_initialize_invalid_settings_leave_no_output(
    tmp_path: Path, settings: dict[str, str]
) -> None:
    with pytest.raises(ConfigurationError):
        initialize(tmp_path / "directory.yaml", **(SETTINGS | settings))
    assert not list(tmp_path.iterdir())


# Verifies: IP0008
def test_initialize_concurrent_creator_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = os.link

    def race(source: str, destination: Path) -> None:
        destination.write_text("concurrent definition")
        original(source, destination)

    monkeypatch.setattr(os, "link", race)
    output = tmp_path / "directory.yaml"
    with pytest.raises(ConfigurationError, match="already exists"):
        initialize(output, **SETTINGS)
    assert output.read_text() == "concurrent definition"
    assert list(tmp_path.iterdir()) == [output]
