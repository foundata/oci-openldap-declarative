"""Managed UUIDs, naming and membership references share one directory identity model."""

from __future__ import annotations

import json
from itertools import combinations
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from jsonschema import Draft202012Validator

from generator import generate
from scripts.directory_data import ConfigurationError
from tests.entry_uuid_cases import ENTRY_UUID_CASES
from tests.password_hash_cases import VALID_HASH

ROOT = Path(__file__).resolve().parents[2]
ALICE_UUID = "003ffd6f-3074-457f-9740-2547970687be"
DISABLED_UUID = "62d4e3af-b3f5-454f-8293-70d7eb92bf85"
GROUP_UUID = "73113c3f-7a96-4268-82a4-fd09154d8364"
BIND_UUID = "843828e3-1e61-4114-b0a1-b0f4914f55a7"
ENTITY_PATHS = ["base", "alice", "inactive", "group", "bind"]


@pytest.fixture
def document() -> dict[str, Any]:
    value: dict[str, Any] = yaml.safe_load(
        (ROOT / "examples/generator/directory.yaml").read_text()
    )
    for entry in [*value["users"], *value["bind_accounts"]]:
        entry.pop("password_file", None)
        if entry.get("active", True):
            entry["password_hash"] = VALID_HASH
    return value


def entity(document: dict[str, Any], name: str) -> dict[str, Any]:
    entries: dict[str, dict[str, Any]] = {
        "base": document,
        "alice": document["users"][0],
        "inactive": document["users"][1],
        "group": document["groups"][0],
        "bind": document["bind_accounts"][0],
    }
    return entries[name]


def parse(tmp_path: Path, document: dict[str, Any]) -> generate.Directory:
    path = tmp_path / "directory.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    path.chmod(0o600)
    return generate.parse_directory(path)


def schema_accepts(document: dict[str, Any]) -> bool:
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    return cast(bool, Draft202012Validator(schema).is_valid(document))


@pytest.mark.parametrize("name", ENTITY_PATHS)
@pytest.mark.parametrize(("entry_uuid", "valid"), ENTRY_UUID_CASES)
def test_explicit_uuid_validation_matches_schema(
    tmp_path: Path, document: dict[str, Any], name: str, entry_uuid: str, valid: bool
) -> None:
    entity(document, name)["entry_uuid"] = entry_uuid
    if name in {"alice", "inactive"}:
        document["groups"][0]["members"] = ["alice", "disabled"]
    assert schema_accepts(document) is valid
    if valid:
        parse(tmp_path, document)
    else:
        with pytest.raises(ConfigurationError, match="entry_uuid"):
            parse(tmp_path, document)


@pytest.mark.parametrize(("first", "second"), list(combinations(ENTITY_PATHS, 2)))
def test_uuid_collisions_include_inactive_and_cross_kind_entries(
    tmp_path: Path, document: dict[str, Any], first: str, second: str
) -> None:
    entity(document, second)["entry_uuid"] = entity(document, first)["entry_uuid"]
    document["groups"][0]["members"] = ["alice"]
    with pytest.raises(ConfigurationError, match=r"duplicate.*entry_uuid"):
        parse(tmp_path, document)


@pytest.mark.parametrize("name", ENTITY_PATHS[1:])
def test_declared_uuid_cannot_collide_with_generated_ou(
    tmp_path: Path, document: dict[str, Any], name: str
) -> None:
    entity(document, name)["entry_uuid"] = generate.container_uuid(
        document["entry_uuid"], "people"
    )
    document["groups"][0]["members"] = ["alice"]
    with pytest.raises(ConfigurationError, match=r"duplicate.*entry_uuid"):
        parse(tmp_path, document)


@pytest.mark.parametrize(
    "members",
    [
        [ALICE_UUID, "disabled"],
        ["alice", DISABLED_UUID],
        [ALICE_UUID.upper(), "DISABLED"],
        ["ALICE", "disabled"],
    ],
)
def test_members_accept_both_references_and_resolve_to_uuids(
    tmp_path: Path, document: dict[str, Any], members: list[str]
) -> None:
    document["groups"][0]["members"] = members
    assert schema_accepts(document)
    parsed = parse(tmp_path, document)
    assert parsed.groups[GROUP_UUID].members == (ALICE_UUID, DISABLED_UUID)
    entries = dict(generate.simplified_entries(parsed))
    group = entries[f"cn=staff,ou=groups,{parsed.base_dn}"]
    assert group["member"] == [f"uid=alice,ou=people,{parsed.base_dn}".encode()]


@pytest.mark.parametrize(
    "members",
    [["alice", ALICE_UUID], ["ALICE", "alice"], [ALICE_UUID.upper(), ALICE_UUID]],
)
def test_different_references_cannot_repeat_a_user(
    tmp_path: Path, document: dict[str, Any], members: list[str]
) -> None:
    document["groups"][0]["members"] = members
    with pytest.raises(ConfigurationError, match="same user"):
        parse(tmp_path, document)


def test_uuid_shaped_username_cannot_make_membership_ambiguous(
    tmp_path: Path, document: dict[str, Any]
) -> None:
    document["users"][2]["username"] = ALICE_UUID
    document["groups"][0]["members"] = [ALICE_UUID]
    with pytest.raises(ConfigurationError, match="ambiguous"):
        parse(tmp_path, document)
    document["groups"][0]["members"] = ["alice"]
    assert parse(tmp_path, document).groups[GROUP_UUID].members == (ALICE_UUID,)


def test_uuid_shaped_username_is_valid_when_both_references_identify_one_user(
    tmp_path: Path, document: dict[str, Any]
) -> None:
    document["users"][0]["username"] = ALICE_UUID
    document["groups"][0]["members"] = [ALICE_UUID]
    assert parse(tmp_path, document).groups[GROUP_UUID].members == (ALICE_UUID,)


@pytest.mark.parametrize("reference", ["unknown", "application", BIND_UUID])
def test_members_only_reference_declared_users(
    tmp_path: Path, document: dict[str, Any], reference: str
) -> None:
    document["groups"][0]["members"] = [reference]
    with pytest.raises(ConfigurationError, match="unknown user"):
        parse(tmp_path, document)


def test_uuid_members_survive_renames_but_username_members_need_updates(
    tmp_path: Path, document: dict[str, Any]
) -> None:
    document["users"][0]["username"] = "alicia"
    parsed = parse(tmp_path, document)
    assert parsed.groups[GROUP_UUID].members[0] == ALICE_UUID
    document["groups"][0]["members"] = ["alice"]
    with pytest.raises(ConfigurationError, match="unknown user"):
        parse(tmp_path, document)
    document["groups"][0]["members"] = ["alicia"]
    assert parse(tmp_path, document).groups[GROUP_UUID].members == (ALICE_UUID,)


@pytest.mark.parametrize("kind", ["users", "bind_accounts"])
@pytest.mark.parametrize("display_name", [None, "Alice Example"])
def test_display_name_supplies_cn_without_renaming_the_entry(
    tmp_path: Path, document: dict[str, Any], kind: str, display_name: str | None
) -> None:
    item = document[kind][0]
    if display_name is None:
        item.pop("display_name", None)
    else:
        item["display_name"] = display_name
    parsed = parse(tmp_path, document)
    entries = dict(generate.simplified_entries(parsed))
    ou = "people" if kind == "users" else "services"
    attributes = entries[f"uid={item['username']},ou={ou},{parsed.base_dn}"]
    assert attributes["entryUUID"] == [item["entry_uuid"].encode()]
    assert attributes["uid"] == [item["username"].encode()]
    assert attributes["cn"] == [(display_name or item["username"]).encode()]
    assert attributes.get("displayName") == (
        [display_name.encode()] if display_name else None
    )
    if kind == "bind_accounts":
        assert b"openldapDeclarativeBindAccount" in attributes["objectClass"]
        assert "sn" not in attributes


@pytest.mark.parametrize("kind", ["users", "bind_accounts"])
@pytest.mark.parametrize(
    "value", [None, "", "Example\n", "Example\r", "Example\x00", 42, "x" * 257]
)
def test_display_name_validation_matches_schema(
    tmp_path: Path, document: dict[str, Any], kind: str, value: Any
) -> None:
    document[kind][0]["display_name"] = value
    assert not schema_accepts(document)
    with pytest.raises(ConfigurationError, match="display_name"):
        parse(tmp_path, document)


def test_names_and_target_changes_do_not_rekey_directory_entries(
    tmp_path: Path, document: dict[str, Any]
) -> None:
    before = dict(generate.simplified_entries(parse(tmp_path, document)))
    document["directory_id"] = "other-target"
    document["users"][0].update(username="alicia", display_name="Alicia Example")
    document["groups"][0]["groupname"] = "employees"
    document["bind_accounts"][0].update(username="reader", display_name="LDAP reader")
    after = dict(generate.simplified_entries(parse(tmp_path, document)))
    assert {tuple(entry["entryUUID"]) for entry in after.values()} == {
        tuple(entry["entryUUID"]) for entry in before.values()
    }
    assert after[document["base_dn"]]["entryUUID"] == [document["entry_uuid"].encode()]
    group = after[f"cn=employees,ou=groups,{document['base_dn']}"]
    assert group["entryUUID"] == [GROUP_UUID.encode()]
    assert group["member"] == [f"uid=alicia,ou=people,{document['base_dn']}".encode()]


@pytest.mark.parametrize("username", ["alice", "ALICE", "disabled"])
def test_user_and_bind_usernames_are_unique_even_for_inactive_users(
    tmp_path: Path, document: dict[str, Any], username: str
) -> None:
    document["bind_accounts"][0]["username"] = username
    with pytest.raises(ConfigurationError, match=r"distinct.*usernames"):
        parse(tmp_path, document)


@pytest.mark.parametrize(
    ("name", "field"),
    [
        ("base", "uuid_namespace"),
        ("alice", "id"),
        ("alice", "uid"),
        ("alice", "common_name"),
        ("group", "id"),
        ("group", "common_name"),
        ("bind", "id"),
        ("bind", "common_name"),
    ],
)
def test_removed_identity_keys_are_not_aliases(
    tmp_path: Path, document: dict[str, Any], name: str, field: str
) -> None:
    entity(document, name)[field] = "old-value"
    assert not schema_accepts(document)
    with pytest.raises(ConfigurationError, match="unknown keys"):
        parse(tmp_path, document)
