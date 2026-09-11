"""Test additive YAML extensions independently of installed OpenLDAP schemas."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import ldap
import pytest
import yaml
from jsonschema import Draft202012Validator

from generator import export_schema as schema_export
from generator import extensions, generate
from generator.export_schema import export_schema
from generator.extensions import Extensions, SchemaCatalog, parse_extensions
from generator.vault import DecryptedString, Vault
from scripts.directory_data import ConfigurationError, parse_ldif
from tests.password_hash_cases import VALID_HASH

ROOT = Path(__file__).resolve().parents[2]
BASE_ATTRIBUTES = (
    "( 2.5.4.41 NAME 'name' )",
    "( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
    "( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name )",
    "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) )",
    "( 2.5.4.35 NAME 'userPassword' )",
    "( 2.5.4.31 NAME 'member' )",
    "( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) )",
    "( 2.5.4.13 NAME 'description' )",
    "( 2.16.840.1.113730.3.1.3 NAME ( 'employeeNumber' 'employeeId' ) SINGLE-VALUE )",
    "( 2.16.840.1.113730.3.1.39 NAME 'preferredLanguage' SINGLE-VALUE )",
    "( 0.9.2342.19200300.100.1.41 NAME 'mobile' )",
    "( 1.3.6.1.1.1.1.0 NAME 'uidNumber' SINGLE-VALUE )",
    "( 1.3.6.1.1.1.1.1 NAME 'gidNumber' SINGLE-VALUE )",
    "( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' SINGLE-VALUE )",
)
BASE_CLASSES = (
    "( 2.5.6.0 NAME 'top' ABSTRACT )",
    "( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' SUP top AUXILIARY )",
    "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP top STRUCTURAL )",
    "( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL )",
    "( 2.5.6.8 NAME 'organizationalRole' SUP top STRUCTURAL )",
    "( 0.9.2342.19200300.100.4.19 NAME 'simpleSecurityObject' SUP top AUXILIARY )",
    "( 1.3.6.1.1.1.2.0 NAME ( 'posixAccount' 'posixAlias' ) SUP top AUXILIARY )",
)


def schema_file(
    path: Path, attributes: tuple[str, ...] = (), classes: tuple[str, ...] = ()
) -> Path:
    path.write_text(
        "dn: cn=test,cn=schema,cn=config\nobjectClass: olcSchemaConfig\ncn: test\n"
        + "".join(f"olcAttributeTypes: {value}\n" for value in attributes)
        + "".join(f"olcObjectClasses: {value}\n" for value in classes)
        + "\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SchemaCatalog:
    path = schema_file(tmp_path / "builtin.ldif", BASE_ATTRIBUTES, BASE_CLASSES)
    monkeypatch.setattr(extensions, "BUILTIN_SCHEMA_FILES", (path,))
    return SchemaCatalog(())


def document() -> dict[str, Any]:
    value: dict[str, Any] = yaml.safe_load(
        (ROOT / "examples/generator/directory.yaml").read_text()
    )
    for entry in [*value["users"], *value["bind_accounts"]]:
        entry.pop("password_file", None)
        if entry.get("active", True):
            entry["password_hash"] = VALID_HASH
    return value


def parse_document(
    path: Path, value: dict[str, Any], vault: Vault | None = None
) -> generate.Directory:
    path.write_text(yaml.safe_dump(value), encoding="utf-8")
    path.chmod(0o600)
    return generate.parse_directory(path, vault)


@pytest.mark.parametrize("kind", ["users", "groups", "bind_accounts"])
def test_extensions_work_on_each_entity(
    catalog: SchemaCatalog, tmp_path: Path, kind: str
) -> None:
    value = document()
    value[kind][0]["attributes"] = {"mobile": ["+49 123", "+49 456"]}
    value[kind][0]["object_classes"] = ["posixAccount"]
    validator = Draft202012Validator(
        json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    )
    validator.validate(value)
    parsed = parse_document(tmp_path / "directory.yaml", value)
    generated = generate.simplified_entries(parsed)
    matches = [attributes for _, attributes in generated if "mobile" in attributes]
    assert len(matches) == 1
    assert matches[0]["mobile"] == [b"+49 123", b"+49 456"]
    assert b"posixAccount" in matches[0]["objectClass"]


@pytest.mark.parametrize(
    "value",
    [
        {"attributes": None},
        {"attributes": []},
        {"attributes": {"mobile": "+49 123"}},
        {"attributes": {"mobile": []}},
        {"attributes": {"mobile": [None]}},
        {"attributes": {"mobile": [True]}},
        {"attributes": {"mobile": [10001]}},
        {"attributes": {"mobile": [{}]}},
        {"attributes": {"mobile": [""]}},
        {"attributes": {"mobile": ["private\nvalue"]}},
        {"attributes": {"mobile": ["private\n"]}},
        {"attributes": {"mobile": ["private\rvalue"]}},
        {"attributes": {"mobile": ["private\x00value"]}},
        {"attributes": {"mobile": ["x" * 4097]}},
        {"attributes": {"mobile": ["duplicate", "duplicate"]}},
        {"attributes": {"mobile": [str(index) for index in range(65)]}},
        {"attributes": {f"attribute{index}": ["a"] for index in range(129)}},
        {"attributes": {"mobile;lang-en": ["a"]}},
        {"attributes": {"mobile\n": ["a"]}},
        {"attributes": {"*": ["a"]}},
        {"object_classes": None},
        {"object_classes": "posixAccount"},
        {"object_classes": [True]},
        {"object_classes": ["posixAccount", "posixAccount"]},
        {"object_classes": [f"class{index}" for index in range(17)]},
    ],
)
def test_invalid_shapes_fail_parser_and_json_schema(value: dict[str, Any]) -> None:
    with pytest.raises(ConfigurationError) as failure:
        parse_extensions(value, context="users[0]")
    assert "private" not in str(failure.value)
    source = document()
    source["users"][0].update(value)
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    assert not Draft202012Validator(schema).is_valid(source)


@pytest.mark.parametrize(
    "name",
    [
        "cn",
        "CN",
        "commonName",
        "2.5.4.3",
        "surname",
        "userid",
        "objectClass",
        "2.5.4.0",
        "entryUUID",
        "1.3.6.1.1.16.4",
        "member",
        "2.5.4.31",
        "memberOf",
        "1.2.840.113556.1.2.102",
        "userPassword",
        "2.5.4.35",
        "olcAccess",
        "mail",
        "rfc822Mailbox",
        "description",
        "proxyAddresses",
        "telephoneNumber",
        "givenName",
    ],
)
def test_reserved_attributes_and_aliases_are_rejected(
    catalog: SchemaCatalog, tmp_path: Path, name: str
) -> None:
    value = document()
    value["users"][0].pop("mail")
    value["users"][0]["attributes"] = {name: ["PRIVATE-MARKER"]}
    with pytest.raises(ConfigurationError, match="reserved") as failure:
        parse_document(tmp_path / "directory.yaml", value)
    assert "PRIVATE-MARKER" not in str(failure.value)


@pytest.mark.parametrize(
    ("attributes", "classes", "message"),
    [
        ({"unknownAttribute": ["x"]}, [], "unknown attribute"),
        ({"employeeNumber": ["x"], "employeeId": ["y"]}, [], "attribute alias"),
        ({"employeeNumber": ["x", "y"]}, [], "single-valued"),
        ({}, ["unknownClass"], "unknown class"),
        ({}, ["inetOrgPerson"], "auxiliary"),
        ({}, ["top"], "auxiliary"),
        ({}, ["extensibleObject"], "extensibleObject"),
        ({}, ["1.3.6.1.4.1.1466.101.120.111"], "extensibleObject"),
        ({}, ["posixAccount", "posixAlias"], "class or alias"),
    ],
)
def test_schema_aware_rejections(
    catalog: SchemaCatalog,
    attributes: dict[str, tuple[str, ...]],
    classes: list[str],
    message: str,
) -> None:
    with pytest.raises(ConfigurationError, match=message):
        catalog.validate(
            Extensions(attributes, tuple(classes)),
            reserved={"cn"},
            base_classes=("top", "inetOrgPerson"),
            context="users[0]",
        )


@pytest.mark.parametrize(
    "definition",
    [
        "( 1.2.3 NAME 'privateAttribute' SUP userPassword )",
        "( 1.2.3 NAME 'privateAttribute' SUP commonName )",
        "( 1.2.3 NAME 'privateAttribute' NO-USER-MODIFICATION )",
        "( 1.2.3 NAME 'privateAttribute' USAGE directoryOperation )",
        "( 1.2.3 NAME 'privateAttribute' COLLECTIVE )",
        "( 1.2.3 NAME 'privateAttribute' SUP privateAttribute )",
        "( 1.2.3 NAME 'privateAttribute' SUP unknownAttribute )",
        "( 1.3.6.1.1.16.4 NAME 'privateAttribute' )",
        "( 1.2.3 NAME ( 'privateAttribute' 'olcExample' ) )",
    ],
)
def test_custom_attribute_cannot_bypass_protection(
    catalog: SchemaCatalog, tmp_path: Path, definition: str
) -> None:
    path = schema_file(tmp_path / "custom.ldif", (definition,))
    with pytest.raises(ConfigurationError):
        SchemaCatalog((path,)).validate(
            Extensions({"privateAttribute": ("PRIVATE-MARKER",)}),
            reserved={"cn"},
            base_classes=("top", "inetOrgPerson"),
            context="users[0]",
        )


@pytest.mark.parametrize(
    "superior", ["extensibleObject", "inetOrgPerson", "unknown", "customClass"]
)
def test_invalid_auxiliary_class_ancestry(
    catalog: SchemaCatalog, tmp_path: Path, superior: str
) -> None:
    path = schema_file(
        tmp_path / "custom.ldif",
        classes=(f"( 1.2.3 NAME 'customClass' SUP {superior} AUXILIARY )",),
    )
    with pytest.raises(ConfigurationError):
        SchemaCatalog((path,)).validate(
            Extensions(object_classes=("customClass",)),
            reserved={"cn"},
            base_classes=("top", "inetOrgPerson"),
            context="users[0]",
        )


def test_custom_schema_paths_and_inherited_attributes(
    catalog: SchemaCatalog, tmp_path: Path
) -> None:
    schema_file(
        tmp_path / "custom.ldif",
        ("( 1.2.3 NAME 'customAttribute' SUP mobile )",),
        ("( 1.2.4 NAME 'customClass' SUP top AUXILIARY MAY customAttribute )",),
    )
    value = document()
    value["schema_files"] = ["custom.ldif"]
    value["users"][0]["attributes"] = {"customAttribute": ["one", "two"]}
    value["users"][0]["object_classes"] = ["customClass"]
    parsed = parse_document(tmp_path / "directory.yaml", value)
    assert parsed.users["person-0001"].extensions.attributes == {
        "customAttribute": ("one", "two")
    }


def test_vault_values_are_decrypted_before_extension_validation(
    catalog: SchemaCatalog, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        Vault, "decrypt", lambda *_: DecryptedString("private employee")
    )
    value = document()
    value["users"][0]["attributes"] = {"employeeNumber": ["PLACEHOLDER"]}
    path = tmp_path / "directory.yaml"
    path.write_text(
        yaml.safe_dump(value).replace("- PLACEHOLDER", "- !vault encrypted")
    )
    path.chmod(0o600)
    parsed = generate.parse_directory(path)
    assert parsed.users["person-0001"].extensions.attributes["employeeNumber"] == (
        "private employee",
    )


def test_group_description_and_empty_extensions_preserve_existing_entries(
    catalog: SchemaCatalog, tmp_path: Path
) -> None:
    value = document()
    before = generate.simplified_entries(
        parse_document(tmp_path / "directory.yaml", value)
    )
    for entry in [*value["users"], *value["groups"], *value["bind_accounts"]]:
        entry.update(attributes={}, object_classes=[])
    parsed = parse_document(tmp_path / "directory.yaml", value)
    assert generate.simplified_entries(parsed) == before
    value["groups"][0]["attributes"] = {"description": ["A group"]}
    parsed = parse_document(tmp_path / "directory.yaml", value)
    assert parsed.groups["group-staff"].extensions.attributes["description"] == (
        "A group",
    )


def test_ordered_schema_values_and_build_only_export(
    catalog: SchemaCatalog, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = {
        "attributeTypes": [b"{0}( 1.2.3 NAME 'example' )"],
        "objectClasses": [b"{0}( 1.2.4 NAME 'exampleClass' AUXILIARY MAY example )"],
        "creatorsName": [b"cn=config"],
        "olcRootPW": [b"MUST-NOT-EXPORT"],
    }
    destination = tmp_path / "builtin.ldif"
    export_schema(source, destination)
    exported = destination.read_text()
    assert "MUST-NOT-EXPORT" not in exported and "creatorsName" not in exported
    assert "cn=openldap,cn=schema,cn=config" in exported
    monkeypatch.setattr(extensions, "BUILTIN_SCHEMA_FILES", (destination,))
    SchemaCatalog(()).validate(
        Extensions({"example": ("value",)}, ("exampleClass",)),
        reserved=set(),
        base_classes=(),
        context="users[0]",
    )


def test_build_only_export_requires_schema_definitions(tmp_path: Path) -> None:
    with pytest.raises(KeyError):
        export_schema({}, tmp_path / "builtin.ldif")


@pytest.mark.parametrize(
    "definition",
    [
        "( 2.5.4.3 NAME 'hijackedCn' )",
        "( 1.2.3 NAME 'commonName' )",
        "not a schema definition",
    ],
)
def test_schema_redefinition_is_rejected_without_echoing_payload(
    catalog: SchemaCatalog, tmp_path: Path, definition: str
) -> None:
    source = schema_file(tmp_path / "conflict.ldif", (definition,))
    with pytest.raises(ConfigurationError, match="invalid or conflicting") as failure:
        SchemaCatalog((source,))
    assert definition not in str(failure.value)


def test_snapshot_uses_the_schema_contents_that_were_validated(
    catalog: SchemaCatalog, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = schema_file(
        tmp_path / "custom.ldif",
        ("( 1.2.3 NAME 'customAttribute' SUP mobile )",),
        ("( 1.2.4 NAME 'customClass' SUP top AUXILIARY MAY customAttribute )",),
    )
    original = path.read_bytes()
    source = document()
    source["schema_files"] = [path.name]
    source["users"][0]["attributes"] = {"customAttribute": ["value"]}
    source["users"][0]["object_classes"] = ["customClass"]
    parsed = parse_document(tmp_path / "directory.yaml", source)
    path.write_text("changed after validation\n")
    destination = tmp_path / "snapshot"
    destination.mkdir(mode=0o700)
    monkeypatch.setattr(generate, "sign_manifest", lambda *_: None)
    generate.generate_snapshot(
        destination, parsed, tmp_path / "unused.key", datetime.now(UTC)
    )
    assert parse_ldif((destination / "schema-00.ldif").read_bytes()) == parse_ldif(
        original
    )


@pytest.mark.parametrize("failure", ["none", "connect", "search", "timeout"])
def test_build_only_server_is_private_and_always_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    process = Mock()
    process.poll.return_value = None
    factory = Mock(return_value=process)
    connection = Mock()
    connection.search_s.return_value = [
        (
            "cn=Subschema",
            {
                "attributeTypes": [b"( 1.2 NAME 'example' )"],
                "objectClasses": [b"( 1.3 NAME 'exampleClass' AUXILIARY )"],
            },
        )
    ]
    initialize = Mock(return_value=connection)
    monkeypatch.setattr("generator.export_schema.subprocess.Popen", factory)
    monkeypatch.setattr("generator.export_schema.ldap.initialize", initialize)
    monkeypatch.setattr(schema_export, "SCHEMAS", ())
    if failure == "connect":
        initialize.side_effect = ldap.SERVER_DOWN
    elif failure == "search":
        connection.search_s.return_value = []
    elif failure == "timeout":
        monkeypatch.setattr(
            "generator.export_schema.time.monotonic", Mock(side_effect=[0, 100])
        )
        process.wait.side_effect = [subprocess.TimeoutExpired("slapd", 10), 0]
    if failure == "none":
        schema_export.collect_schema(tmp_path)
        assert (tmp_path / "openldap.ldif").is_file()
        assert json.loads((tmp_path / "source-checksums.json").read_text()) == {}
    else:
        with pytest.raises((ldap.SERVER_DOWN, RuntimeError)):
            schema_export.collect_schema(tmp_path)
    command = factory.call_args.args[0]
    assert command[command.index("-h") + 1].startswith("ldapi://%2F")
    assert not Path(command[command.index("-f") + 1]).parent.exists()
    process.terminate.assert_called_once()
    if failure == "timeout":
        process.kill.assert_called_once()
    process.wait.assert_called()
