"""Shared LDIF validation for generator input and signed runtime snapshots."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.directory_data import (
    ConfigurationError,
    Entry,
    parse_ldif,
    validate_entries,
    validate_schema,
    write_ldif,
)

EXAMPLES = Path(__file__).resolve().parents[2] / "examples/generator"


def native() -> list[Entry]:
    return parse_ldif((EXAMPLES / "native.ldif").read_bytes())


def test_native_entries_preserve_uuid4_and_custom_attributes(tmp_path: Path) -> None:
    entries = native()
    validate_entries(entries, "o=Example")
    output = tmp_path / "directory.ldif"
    write_ldif(output, entries)
    assert parse_ldif(output.read_bytes()) == entries
    assert b"TEST DATA ONLY" not in output.read_bytes()
    validate_schema(parse_ldif((EXAMPLES / "device-schema.ldif").read_bytes()))


@pytest.mark.parametrize(
    "damage",
    [
        "missing-uuid",
        "duplicate-uuid",
        "duplicate-dn",
        "outside-base",
        "missing-parent",
        "missing-base",
        "config",
        "plaintext",
        "password-oid",
        "password-option",
        "uuid-case",
    ],
)
def test_invalid_native_entries_fail_without_echoing_values(damage: str) -> None:
    entries = native()
    attributes = entries[2][1]
    if damage == "missing-uuid":
        del attributes["entryuuid"]
    elif damage == "duplicate-uuid":
        attributes["entryuuid"] = entries[0][1]["entryuuid"]
    elif damage == "duplicate-dn":
        entries.append(copy.deepcopy(entries[2]))
    elif damage == "outside-base":
        entries[2] = ("cn=TOP-SECRET,o=elsewhere", attributes)
    elif damage == "missing-parent":
        del entries[1]
    elif damage == "missing-base":
        del entries[0]
    elif damage == "config":
        attributes["olcmoduleload"] = [b"TOP-SECRET"]
    elif damage == "uuid-case":
        attributes["entryuuid"] = [attributes["entryuuid"][0].upper()]
    else:
        key = {
            "plaintext": "userpassword",
            "password-oid": "2.5.4.35",
            "password-option": "userpassword;binary",
        }[damage]
        attributes[key] = [b"TOP-SECRET"]
    with pytest.raises(ConfigurationError) as raised:
        validate_entries(entries, "o=Example")
    assert "TOP-SECRET" not in str(raised.value)


@pytest.mark.parametrize(
    "content",
    [
        b"dn: o=Example\nchangetype: add\nobjectClass: organization\no: Example\n",
        b"dn: o=Example\ncontrol: TOP-SECRET\n",
        b"include: file:///TOP-SECRET\n",
        b"dn: o=Example\nuserPassword:< file:///TOP-SECRET\n",
        b"dn: o=Example\nuserPassword:: NOT!BASE64\n",
        b"dn: o=Example\ncn: a\nCN: b\n",
        b"version: 2\n\ndn: o=Example\no: Example\n",
        b"dn: o=Example\ninvalid attribute: TOP-SECRET\n",
        b"dn: o=Example\n-\n",
        b"",
    ],
)
def test_ldif_only_accepts_literal_entry_records(content: bytes) -> None:
    with pytest.raises(ConfigurationError) as raised:
        parse_ldif(content)
    assert "TOP-SECRET" not in str(raised.value)


@pytest.mark.parametrize(
    "damage", ["module", "acl", "wrong-dn", "wrong-class", "binary-value"]
)
def test_custom_schema_cannot_change_runtime_policy(damage: str) -> None:
    entries = parse_ldif((EXAMPLES / "device-schema.ldif").read_bytes())
    attributes = entries[0][1]
    if damage == "module":
        attributes["olcmoduleload"] = [b"TOP-SECRET"]
    elif damage == "acl":
        attributes["olcaccess"] = [b"to * by * write"]
    elif damage == "wrong-dn":
        entries[0] = ("cn=config", attributes)
    elif damage == "wrong-class":
        attributes["objectclass"] = [b"olcGlobal"]
    else:
        attributes["olcattributetypes"] = [b"\xff"]
    with pytest.raises(ConfigurationError):
        validate_schema(entries)


def test_unicode_and_binary_attribute_values_round_trip(tmp_path: Path) -> None:
    entries = native()
    entries[2][1]["jpegphoto"] = [b"\x00\xff\x01"]
    entries[2][1]["description"] = ["Non-ASCII: \u00e4".encode()]
    path = tmp_path / "data.ldif"
    write_ldif(path, entries)
    assert parse_ldif(path.read_bytes()) == entries
