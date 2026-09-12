#!/usr/bin/env python3

"""Validate entry LDIF and schema-only LDIF before offline OpenLDAP import."""

from __future__ import annotations

import argparse
import base64
import binascii
import io
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, cast

import ldap.dn
from ldif import LDIFRecordList, LDIFWriter

MAX_DATA_BYTES = 16 * 1024 * 1024
ATTRIBUTE_PATTERN = re.compile(r"(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)")
HASH_PATTERN = re.compile(
    r"\{ARGON2\}\$argon2id\$v=19\$m=([1-9][0-9]*),t=([1-9][0-9]*),p=([1-9][0-9]*)"
    r"\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)"
)
DEFAULT_READ_ATTRIBUTES = (
    "objectClass",
    "entryUUID",
    "dc",
    "o",
    "ou",
    "uid",
    "cn",
    "sn",
    "givenName",
    "displayName",
    "initials",
    "description",
    "physicalDeliveryOfficeName",
    "telephoneNumber",
    "mobile",
    "employeeNumber",
    "title",
    "proxyAddresses",
    "mail",
    "member",
    "memberOf",
)
type Entry = tuple[str, dict[str, list[bytes]]]
type DNKey = tuple[tuple[tuple[str, str], ...], ...]


class ConfigurationError(Exception):
    """An operator-provided input is invalid; diagnostics never contain values."""


def validate_entry_uuid(value: Any, *, context: str = "entryUUID") -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise ConfigurationError(f"invalid {context}")
    try:
        identifier = uuid.UUID(value)
    except ValueError:
        raise ConfigurationError(f"invalid {context}") from None
    if (
        str(identifier) != value
        or identifier.variant != uuid.RFC_4122
        or identifier.version not in range(1, 9)
    ):
        raise ConfigurationError(
            f"{context} must be a canonical lowercase RFC-variant UUID (version 1 through 8)"
        )
    return value


def validate_password_hash(value: Any, *, context: str) -> str:
    match = (
        HASH_PATTERN.fullmatch(value)
        if isinstance(value, str) and len(value) <= 4096
        else None
    )
    if match is None:
        raise ConfigurationError(
            f"{context} must be an OpenLDAP {{ARGON2}} Argon2id v=19 verifier"
        )
    memory, iterations, parallelism = (int(number) for number in match.groups()[:3])
    if not (
        19456 <= memory <= 2**32 - 1
        and 2 <= iterations <= 2**32 - 1
        and 1 <= parallelism <= 2**24 - 1
        and memory >= 8 * parallelism
    ):
        raise ConfigurationError(
            f"{context} has unsupported Argon2 parameters; require m>=19456, t>=2, p>=1"
        )
    for encoded, minimum in zip(match.groups()[3:], (16, 32), strict=True):
        try:
            decoded = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), validate=True
            )
        except binascii.Error:
            raise ConfigurationError(
                f"{context} has invalid Argon2 base64 encoding"
            ) from None
        if (
            len(decoded) < minimum
            or base64.b64encode(decoded).decode("ascii").rstrip("=") != encoded
        ):
            raise ConfigurationError(
                f"{context} has short or non-canonical Argon2 base64 encoding"
            )
    return cast(str, value)


def read_regular(
    path: Path, *, maximum: int, context: str, private: bool = False
) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ConfigurationError(
                f"{context} must be a regular file, not a symbolic link"
            )
        if private and info.st_mode & 0o077:
            raise ConfigurationError(
                f"{context} must not be readable or writable by group or other users"
            )
        if info.st_size > maximum:
            raise ConfigurationError(f"{context} exceeds the {maximum}-byte limit")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_mode) != (
                info.st_dev,
                info.st_ino,
                info.st_mode,
            ):
                raise ConfigurationError(f"{context} changed while opening it")
            content = stream.read(maximum + 1)
        if len(content) > maximum:
            raise ConfigurationError(f"{context} exceeds the {maximum}-byte limit")
        return content
    except OSError:
        raise ConfigurationError(f"cannot read {context}") from None


def dn_key(value: str, *, fold_values: bool = True) -> DNKey:
    try:
        parsed = ldap.dn.str2dn(value, flags=ldap.DN_FORMAT_LDAPV3)
    except ldap.DECODING_ERROR:
        raise ConfigurationError("invalid LDAP DN") from None
    if not parsed or any(char in value for char in "\x00\r\n"):
        raise ConfigurationError("empty or unsafe LDAP DN")
    # OpenLDAP performs the final schema-aware normalization during offline import.
    return tuple(
        tuple(
            sorted(
                (name.casefold(), content.casefold() if fold_values else content)
                for name, content, _ in rdn
            )
        )
        for rdn in parsed
    )


def parse_ldif(content: bytes) -> list[Entry]:
    if len(content) > MAX_DATA_BYTES:
        raise ConfigurationError("LDIF exceeds the 16 MiB limit")
    try:
        # Tighten python-ldap's permissive base64 and URL handling, not its parser.
        logical_lines = re.sub(rb"\r?\n ", b"", content).splitlines()
        for line in logical_lines:
            if not line or line.startswith(b"#"):
                continue
            if b":" not in line:
                raise ConfigurationError("invalid LDIF value specification")
            name, value = line.split(b":", 1)
            if not re.fullmatch(
                rb"(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)(?:;[A-Za-z0-9-]+)*",
                name,
            ):
                raise ConfigurationError("invalid LDIF attribute description")
            if value.startswith(b"<"):
                raise ConfigurationError("LDIF URL values are not accepted")
            if name.lower() in (b"changetype", b"control", b"include"):
                raise ConfigurationError(
                    "LDIF must contain entries, not changes, controls or includes"
                )
            if value.startswith(b":"):
                base64.b64decode(value[1:].lstrip(b" "), validate=True)
        parser = LDIFRecordList(io.BytesIO(content + b"\n\n"), process_url_schemes=[])
        parser.parse()
        if parser.version not in (None, 1):
            raise ConfigurationError("LDIF version must be 1")
        entries: list[Entry] = []
        for dn, raw_attributes in parser.all_records:
            attributes: dict[str, list[bytes]] = {}
            for name, values in raw_attributes.items():
                lowered = name.lower()
                if lowered in attributes:
                    raise ConfigurationError(
                        "LDIF repeats an attribute using different capitalization"
                    )
                if any(not isinstance(value, bytes) for value in values):
                    raise ConfigurationError("LDIF contains a non-literal value")
                attributes[lowered] = values
            entries.append((dn, attributes))
        if not entries:
            raise ConfigurationError("LDIF must contain at least one entry")
        return entries
    except (ValueError, UnicodeError, AttributeError, EOFError):
        raise ConfigurationError("invalid LDIF syntax or encoding") from None


def validate_entries(
    entries: list[Entry], base_dn: str, *, application_policy: bool = True
) -> None:
    base = dn_key(base_dn)
    config = dn_key("cn=config")
    dns: set[DNKey] = set()
    exact_dns: set[DNKey] = set()
    identifiers: set[str] = set()
    for dn, attributes in entries:
        key = dn_key(dn)
        if key[-len(base) :] != base or key[-len(config) :] == config:
            raise ConfigurationError(
                "directory entry is outside the base DN or targets cn=config"
            )
        exact = dn_key(dn, fold_values=False)
        if exact in exact_dns:
            raise ConfigurationError("directory contains duplicate DNs")
        exact_dns.add(exact)
        dns.add(key)
        values = attributes.get("entryuuid", [])
        if application_policy and len(values) != 1:
            raise ConfigurationError(
                "every entry must supply exactly one stable entryUUID"
            )
        if len(values) > 1:
            raise ConfigurationError("entryUUID must be single-valued")
        try:
            if not values:
                continue
            text = values[0].decode("ascii")
        except UnicodeError:
            raise ConfigurationError("invalid entryUUID") from None
        identifier = validate_entry_uuid(text)
        if identifier in identifiers:
            raise ConfigurationError("directory contains duplicate entryUUID values")
        identifiers.add(identifier)
        for name, values in attributes.items():
            attribute = name.split(";", 1)[0]
            if application_policy and attribute.startswith("olc"):
                raise ConfigurationError(
                    "directory data must not contain server configuration"
                )
            if application_policy and attribute in ("userpassword", "2.5.4.35"):
                if ";" in name:
                    raise ConfigurationError(
                        "userPassword attribute options are not accepted"
                    )
                for value in values:
                    try:
                        validate_password_hash(
                            value.decode("ascii"), context="userPassword"
                        )
                    except UnicodeError:
                        raise ConfigurationError(
                            "userPassword must contain an Argon2id verifier"
                        ) from None
    if base not in dns:
        raise ConfigurationError("directory must contain its base DN entry")
    for entry_dn in dns:
        if entry_dn != base and entry_dn[1:] not in dns:
            raise ConfigurationError("directory entry has no parent entry")


def validate_schema(entries: list[Entry]) -> None:
    parent = dn_key("cn=schema,cn=config")
    allowed = {"cn", "objectclass", "olcattributetypes", "olcobjectclasses"}
    for dn, attributes in entries:
        key = dn_key(dn)
        if (
            len(key) != 3
            or key[1:] != parent
            or len(key[0]) != 1
            or key[0][0][0] != "cn"
        ):
            raise ConfigurationError(
                "schema entry must be directly under cn=schema,cn=config"
            )
        if set(attributes) - allowed or len(attributes.get("cn", [])) != 1:
            raise ConfigurationError(
                "schema LDIF may only define cn, objectClass, olcAttributeTypes and olcObjectClasses"
            )
        classes = {value.lower() for value in attributes.get("objectclass", [])}
        if classes not in ({b"olcschemaconfig"}, {b"top", b"olcschemaconfig"}):
            raise ConfigurationError("schema entry must use olcSchemaConfig")
        for values in attributes.values():
            for value in values:
                try:
                    value.decode("utf-8")
                except UnicodeError:
                    raise ConfigurationError("schema values must use UTF-8") from None
                if b"\x00" in value:
                    raise ConfigurationError("schema values must not contain NUL")


def write_ldif(path: Path, entries: list[Entry]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        writer = LDIFWriter(stream, cols=1000)
        for dn, attributes in entries:
            writer.unparse(dn, attributes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dn", required=True)
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--schema", action="append", type=Path, default=[])
    parser.add_argument("data", nargs="+", type=Path)
    args = parser.parse_args()
    entries: list[Entry] = []
    total = 0
    for path in args.schema + args.data:
        content = read_regular(path, maximum=MAX_DATA_BYTES, context="snapshot LDIF")
        total += len(content)
        if total > MAX_DATA_BYTES:
            raise ConfigurationError("snapshot exceeds the 16 MiB limit")
        records = parse_ldif(content)
        if path in args.schema:
            validate_schema(records)
        else:
            entries.extend(records)
    validate_entries(entries, args.base_dn, application_policy=not args.native)


if __name__ == "__main__":
    try:
        main()
    except ConfigurationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(65) from None
