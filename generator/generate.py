#!/usr/bin/env python3

"""Generate one signed OpenLDAP snapshot from a directory definition."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, NoReturn, cast

import ldap.dn
import yaml
from argon2 import PasswordHasher, Type
from yaml.events import AliasEvent

from generator.vault import DecryptedString, Vault, VaultScalar
from scripts.directory_data import (
    ATTRIBUTE_PATTERN,
    DEFAULT_READ_ATTRIBUTES,
    MAX_DATA_BYTES,
    ConfigurationError,
    Entry,
    dn_key,
    parse_ldif,
    read_regular,
    validate_entries,
    validate_password_hash,
    validate_schema,
    write_ldif,
)

DIRECTORY_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SOURCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
UID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
UUID_NAMESPACE_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}"
    r"-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
)
MAX_YAML_BYTES = 1024 * 1024
MAX_EXPIRY_OFFSET_SECONDS = 86_400
type CredentialKind = Literal["plaintext", "plaintext-file", "hash-file", "hash"]
PASSWORD_FIELDS: dict[str, CredentialKind] = {
    "password": "plaintext",
    "password_file": "plaintext-file",
    "password_hash_file": "hash-file",
    "password_hash": "hash",
}


class StrictLoader(yaml.SafeLoader):
    """Accept scalar Vault tags, but reject aliases and ambiguous mapping keys."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            raise ConfigurationError("YAML aliases are not accepted")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                error("all YAML mapping keys must be unencrypted strings")
            if key in mapping:
                error("duplicate YAML key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def vault_scalar(loader: StrictLoader, node: Any) -> VaultScalar:
    if not isinstance(node, yaml.ScalarNode):
        error("!vault may only tag a scalar value")
    return VaultScalar(loader.construct_scalar(node))


StrictLoader.add_constructor("!vault", vault_scalar)


@dataclass(frozen=True)
class CredentialSource:
    kind: CredentialKind
    value: str = field(repr=False)


@dataclass(frozen=True)
class User:
    source_id: str
    uid: str
    common_name: str
    surname: str
    mail: str | None
    active: bool
    credential: CredentialSource | None


@dataclass(frozen=True)
class Group:
    source_id: str
    common_name: str
    members: tuple[str, ...]


@dataclass(frozen=True)
class BindAccount:
    source_id: str
    common_name: str
    credential: CredentialSource


@dataclass(frozen=True)
class Directory:
    directory_id: str
    base_dn: str
    revision: int
    soft_ttl_seconds: int
    hard_ttl_seconds: int
    expiry_offset_seconds: int
    input_type: str
    namespace: uuid.UUID | None
    organization: str | None
    users: dict[str, User]
    groups: dict[str, Group]
    bind_account: BindAccount | None
    ldif_files: tuple[Path, ...]
    schema_files: tuple[Path, ...]
    read_attributes: tuple[str, ...]


def error(message: str) -> NoReturn:
    raise ConfigurationError(message)


def strict_keys(
    value: Any, *, required: set[str], optional: set[str], context: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        error(f"{context} must be a mapping")
    keys = set(value)
    if required - keys:
        error(f"{context} is missing keys: {', '.join(sorted(required - keys))}")
    if keys - required - optional:
        error(f"{context} contains unknown keys")
    return value


def text_value(value: Any, *, context: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        error(f"{context} must be a non-empty string of at most {maximum} characters")
    if any(char in value for char in "\x00\r\n"):
        error(f"{context} must not contain NUL or newline characters")
    return value


def string_list(value: Any, *, context: str, maximum: int = 128) -> tuple[str, ...]:
    if not isinstance(value, list):
        error(f"{context} must be a list")
    result = tuple(
        text_value(item, context=f"{context} item", maximum=maximum) for item in value
    )
    if len(result) != len(set(result)):
        error(f"{context} must not contain duplicate values")
    return result


def positive_integer(value: Any, *, context: str, maximum: int = 2**31 - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        error(f"{context} must be an integer from 1 through {maximum}")
    return value


def nonnegative_integer(value: Any, *, context: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        error(f"{context} must be an integer from 0 through {maximum}")
    return value


def load_yaml(
    path: Path, *, context: str, vault: Vault | None = None
) -> dict[str, Any]:
    content = read_regular(path, maximum=MAX_YAML_BYTES, context=context)
    try:
        value = yaml.load(content.decode("utf-8"), Loader=StrictLoader)
    except (UnicodeError, yaml.YAMLError, RecursionError):
        error(f"cannot parse {context}: invalid UTF-8 or YAML syntax")
    if not isinstance(value, dict):
        error(f"{context} must contain one top-level mapping")
    return cast(dict[str, Any], (vault or Vault([])).resolve(value))


def validate_source_id(value: Any, *, context: str) -> str:
    source_id = text_value(value, context=context, maximum=128)
    if not SOURCE_ID_PATTERN.fullmatch(source_id):
        error(f"{context} contains unsupported characters")
    return source_id


def validate_uid(value: Any, *, context: str) -> str:
    uid = text_value(value, context=context, maximum=64)
    if not UID_PATTERN.fullmatch(uid):
        error(f"{context} must match {UID_PATTERN.pattern}")
    return uid


def validate_base_dn(value: Any, *, context: str, simplified: bool = True) -> str:
    base_dn = text_value(value, context=context)
    try:
        dn_key(base_dn)
        parsed = ldap.dn.str2dn(base_dn, flags=ldap.DN_FORMAT_LDAPV3)
    except ConfigurationError:
        error(f"{context} is not a valid LDAP DN")
    if simplified:
        if not base_dn.isascii():
            error(f"{context} must contain only ASCII characters")
        if len(parsed[0]) != 1 or parsed[0][0][0].casefold() != "dc":
            error(f"{context} must begin with one dc RDN")
    if dn_key(base_dn)[-1:] == dn_key("cn=config"):
        error(f"{context} must not target cn=config")
    return cast(str, ldap.dn.dn2str(parsed))


def credential_source(
    kind: CredentialKind, value: Any, *, context: str
) -> CredentialSource:
    if kind == "hash":
        return CredentialSource(kind, validate_password_hash(value, context=context))
    text = text_value(value, context=context, maximum=4096)
    if kind != "plaintext" and not Path(text).is_absolute():
        error(f"{context} must be an absolute path")
    return CredentialSource(kind, text)


def default_credential_source(
    item: dict[str, Any], *, context: str, path: Path
) -> CredentialSource | None:
    fields = [name for name in PASSWORD_FIELDS if name in item]
    if len(fields) > 1:
        error(f"{context} must not combine password sources")
    if not fields:
        return None
    name = fields[0]
    if (
        name in {"password", "password_hash"}
        and not isinstance(item[name], DecryptedString)
        and path.stat().st_mode & 0o077
    ):
        error(
            "directory YAML containing unencrypted inline credentials must be readable only by its owner"
        )
    return credential_source(
        PASSWORD_FIELDS[name], item[name], context=f"{context}.{name}"
    )


def parse_users(root: dict[str, Any], path: Path) -> dict[str, User]:
    if not isinstance(root["users"], list):
        error("users must be a list")
    users: dict[str, User] = {}
    uids: set[str] = set()
    for index, raw in enumerate(root["users"]):
        context = f"users[{index}]"
        item = strict_keys(
            raw,
            required={"id", "uid", "common_name", "surname", "active"},
            optional={"mail"} | set(PASSWORD_FIELDS),
            context=context,
        )
        source_id = validate_source_id(item["id"], context=f"{context}.id")
        uid = validate_uid(item["uid"], context=f"{context}.uid")
        if source_id in users or uid.casefold() in uids:
            error("duplicate user id or case-insensitive uid")
        if not isinstance(item["active"], bool):
            error(f"{context}.active must be true or false")
        credential = default_credential_source(item, context=context, path=path)
        if item["active"] and credential is None:
            error(f"{context} requires one password source when active")
        users[source_id] = User(
            source_id,
            uid,
            text_value(
                item["common_name"], context=f"{context}.common_name", maximum=256
            ),
            text_value(item["surname"], context=f"{context}.surname", maximum=256),
            text_value(item["mail"], context=f"{context}.mail", maximum=320)
            if "mail" in item
            else None,
            item["active"],
            credential,
        )
        uids.add(uid.casefold())
    return users


def parse_groups(root: dict[str, Any], users: dict[str, User]) -> dict[str, Group]:
    if not isinstance(root["groups"], list):
        error("groups must be a list")
    groups: dict[str, Group] = {}
    names: set[str] = set()
    for index, raw in enumerate(root["groups"]):
        context = f"groups[{index}]"
        item = strict_keys(
            raw,
            required={"id", "common_name", "members"},
            optional=set(),
            context=context,
        )
        source_id = validate_source_id(item["id"], context=f"{context}.id")
        name = validate_uid(item["common_name"], context=f"{context}.common_name")
        members = string_list(item["members"], context=f"{context}.members")
        if source_id in groups or name.casefold() in names:
            error("duplicate group id or case-insensitive common_name")
        if set(members) - users.keys():
            error(f"{context} references unknown users")
        groups[source_id] = Group(source_id, name, members)
        names.add(name.casefold())
    return groups


def source_files(value: Any, path: Path, *, context: str) -> tuple[Path, ...]:
    names = string_list(value, context=context, maximum=4096)
    if len(names) > 31:
        error(f"{context} accepts at most 31 files")
    return tuple(
        Path(name) if Path(name).is_absolute() else path.parent / name for name in names
    )


def parse_directory(path: Path, vault: Vault | None = None) -> Directory:
    root = load_yaml(path, context="directory YAML", vault=vault)
    if type(root.get("format_version")) is not int or root["format_version"] != 1:
        error("directory YAML format_version must be 1")
    input_type = root.get("input_type")
    if input_type not in ("users-groups", "ldif"):
        error("input_type must be users-groups or ldif")
    required = {
        "format_version",
        "directory_id",
        "base_dn",
        "revision",
        "soft_ttl_seconds",
        "hard_ttl_seconds",
        "input_type",
    }
    specific = (
        {"uuid_namespace", "organization", "users", "groups", "bind_account"}
        if input_type == "users-groups"
        else {"ldif_files", "read_attributes"}
    )
    strict_keys(
        root,
        required=required | specific,
        optional={"expiry_offset_seconds", "schema_files"}
        | ({"read_attributes"} if input_type == "users-groups" else set()),
        context="directory YAML",
    )
    directory_id = text_value(root["directory_id"], context="directory_id", maximum=128)
    if not DIRECTORY_ID_PATTERN.fullmatch(directory_id):
        error("directory_id must match " + DIRECTORY_ID_PATTERN.pattern)
    soft = positive_integer(root["soft_ttl_seconds"], context="soft_ttl_seconds")
    hard = positive_integer(root["hard_ttl_seconds"], context="hard_ttl_seconds")
    offset = nonnegative_integer(
        root.get("expiry_offset_seconds", 0),
        context="expiry_offset_seconds",
        maximum=MAX_EXPIRY_OFFSET_SECONDS,
    )
    if soft >= hard:
        error("soft_ttl_seconds must be less than hard_ttl_seconds")
    if offset >= soft:
        error("expiry_offset_seconds must be less than soft_ttl_seconds")
    read_attributes = string_list(
        root.get("read_attributes", list(DEFAULT_READ_ATTRIBUTES)),
        context="read_attributes",
    )
    if not 1 <= len(read_attributes) <= 128 or any(
        not ATTRIBUTE_PATTERN.fullmatch(name) for name in read_attributes
    ):
        error("read_attributes requires 1 through 128 literal attribute names or OIDs")
    if len({name.casefold() for name in read_attributes}) != len(read_attributes):
        error("read_attributes must not repeat case-insensitive names")
    if any(
        name.lower() in {"userpassword", "2.5.4.35"} or name.lower().startswith("olc")
        for name in read_attributes
    ):
        error("read_attributes must not expose passwords or server configuration")
    namespace = None
    organization = None
    users: dict[str, User] = {}
    groups: dict[str, Group] = {}
    bind = None
    files: tuple[Path, ...] = ()
    if input_type == "users-groups":
        namespace_text = text_value(root["uuid_namespace"], context="uuid_namespace")
        if not UUID_NAMESPACE_PATTERN.fullmatch(namespace_text):
            error(
                "uuid_namespace must be a hyphenated RFC-variant UUID of version 1 through 5"
            )
        namespace = uuid.UUID(namespace_text)
        organization = text_value(
            root["organization"], context="organization", maximum=256
        )
        users = parse_users(root, path)
        groups = parse_groups(root, users)
        item = strict_keys(
            root["bind_account"],
            required={"id", "common_name"},
            optional=set(PASSWORD_FIELDS),
            context="bind_account",
        )
        credential = default_credential_source(item, context="bind_account", path=path)
        if credential is None:
            error("bind_account requires one password source")
        bind = BindAccount(
            validate_source_id(item["id"], context="bind_account.id"),
            validate_uid(item["common_name"], context="bind_account.common_name"),
            credential,
        )
    else:
        files = source_files(root["ldif_files"], path, context="ldif_files")
        if not files:
            error("ldif_files must not be empty")
    return Directory(
        directory_id,
        validate_base_dn(
            root["base_dn"], context="base_dn", simplified=input_type == "users-groups"
        ),
        positive_integer(
            root["revision"], context="revision", maximum=9_007_199_254_740_991
        ),
        soft,
        hard,
        offset,
        input_type,
        namespace,
        organization,
        users,
        groups,
        bind,
        files,
        source_files(root.get("schema_files", []), path, context="schema_files"),
        read_attributes,
    )


def read_credential_file(path_value: str, *, context: str) -> str:
    value = read_regular(Path(path_value), maximum=4096, context=context, private=True)
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    if not value or any(char in value for char in (b"\x00", b"\r", b"\n")):
        error(f"{context} must contain exactly one non-empty line")
    try:
        return value.decode("utf-8")
    except UnicodeError:
        error(f"{context} must contain valid UTF-8")


def hash_password(password: str) -> str:
    return "{ARGON2}" + PasswordHasher(
        time_cost=2,
        memory_cost=19456,
        parallelism=1,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    ).hash(password)


def password_verifier(source: CredentialSource, *, context: str) -> str:
    value = (
        read_credential_file(source.value, context=context)
        if source.kind.endswith("-file")
        else source.value
    )
    if source.kind in {"plaintext", "plaintext-file"}:
        return hash_password(value)
    return validate_password_hash(value, context=context)


def stable_uuid(namespace: uuid.UUID, entity_type: str, source_id: str) -> str:
    return str(uuid.uuid5(namespace, f"{entity_type}:{source_id}"))


def simplified_entries(directory: Directory) -> list[Entry]:
    assert directory.namespace is not None and directory.bind_account is not None
    namespace = directory.namespace
    base = directory.base_dn
    entries: list[Entry] = []

    def add(dn: str, attributes: dict[str, list[str]]) -> None:
        entries.append(
            (
                dn,
                {
                    name: [value.encode("utf-8") for value in values]
                    for name, values in attributes.items()
                },
            )
        )

    add(
        base,
        {
            "objectClass": ["top", "dcObject", "organization"],
            "dc": [ldap.dn.str2dn(base)[0][0][1]],
            "o": [directory.organization or ""],
            "entryUUID": [stable_uuid(namespace, "directory", directory.directory_id)],
        },
    )
    for name in ("people", "groups", "services"):
        add(
            f"ou={name},{base}",
            {
                "objectClass": ["top", "organizationalUnit"],
                "ou": [name],
                "entryUUID": [
                    stable_uuid(
                        namespace,
                        "container",
                        f"{directory.directory_id}:{name}",
                    )
                ],
            },
        )
    users = {key: user for key, user in directory.users.items() if user.active}
    memberships: dict[str, list[str]] = {key: [] for key in users}
    for group in directory.groups.values():
        dn = f"cn={ldap.dn.escape_dn_chars(group.common_name)},ou=groups,{base}"
        members = [key for key in group.members if key in users]
        if not members:
            continue
        for key in members:
            memberships[key].append(dn)
        add(
            dn,
            {
                "objectClass": ["top", "groupOfNames"],
                "cn": [group.common_name],
                "entryUUID": [stable_uuid(namespace, "group", group.source_id)],
                "member": sorted(
                    f"uid={ldap.dn.escape_dn_chars(users[key].uid)},ou=people,{base}"
                    for key in members
                ),
            },
        )
    for key, user in users.items():
        assert user.credential is not None
        attributes = {
            "objectClass": ["top", "inetOrgPerson"],
            "uid": [user.uid],
            "cn": [user.common_name],
            "sn": [user.surname],
            "entryUUID": [stable_uuid(namespace, "user", key)],
            "userPassword": [
                password_verifier(user.credential, context="user credential")
            ],
        }
        if user.mail is not None:
            attributes["mail"] = [user.mail]
        if memberships[key]:
            attributes["memberOf"] = sorted(memberships[key])
        add(f"uid={ldap.dn.escape_dn_chars(user.uid)},ou=people,{base}", attributes)
    bind = directory.bind_account
    add(
        f"cn={ldap.dn.escape_dn_chars(bind.common_name)},ou=services,{base}",
        {
            "objectClass": ["top", "organizationalRole", "simpleSecurityObject"],
            "cn": [bind.common_name],
            "entryUUID": [stable_uuid(namespace, "bind", bind.source_id)],
            "userPassword": [
                password_verifier(bind.credential, context="bind credential")
            ],
        },
    )
    return entries


def iso_timestamp(value: datetime) -> str:
    return (
        value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def parse_generated_at(value: str | None) -> datetime:
    if value is None:
        return datetime.now(UTC).replace(microsecond=0)
    if not value.endswith("Z"):
        error("--generated-at must be an RFC 3339 UTC timestamp ending in Z")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        error("--generated-at is invalid")
    if result.microsecond:
        error("--generated-at must use whole seconds")
    return result


def validate_signing_key(path: Path) -> None:
    read_regular(path, maximum=16384, context="signing key", private=True)


def sign_manifest(
    manifest_path: Path, signing_key: Path, directory_id: str, revision: int
) -> None:
    signature_path = manifest_path.with_name("manifest.json.minisig")
    try:
        result = subprocess.run(
            [
                "minisign",
                "-S",
                "-W",
                "-s",
                str(signing_key),
                "-m",
                str(manifest_path),
                "-x",
                str(signature_path),
                "-t",
                f"openldap snapshot {directory_id} revision {revision}",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        error("cannot execute minisign within 30 seconds")
    if result.returncode != 0:
        error("minisign could not sign the manifest")
    signature_path.chmod(0o600)


def generate_snapshot(
    destination: Path, directory: Directory, signing_key: Path, generated_at: datetime
) -> None:
    entries = (
        simplified_entries(directory) if directory.input_type == "users-groups" else []
    )
    total = 0
    for path in directory.ldif_files:
        content = read_regular(path, maximum=MAX_DATA_BYTES, context="source LDIF")
        total += len(content)
        if total > MAX_DATA_BYTES:
            error("source LDIF exceeds the 16 MiB limit")
        entries.extend(parse_ldif(content))
    ldif_path = destination / "directory.ldif"
    write_ldif(
        ldif_path,
        sorted(entries, key=lambda entry: (len(dn_key(entry[0])), dn_key(entry[0]))),
    )
    validate_entries(parse_ldif(ldif_path.read_bytes()), directory.base_dn)
    files = [
        {
            "path": ldif_path.name,
            "kind": "data",
            "sha256": hashlib.sha256(ldif_path.read_bytes()).hexdigest(),
        }
    ]
    for index, source in enumerate(directory.schema_files):
        content = read_regular(source, maximum=MAX_DATA_BYTES, context="schema LDIF")
        total += len(content)
        if total > MAX_DATA_BYTES:
            error("source LDIF exceeds the 16 MiB limit")
        schema = parse_ldif(content)
        validate_schema(schema)
        path = destination / f"schema-{index:02d}.ldif"
        write_ldif(path, schema)
        files.append(
            {
                "path": path.name,
                "kind": "schema",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    if (
        sum((destination / record["path"]).stat().st_size for record in files)
        > MAX_DATA_BYTES
    ):
        error("snapshot exceeds the 16 MiB limit")
    manifest = {
        "format_version": 1,
        "directory_id": directory.directory_id,
        "base_dn": directory.base_dn,
        "revision": directory.revision,
        "generated_at": iso_timestamp(generated_at),
        "soft_expires_at": iso_timestamp(
            generated_at
            + timedelta(
                seconds=directory.soft_ttl_seconds - directory.expiry_offset_seconds
            )
        ),
        "expires_at": iso_timestamp(
            generated_at
            + timedelta(
                seconds=directory.hard_ttl_seconds - directory.expiry_offset_seconds
            )
        ),
        "uuid_namespace": str(directory.namespace)
        if directory.namespace is not None
        else None,
        "input_type": directory.input_type,
        "read_attributes": directory.read_attributes,
        "files": files,
    }
    manifest_path = destination / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    for path in destination.iterdir():
        path.chmod(0o600)
    sign_manifest(
        manifest_path, signing_key, directory.directory_id, directory.revision
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory", required=True, type=Path, help="one version-1 directory YAML"
    )
    parser.add_argument(
        "--vault",
        action="append",
        default=[],
        help="KEYID@prompt or KEYID@/absolute/password-file; repeatable",
    )
    parser.add_argument(
        "--signing-key", required=True, type=Path, help="minisign secret key"
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="new snapshot directory"
    )
    parser.add_argument(
        "--generated-at",
        help="fixed RFC 3339 UTC generation time, primarily for testing",
    )
    return parser.parse_args()


def main() -> int:
    os.umask(0o077)
    arguments = parse_arguments()
    directory = parse_directory(arguments.directory, Vault(arguments.vault))
    validate_signing_key(arguments.signing_key)
    generated_at = parse_generated_at(arguments.generated_at)
    output = arguments.output.absolute()
    if output.exists() or output.is_symlink():
        error("output path already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        generate_snapshot(staging, directory, arguments.signing_key, generated_at)
        staging.rename(output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(f"generated {output} revision {directory.revision}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConfigurationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except Exception:
        print("ERROR: generator failed unexpectedly", file=sys.stderr)
        raise SystemExit(1) from None
