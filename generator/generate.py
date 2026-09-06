#!/usr/bin/env python3

"""Generate signed, service-specific OpenLDAP snapshots from strict YAML."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, cast

import ldap.dn
import yaml
from argon2 import PasswordHasher, Type
from ldif import LDIFWriter
from yaml.events import AliasEvent

SERVICE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SOURCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
UID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_YAML_BYTES = 1024 * 1024
ARGON_MEMORY_COST = 19_456
ARGON_TIME_COST = 2
ARGON_PARALLELISM = 1
MAX_EXPIRY_OFFSET_SECONDS = 86_400


class ConfigurationError(Exception):
    """An operator-provided input is invalid."""


class StrictLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects aliases and duplicate mapping keys."""

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
                raise ConfigurationError("all YAML mapping keys must be strings")
            if key in mapping:
                raise ConfigurationError(f"duplicate YAML key: {key}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True)
class User:
    source_id: str
    uid: str
    common_name: str
    surname: str
    mail: str | None
    active: bool


@dataclass(frozen=True)
class Group:
    source_id: str
    common_name: str
    members: tuple[str, ...]


@dataclass(frozen=True)
class BindAccount:
    source_id: str
    common_name: str


@dataclass(frozen=True)
class Service:
    service_id: str
    base_dn: str
    revision: int
    soft_ttl_seconds: int
    hard_ttl_seconds: int
    expiry_offset_seconds: int
    groups: tuple[str, ...]
    users: tuple[str, ...]
    bind_account: BindAccount


@dataclass(frozen=True)
class Directory:
    namespace: uuid.UUID
    organization: str
    users: dict[str, User]
    groups: dict[str, Group]
    services: dict[str, Service]


@dataclass(frozen=True)
class Credentials:
    users: dict[str, dict[str, Any]]
    services: dict[str, str]


def error(message: str) -> NoReturn:
    raise ConfigurationError(message)


def strict_keys(
    value: Any, *, required: set[str], optional: set[str], context: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        error(f"{context} must be a mapping")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        error(f"{context} is missing keys: {', '.join(sorted(missing))}")
    if unknown:
        error(f"{context} contains unknown keys: {', '.join(sorted(unknown))}")
    return value


def text_value(value: Any, *, context: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        error(f"{context} must be a non-empty string of at most {maximum} characters")
    if "\x00" in value or "\r" in value or "\n" in value:
        error(f"{context} must not contain NUL or newline characters")
    return value


def string_list(value: Any, *, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        error(f"{context} must be a list")
    result = tuple(
        text_value(item, context=f"{context} item", maximum=128) for item in value
    )
    if len(result) != len(set(result)):
        error(f"{context} must not contain duplicate values")
    return result


def positive_integer(value: Any, *, context: str, maximum: int = 2**31 - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > maximum
    ):
        error(f"{context} must be an integer from 1 through {maximum}")
    return value


def nonnegative_integer(value: Any, *, context: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > maximum
    ):
        error(f"{context} must be an integer from 0 through {maximum}")
    return value


def load_yaml(path: Path, *, context: str) -> dict[str, Any]:
    try:
        file_stat = path.lstat()
    except OSError as exc:
        error(f"cannot inspect {context}: {exc}")
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        error(f"{context} must be a regular file, not a symbolic link")
    if file_stat.st_size > MAX_YAML_BYTES:
        error(f"{context} exceeds the {MAX_YAML_BYTES}-byte input limit")
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = yaml.load(stream, Loader=StrictLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        error(f"cannot parse {context}: {exc}")
    if not isinstance(value, dict):
        error(f"{context} must contain one top-level mapping")
    return value


def validate_source_id(value: Any, *, context: str) -> str:
    source_id = text_value(value, context=context, maximum=128)
    if not SOURCE_ID_PATTERN.fullmatch(source_id):
        error(f"{context} contains unsupported characters")
    return source_id


def validate_service_id(value: Any, *, context: str) -> str:
    service_id = text_value(value, context=context, maximum=128)
    if not SERVICE_ID_PATTERN.fullmatch(service_id):
        error(f"{context} must match {SERVICE_ID_PATTERN.pattern}")
    return service_id


def validate_uid(value: Any, *, context: str) -> str:
    uid = text_value(value, context=context, maximum=64)
    if not UID_PATTERN.fullmatch(uid):
        error(f"{context} must match {UID_PATTERN.pattern}")
    return uid


def validate_base_dn(value: Any, *, context: str) -> str:
    base_dn = text_value(value, context=context)
    if not base_dn.isascii():
        error(f"{context} must contain only ASCII characters")
    try:
        parsed = ldap.dn.str2dn(base_dn, flags=ldap.DN_FORMAT_LDAPV3)
        canonical = ldap.dn.dn2str(parsed)
    except ldap.DECODING_ERROR as exc:
        error(f"{context} is not a valid LDAP DN: {exc}")
    if not canonical:
        error(f"{context} must not be the root DSE")
    if len(parsed[0]) != 1 or parsed[0][0][0].casefold() != "dc":
        error(f"{context} must begin with one dc RDN")
    return cast(str, canonical)


def parse_directory(path: Path) -> Directory:
    root = strict_keys(
        load_yaml(path, context="directory YAML"),
        required={
            "format_version",
            "uuid_namespace",
            "organization",
            "users",
            "groups",
            "services",
        },
        optional=set(),
        context="directory YAML",
    )
    if root["format_version"] != 1:
        error("directory YAML format_version must be 1")
    try:
        namespace = uuid.UUID(
            text_value(root["uuid_namespace"], context="uuid_namespace")
        )
    except ValueError as exc:
        error(f"uuid_namespace is invalid: {exc}")
    organization = text_value(root["organization"], context="organization", maximum=256)

    if not isinstance(root["users"], list):
        error("users must be a list")
    users: dict[str, User] = {}
    user_uids: set[str] = set()
    for index, raw_user in enumerate(root["users"]):
        context = f"users[{index}]"
        item = strict_keys(
            raw_user,
            required={"id", "uid", "common_name", "surname", "active"},
            optional={"mail"},
            context=context,
        )
        source_id = validate_source_id(item["id"], context=f"{context}.id")
        uid = validate_uid(item["uid"], context=f"{context}.uid")
        if source_id in users:
            error(f"duplicate user id: {source_id}")
        if uid.casefold() in user_uids:
            error(f"duplicate user uid under case-insensitive matching: {uid}")
        if not isinstance(item["active"], bool):
            error(f"{context}.active must be true or false")
        mail = None
        if "mail" in item:
            mail = text_value(item["mail"], context=f"{context}.mail", maximum=320)
        users[source_id] = User(
            source_id=source_id,
            uid=uid,
            common_name=text_value(
                item["common_name"], context=f"{context}.common_name", maximum=256
            ),
            surname=text_value(
                item["surname"], context=f"{context}.surname", maximum=256
            ),
            mail=mail,
            active=item["active"],
        )
        user_uids.add(uid.casefold())

    if not isinstance(root["groups"], list):
        error("groups must be a list")
    groups: dict[str, Group] = {}
    group_names: set[str] = set()
    for index, raw_group in enumerate(root["groups"]):
        context = f"groups[{index}]"
        item = strict_keys(
            raw_group,
            required={"id", "common_name", "members"},
            optional=set(),
            context=context,
        )
        source_id = validate_source_id(item["id"], context=f"{context}.id")
        common_name = validate_uid(
            item["common_name"], context=f"{context}.common_name"
        )
        members = string_list(item["members"], context=f"{context}.members")
        if source_id in groups:
            error(f"duplicate group id: {source_id}")
        if common_name.casefold() in group_names:
            error(
                f"duplicate group common_name under case-insensitive matching: {common_name}"
            )
        unknown_members = set(members) - set(users)
        if unknown_members:
            error(
                f"{context} references unknown users: {', '.join(sorted(unknown_members))}"
            )
        groups[source_id] = Group(
            source_id=source_id, common_name=common_name, members=members
        )
        group_names.add(common_name.casefold())

    if not isinstance(root["services"], list):
        error("services must be a list")
    services: dict[str, Service] = {}
    bind_source_ids: set[str] = set()
    for index, raw_service in enumerate(root["services"]):
        context = f"services[{index}]"
        item = strict_keys(
            raw_service,
            required={
                "id",
                "base_dn",
                "revision",
                "soft_ttl_seconds",
                "hard_ttl_seconds",
                "expiry_offset_seconds",
                "groups",
                "users",
                "bind_account",
            },
            optional=set(),
            context=context,
        )
        service_id = validate_service_id(item["id"], context=f"{context}.id")
        selected_groups = string_list(item["groups"], context=f"{context}.groups")
        selected_users = string_list(item["users"], context=f"{context}.users")
        unknown_groups = set(selected_groups) - set(groups)
        unknown_users = set(selected_users) - set(users)
        if unknown_groups:
            error(
                f"{context} references unknown groups: {', '.join(sorted(unknown_groups))}"
            )
        if unknown_users:
            error(
                f"{context} references unknown users: {', '.join(sorted(unknown_users))}"
            )
        bind_item = strict_keys(
            item["bind_account"],
            required={"id", "common_name"},
            optional=set(),
            context=f"{context}.bind_account",
        )
        bind_account = BindAccount(
            source_id=validate_source_id(
                bind_item["id"], context=f"{context}.bind_account.id"
            ),
            common_name=validate_uid(
                bind_item["common_name"], context=f"{context}.bind_account.common_name"
            ),
        )
        if bind_account.source_id in bind_source_ids:
            error(f"duplicate service bind-account id: {bind_account.source_id}")
        if service_id in services:
            error(f"duplicate service id: {service_id}")
        soft_ttl = positive_integer(
            item["soft_ttl_seconds"], context=f"{context}.soft_ttl_seconds"
        )
        hard_ttl = positive_integer(
            item["hard_ttl_seconds"], context=f"{context}.hard_ttl_seconds"
        )
        expiry_offset = nonnegative_integer(
            item["expiry_offset_seconds"],
            context=f"{context}.expiry_offset_seconds",
            maximum=MAX_EXPIRY_OFFSET_SECONDS,
        )
        if soft_ttl >= hard_ttl:
            error(f"{context}.soft_ttl_seconds must be less than hard_ttl_seconds")
        if expiry_offset >= soft_ttl:
            error(f"{context}.expiry_offset_seconds must be less than soft_ttl_seconds")
        services[service_id] = Service(
            service_id=service_id,
            base_dn=validate_base_dn(item["base_dn"], context=f"{context}.base_dn"),
            revision=positive_integer(
                item["revision"],
                context=f"{context}.revision",
                maximum=9_007_199_254_740_991,
            ),
            soft_ttl_seconds=soft_ttl,
            hard_ttl_seconds=hard_ttl,
            expiry_offset_seconds=expiry_offset,
            groups=selected_groups,
            users=selected_users,
            bind_account=bind_account,
        )
        bind_source_ids.add(bind_account.source_id)

    return Directory(
        namespace=namespace,
        organization=organization,
        users=users,
        groups=groups,
        services=services,
    )


def credential_path(value: Any, *, context: str) -> str:
    path = Path(text_value(value, context=context, maximum=4096))
    if not path.is_absolute():
        error(f"{context} must be an absolute path")
    return str(path)


def parse_credentials(path: Path) -> Credentials:
    root = strict_keys(
        load_yaml(path, context="credentials YAML"),
        required={"format_version", "users", "services"},
        optional=set(),
        context="credentials YAML",
    )
    if root["format_version"] != 1:
        error("credentials YAML format_version must be 1")
    if not isinstance(root["users"], dict):
        error("credentials users must be a mapping keyed by immutable user id")
    users: dict[str, dict[str, Any]] = {}
    for user_id, raw_credential in root["users"].items():
        source_id = validate_source_id(user_id, context="credentials user id")
        item = strict_keys(
            raw_credential,
            required=set(),
            optional={"password_file", "service_password_files"},
            context=f"credentials.users.{source_id}",
        )
        default_password = None
        if "password_file" in item:
            default_password = credential_path(
                item["password_file"],
                context=f"credentials.users.{source_id}.password_file",
            )
        service_passwords: dict[str, str] = {}
        if "service_password_files" in item:
            if not isinstance(item["service_password_files"], dict):
                error(
                    f"credentials.users.{source_id}.service_password_files must be a mapping"
                )
            for service_id, password_file in item["service_password_files"].items():
                validated_service_id = validate_service_id(
                    service_id,
                    context=f"credentials.users.{source_id}.service_password_files key",
                )
                service_passwords[validated_service_id] = credential_path(
                    password_file,
                    context=(
                        f"credentials.users.{source_id}.service_password_files.{validated_service_id}"
                    ),
                )
        if default_password is None and not service_passwords:
            error(
                f"credentials.users.{source_id} must define at least one password source"
            )
        users[source_id] = {
            "password_file": default_password,
            "service_password_files": service_passwords,
        }

    if not isinstance(root["services"], dict):
        error("credentials services must be a mapping keyed by service id")
    services: dict[str, str] = {}
    for service_id, raw_credential in root["services"].items():
        validated_service_id = validate_service_id(
            service_id, context="credentials service id"
        )
        item = strict_keys(
            raw_credential,
            required={"bind_password_file"},
            optional=set(),
            context=f"credentials.services.{validated_service_id}",
        )
        services[validated_service_id] = credential_path(
            item["bind_password_file"],
            context=f"credentials.services.{validated_service_id}.bind_password_file",
        )
    return Credentials(users=users, services=services)


def validate_credential_references(
    directory: Directory, credentials: Credentials
) -> None:
    unknown_users = set(credentials.users) - set(directory.users)
    unknown_services = set(credentials.services) - set(directory.services)
    if unknown_users:
        error(
            f"credentials reference unknown users: {', '.join(sorted(unknown_users))}"
        )
    if unknown_services:
        error(
            f"credentials reference unknown services: {', '.join(sorted(unknown_services))}"
        )
    for user_id, item in credentials.users.items():
        unknown_overrides = set(item["service_password_files"]) - set(
            directory.services
        )
        if unknown_overrides:
            error(
                f"credentials for {user_id} reference unknown services: "
                f"{', '.join(sorted(unknown_overrides))}"
            )


def read_password(path_value: str, *, context: str) -> str:
    path = Path(path_value)
    try:
        file_stat = path.lstat()
    except OSError as exc:
        error(f"cannot inspect {context}: {exc}")
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        error(f"{context} must be a regular file, not a symbolic link")
    if file_stat.st_mode & 0o077:
        error(f"{context} must not be readable or writable by group or other users")
    if file_stat.st_size > 4096:
        error(f"{context} exceeds the 4096-byte limit")
    try:
        password_bytes = path.read_bytes()
    except OSError as exc:
        error(f"cannot read {context}: {exc}")
    if password_bytes.endswith(b"\r\n"):
        password_bytes = password_bytes[:-2]
    elif password_bytes.endswith(b"\n"):
        password_bytes = password_bytes[:-1]
    if (
        not password_bytes
        or b"\x00" in password_bytes
        or b"\r" in password_bytes
        or b"\n" in password_bytes
    ):
        error(f"{context} must contain exactly one non-empty line")
    try:
        return password_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        error(f"{context} must contain valid UTF-8: {exc}")


def user_password_file(credentials: Credentials, user_id: str, service_id: str) -> str:
    if user_id not in credentials.users:
        error(f"no credential is defined for authorized user {user_id}")
    item = credentials.users[user_id]
    if service_id in item["service_password_files"]:
        return cast(str, item["service_password_files"][service_id])
    if item["password_file"] is None:
        error(
            f"no default or {service_id}-specific credential is defined for user {user_id}"
        )
    return cast(str, item["password_file"])


def stable_uuid(namespace: uuid.UUID, entity_type: str, source_id: str) -> str:
    return str(uuid.uuid5(namespace, f"{entity_type}:{source_id}"))


def byte_attributes(attributes: dict[str, list[str]]) -> dict[str, list[bytes]]:
    return {
        name: [value.encode("utf-8") for value in values]
        for name, values in attributes.items()
    }


def write_entry(writer: LDIFWriter, dn: str, attributes: dict[str, list[str]]) -> None:
    writer.unparse(dn, byte_attributes(attributes))


def hash_password(password: str) -> str:
    hasher = PasswordHasher(
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )
    return "{ARGON2}" + hasher.hash(password)


def selected_users(directory: Directory, service: Service) -> set[str]:
    selected = set(service.users)
    for group_id in service.groups:
        selected.update(directory.groups[group_id].members)
    return {user_id for user_id in selected if directory.users[user_id].active}


def write_service_ldif(
    destination: Path,
    directory: Directory,
    credentials: Credentials,
    service: Service,
) -> None:
    selected = selected_users(directory, service)
    people_dn = f"ou=people,{service.base_dn}"
    groups_dn = f"ou=groups,{service.base_dn}"
    services_dn = f"ou=services,{service.base_dn}"
    bind_dn = (
        f"cn={ldap.dn.escape_dn_chars(service.bind_account.common_name)},{services_dn}"
    )
    memberships: dict[str, list[str]] = {user_id: [] for user_id in selected}
    group_member_dns: dict[str, list[str]] = {}

    for group_id in service.groups:
        group = directory.groups[group_id]
        member_ids = [user_id for user_id in group.members if user_id in selected]
        group_dn = f"cn={ldap.dn.escape_dn_chars(group.common_name)},{groups_dn}"
        group_member_dns[group_id] = []
        for user_id in member_ids:
            user = directory.users[user_id]
            user_dn = f"uid={ldap.dn.escape_dn_chars(user.uid)},{people_dn}"
            group_member_dns[group_id].append(user_dn)
            memberships[user_id].append(group_dn)

    with destination.open("w", encoding="utf-8", newline="\n") as stream:
        writer = LDIFWriter(stream, cols=1000)
        write_entry(
            writer,
            service.base_dn,
            {
                "objectClass": ["top", "dcObject", "organization"],
                "dc": [ldap.dn.str2dn(service.base_dn)[0][0][1]],
                "o": [directory.organization],
                "entryUUID": [
                    stable_uuid(directory.namespace, "service-base", service.service_id)
                ],
            },
        )
        for ou_name, ou_dn in (
            ("people", people_dn),
            ("groups", groups_dn),
            ("services", services_dn),
        ):
            write_entry(
                writer,
                ou_dn,
                {
                    "objectClass": ["top", "organizationalUnit"],
                    "ou": [ou_name],
                    "entryUUID": [
                        stable_uuid(
                            directory.namespace,
                            "service-container",
                            f"{service.service_id}:{ou_name}",
                        )
                    ],
                },
            )

        for user_id in sorted(
            selected, key=lambda item: directory.users[item].uid.casefold()
        ):
            user = directory.users[user_id]
            password = read_password(
                user_password_file(credentials, user_id, service.service_id),
                context=f"password file for user {user_id} and service {service.service_id}",
            )
            attributes = {
                "objectClass": ["top", "inetOrgPerson"],
                "uid": [user.uid],
                "cn": [user.common_name],
                "sn": [user.surname],
                "entryUUID": [stable_uuid(directory.namespace, "user", user.source_id)],
                "userPassword": [hash_password(password)],
            }
            if user.mail is not None:
                attributes["mail"] = [user.mail]
            if memberships[user_id]:
                attributes["memberOf"] = sorted(memberships[user_id], key=str.casefold)
            write_entry(
                writer,
                f"uid={ldap.dn.escape_dn_chars(user.uid)},{people_dn}",
                attributes,
            )

        if service.service_id not in credentials.services:
            error(f"no bind credential is defined for service {service.service_id}")
        bind_password = read_password(
            credentials.services[service.service_id],
            context=f"bind password file for service {service.service_id}",
        )
        write_entry(
            writer,
            bind_dn,
            {
                "objectClass": ["top", "organizationalRole", "simpleSecurityObject"],
                "cn": [service.bind_account.common_name],
                "entryUUID": [
                    stable_uuid(
                        directory.namespace,
                        "service-bind",
                        service.bind_account.source_id,
                    )
                ],
                "userPassword": [hash_password(bind_password)],
            },
        )

        for group_id in service.groups:
            group = directory.groups[group_id]
            if not group_member_dns[group_id]:
                continue
            write_entry(
                writer,
                f"cn={ldap.dn.escape_dn_chars(group.common_name)},{groups_dn}",
                {
                    "objectClass": ["top", "groupOfNames"],
                    "cn": [group.common_name],
                    "entryUUID": [
                        stable_uuid(directory.namespace, "group", group.source_id)
                    ],
                    "member": sorted(group_member_dns[group_id], key=str.casefold),
                },
            )


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
    except ValueError as exc:
        error(f"--generated-at is invalid: {exc}")
    if result.microsecond:
        error("--generated-at must use whole seconds")
    return result


def validate_signing_key(path: Path) -> None:
    try:
        file_stat = path.lstat()
    except OSError as exc:
        error(f"cannot inspect signing key: {exc}")
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        error("signing key must be a regular file, not a symbolic link")
    if file_stat.st_mode & 0o077:
        error("signing key must not be readable or writable by group or other users")
    if not os.access(path, os.R_OK):
        error("signing key is not readable")


def sign_manifest(
    manifest_path: Path, signing_key: Path, service_id: str, revision: int
) -> None:
    signature_path = manifest_path.with_name("manifest.json.minisig")
    command = [
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
        f"openldap snapshot {service_id} revision {revision}",
    ]
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        error(f"cannot execute minisign: {exc}")
    if result.returncode != 0:
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit status {result.returncode}"
        )
        error(f"minisign could not sign the manifest: {detail}")
    os.chmod(signature_path, 0o600)


def generate_service(
    destination: Path,
    directory: Directory,
    credentials: Credentials,
    service: Service,
    signing_key: Path,
    generated_at: datetime,
) -> None:
    destination.mkdir(mode=0o700)
    ldif_path = destination / "directory.ldif"
    write_service_ldif(ldif_path, directory, credentials, service)
    os.chmod(ldif_path, 0o600)
    digest = hashlib.sha256(ldif_path.read_bytes()).hexdigest()
    manifest = {
        "format_version": 1,
        "service_id": service.service_id,
        "base_dn": service.base_dn,
        "revision": service.revision,
        "generated_at": iso_timestamp(generated_at),
        "soft_expires_at": iso_timestamp(
            generated_at
            + timedelta(
                seconds=service.soft_ttl_seconds - service.expiry_offset_seconds
            )
        ),
        "expires_at": iso_timestamp(
            generated_at
            + timedelta(
                seconds=service.hard_ttl_seconds - service.expiry_offset_seconds
            )
        ),
        "uuid_namespace": str(directory.namespace),
        "files": [{"path": ldif_path.name, "sha256": digest}],
    }
    manifest_path = destination / "manifest.json"
    with manifest_path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, indent=2, ensure_ascii=True)
        stream.write("\n")
    os.chmod(manifest_path, 0o600)
    sign_manifest(manifest_path, signing_key, service.service_id, service.revision)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory", required=True, type=Path, help="identity and authorization YAML"
    )
    parser.add_argument(
        "--credentials", required=True, type=Path, help="credential file reference YAML"
    )
    parser.add_argument(
        "--signing-key", required=True, type=Path, help="minisign secret key"
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="new output directory"
    )
    parser.add_argument(
        "--service",
        action="append",
        default=[],
        help="generate only this service; repeatable",
    )
    parser.add_argument(
        "--generated-at",
        help="fixed RFC 3339 UTC generation time, primarily for testing",
    )
    return parser.parse_args()


def main() -> int:
    os.umask(0o077)
    arguments = parse_arguments()
    directory = parse_directory(arguments.directory)
    credentials = parse_credentials(arguments.credentials)
    validate_credential_references(directory, credentials)
    validate_signing_key(arguments.signing_key)
    generated_at = parse_generated_at(arguments.generated_at)

    selected_service_ids = arguments.service or sorted(directory.services)
    if len(selected_service_ids) != len(set(selected_service_ids)):
        error("--service must not select the same service more than once")
    unknown_services = set(selected_service_ids) - set(directory.services)
    if unknown_services:
        error(f"unknown selected services: {', '.join(sorted(unknown_services))}")
    if not selected_service_ids:
        error("directory YAML does not define any services")

    output = arguments.output.absolute()
    if output.exists() or output.is_symlink():
        error(f"output path already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    os.chmod(staging, 0o700)
    try:
        for service_id in selected_service_ids:
            generate_service(
                staging / service_id,
                directory,
                credentials,
                directory.services[service_id],
                arguments.signing_key,
                generated_at,
            )
        staging.rename(output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    for service_id in selected_service_ids:
        service = directory.services[service_id]
        print(f"generated {output / service_id} revision {service.revision}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConfigurationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except Exception as exc:
        print(f"ERROR: generator failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
