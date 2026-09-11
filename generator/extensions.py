"""Additive LDAP attributes and auxiliary classes for the users/groups input."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ldap.schema import SubSchema
from ldap.schema.models import AttributeType, ObjectClass

from scripts.directory_data import (
    ATTRIBUTE_PATTERN,
    MAX_DATA_BYTES,
    ConfigurationError,
    parse_ldif,
    read_regular,
    validate_schema,
)

SCHEMA_DIRECTORY = Path("/usr/local/share/openldap-declarative/schema")
BUILTIN_SCHEMA_FILES = tuple(
    SCHEMA_DIRECTORY / f"{name}.ldif" for name in ("openldap", "application-user")
)
# Operational attributes are partly built into slapd rather than schema files.
MANAGED_ATTRIBUTES = {
    "objectclass",
    "2.5.4.0",
    "entryuuid",
    "1.3.6.1.1.16.4",
    "userpassword",
    "2.5.4.35",
    "member",
    "2.5.4.31",
    "memberof",
    "1.2.840.113556.1.2.102",
}


@dataclass(frozen=True)
class Extensions:
    attributes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    object_classes: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.attributes or self.object_classes)

    def merge(self, attributes: dict[str, list[str]]) -> dict[str, list[str]]:
        """Merge only after schema-aware collision checks have succeeded."""
        return {
            **attributes,
            **{name: list(values) for name, values in self.attributes.items()},
            "objectClass": [*attributes["objectClass"], *self.object_classes],
        }


def identifier(value: Any, *, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or not ATTRIBUTE_PATTERN.fullmatch(value)
    ):
        raise ConfigurationError(f"{context} requires an LDAP name or numeric OID")
    return value


def parse_extensions(item: dict[str, Any], *, context: str) -> Extensions:
    raw_attributes = item.get("attributes", {})
    if not isinstance(raw_attributes, dict) or len(raw_attributes) > 128:
        raise ConfigurationError(
            f"{context}.attributes requires at most 128 attributes"
        )
    attributes: dict[str, tuple[str, ...]] = {}
    names: set[str] = set()
    for name, values in raw_attributes.items():
        name = identifier(name, context=f"{context}.attributes key")
        if name.casefold() in names:
            raise ConfigurationError(f"{context}.attributes repeats an attribute")
        names.add(name.casefold())
        if not isinstance(values, list) or not 1 <= len(values) <= 64:
            raise ConfigurationError(
                f"{context}.attributes requires 1 through 64 values per attribute"
            )
        if any(
            not isinstance(value, str)
            or not 1 <= len(value) <= 4096
            or any(char in value for char in "\x00\r\n")
            for value in values
        ):
            raise ConfigurationError(
                f"{context}.attributes values must be non-empty strings of at most "
                "4096 characters without NUL or newlines"
            )
        if len(values) != len(set(values)):
            raise ConfigurationError(f"{context}.attributes repeats a value")
        attributes[name] = tuple(values)
    raw_classes = item.get("object_classes", [])
    if not isinstance(raw_classes, list) or len(raw_classes) > 16:
        raise ConfigurationError(
            f"{context}.object_classes requires at most 16 classes"
        )
    classes = tuple(
        identifier(name, context=f"{context}.object_classes item")
        for name in raw_classes
    )
    if len(classes) != len({name.casefold() for name in classes}):
        raise ConfigurationError(f"{context}.object_classes repeats a class")
    return Extensions(attributes, classes)


class SchemaCatalog:
    def __init__(self, schema_files: tuple[Path, ...]) -> None:
        definitions: dict[str, list[str]] = {"attributeTypes": [], "objectClasses": []}
        total = 0
        source_contents: list[bytes] = []
        for index, path in enumerate((*BUILTIN_SCHEMA_FILES, *schema_files)):
            content = read_regular(path, maximum=MAX_DATA_BYTES, context="schema LDIF")
            if index >= len(BUILTIN_SCHEMA_FILES):
                source_contents.append(content)
            total += len(content)
            if total > MAX_DATA_BYTES:
                raise ConfigurationError("schema catalog exceeds the 16 MiB limit")
            entries = parse_ldif(content)
            validate_schema(entries)
            for _, attributes in entries:
                for name in definitions:
                    definitions[name].extend(
                        re.sub(r"^\{[0-9]+\}", "", value.decode("utf-8"))
                        for value in attributes.get(f"olc{name}".lower(), [])
                    )
        try:
            self.schema = SubSchema(definitions, check_uniqueness=2)
        except (ValueError, KeyError, IndexError, AssertionError, TypeError):
            raise ConfigurationError(
                "invalid or conflicting schema definitions"
            ) from None
        self.source_contents = tuple(source_contents)

    def attribute_lineage(self, name: str) -> list[AttributeType]:
        lineage: list[AttributeType] = []
        seen: set[str] = set()
        while True:
            attribute = self.schema.get_obj(AttributeType, name)
            if attribute is None:
                raise ConfigurationError("extension uses an unknown attribute type")
            if attribute.oid in seen or len(seen) >= 128:
                raise ConfigurationError(
                    "cyclic or excessively deep attribute inheritance"
                )
            seen.add(attribute.oid)
            lineage.append(attribute)
            if not attribute.sup:
                return lineage
            if len(attribute.sup) != 1:
                raise ConfigurationError(
                    "attribute type must have at most one superior"
                )
            name = attribute.sup[0]

    def validate(
        self,
        extension: Extensions,
        *,
        reserved: set[str],
        base_classes: tuple[str, ...],
        context: str,
    ) -> None:
        protected = MANAGED_ATTRIBUTES | {name.casefold() for name in reserved}
        protected |= {
            self.schema.getoid(AttributeType, name).casefold() for name in protected
        }
        seen: set[str] = set()
        for name, values in extension.attributes.items():
            if name.casefold() in protected or name.lower().startswith("olc"):
                raise ConfigurationError(
                    f"{context}.attributes contains a reserved attribute"
                )
            lineage = self.attribute_lineage(name)
            for attribute in lineage:
                aliases = {
                    attribute.oid,
                    *(alias.casefold() for alias in attribute.names),
                }
                if aliases & protected or any(
                    alias.startswith("olc") for alias in aliases
                ):
                    raise ConfigurationError(
                        f"{context}.attributes contains a reserved attribute or subtype"
                    )
                if (
                    attribute.usage != 0
                    or attribute.no_user_mod
                    or attribute.collective
                ):
                    raise ConfigurationError(
                        f"{context}.attributes must contain ordinary user attributes"
                    )
                if attribute.single_value and len(values) != 1:
                    raise ConfigurationError(
                        f"{context}.attributes repeats a single-valued attribute"
                    )
            oid = lineage[0].oid
            if oid in seen:
                raise ConfigurationError(
                    f"{context}.attributes repeats an attribute alias"
                )
            seen.add(oid)
        seen = {self.schema.getoid(ObjectClass, name) for name in base_classes}
        for name in extension.object_classes:
            object_class = self.schema.get_obj(ObjectClass, name)
            if object_class is None:
                raise ConfigurationError(
                    f"{context}.object_classes uses an unknown class"
                )
            if (
                object_class.kind != 2
                or object_class.oid == "1.3.6.1.4.1.1466.101.120.111"
                or any(
                    alias.lower() == "extensibleobject" for alias in object_class.names
                )
            ):
                raise ConfigurationError(
                    f"{context}.object_classes requires auxiliary classes other than extensibleObject"
                )
            if object_class.oid in seen:
                raise ConfigurationError(
                    f"{context}.object_classes repeats a generated class or alias"
                )
            seen.add(object_class.oid)
            self.validate_class_ancestors(name)

    def validate_class_ancestors(self, name: str) -> None:
        pending: list[tuple[str, frozenset[str]]] = [(name, frozenset())]
        count = 0
        while pending:
            name, ancestors = pending.pop()
            count += 1
            if name.lower() in {"extensibleobject", "1.3.6.1.4.1.1466.101.120.111"}:
                raise ConfigurationError(
                    "extensions must not inherit from extensibleObject"
                )
            object_class = self.schema.get_obj(ObjectClass, name)
            if object_class is None:
                raise ConfigurationError(
                    "extension uses an unknown superior object class"
                )
            if object_class.oid in ancestors or count > 128:
                raise ConfigurationError(
                    "cyclic or excessively deep object class inheritance"
                )
            if (
                object_class.kind == 0
                or object_class.oid == "1.3.6.1.4.1.1466.101.120.111"
            ):
                raise ConfigurationError(
                    "extensions must not inherit structural classes or extensibleObject"
                )
            pending.extend(
                (parent, ancestors | {object_class.oid}) for parent in object_class.sup
            )
