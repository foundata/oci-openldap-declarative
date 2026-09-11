#!/usr/bin/env python3

"""Check custom slapd configuration against the container's runtime envelope."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

try:
    from scripts.directory_data import (
        MAX_DATA_BYTES,
        ConfigurationError,
        Entry,
        dn_key,
        parse_ldif,
        read_regular,
    )
except ModuleNotFoundError:
    from directory_data import (  # type: ignore[no-redef]
        MAX_DATA_BYTES,
        ConfigurationError,
        Entry,
        dn_key,
        parse_ldif,
        read_regular,
    )

RUNTIME_DIR = "/run/openldap"
MODULES = frozenset(
    {
        "back_mdb",
        "argon2",
        "memberof",
        "sssvlv",
        "dynlist",
        "deref",
        "rwm",
        "ppolicy",
        "refint",
        "unique",
        "constraint",
        "valsort",
        "auditlog",
        "syncprov",
    }
)


def text_values(attributes: dict[str, list[bytes]], name: str) -> list[str]:
    try:
        return [value.decode("utf-8") for value in attributes.get(name, [])]
    except UnicodeError:
        raise ConfigurationError("configuration values must use UTF-8") from None


def validate_config(entries: list[Entry], base_dn: str) -> None:
    """Leave OpenLDAP syntax and policy to slapd; enforce import/lifecycle limits."""
    config = dn_key("cn=config")
    seen = set()
    databases: list[dict[str, list[bytes]]] = []
    for dn, attributes in entries:
        key = dn_key(dn)
        if key[-1:] != config:
            raise ConfigurationError("configuration entries must be under cn=config")
        if key in seen:
            raise ConfigurationError("configuration contains duplicate DNs")
        seen.add(key)
        for name in attributes:
            if ";" in name or not name[0].isalpha():
                raise ConfigurationError(
                    "configuration attributes must use names without options"
                )
        if "olcloglevel" in attributes:
            raise ConfigurationError("LDAP_LOG_LEVEL owns logging; omit olcLogLevel")
        if any(
            name in attributes
            for name in ("olcsyncrepl", "olcmultiprovider", "olcmirrormode")
        ):
            raise ConfigurationError(
                "replication consumers are outside the snapshot import contract"
            )
        for name, expected in (
            ("olcpidfile", f"{RUNTIME_DIR}/slapd.pid"),
            ("olcargsfile", f"{RUNTIME_DIR}/slapd.args"),
            ("olcmodulepath", "/usr/lib/ldap"),
        ):
            if name in attributes and text_values(attributes, name) != [expected]:
                raise ConfigurationError(
                    f"{name} conflicts with the runtime filesystem layout"
                )
        for value in text_values(attributes, "olcmoduleload"):
            value = re.sub(r"^\{[0-9]+\}", "", value)
            parts = value.split()
            if not parts or re.sub(r"\.(?:la|so)$", "", parts[0]) not in MODULES:
                raise ConfigurationError(
                    "olcModuleLoad must name a packaged module without a path"
                )
        for value in text_values(attributes, "olcdatabase"):
            backend = re.sub(r"^\{-?[0-9]+\}", "", value).lower()
            if backend == "mdb":
                databases.append(attributes)
            elif backend not in {"config", "frontend"}:
                raise ConfigurationError(
                    "custom configuration supports one MDB data database"
                )
    if config not in seen or dn_key("cn=schema,cn=config") not in seen:
        raise ConfigurationError(
            "custom configuration requires cn=config and cn=schema,cn=config"
        )
    if len(databases) != 1:
        raise ConfigurationError(
            "custom configuration requires exactly one MDB data database"
        )
    database = databases[0]
    suffixes = text_values(database, "olcsuffix")
    if len(suffixes) != 1 or dn_key(suffixes[0]) != dn_key(base_dn):
        raise ConfigurationError(
            "olcSuffix must match the signed base_dn import target"
        )
    if text_values(database, "olcdbdirectory") != [f"{RUNTIME_DIR}/data"]:
        raise ConfigurationError("olcDbDirectory must be /run/openldap/data")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dn", required=True)
    parser.add_argument("--check-health", type=Path)
    parser.add_argument("--ldapi-uri", default="ldapi://%2Frun%2Fopenldap%2Fldapi")
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    entries = parse_ldif(
        read_regular(args.config, maximum=MAX_DATA_BYTES, context="configuration LDIF")
    )
    validate_config(entries, args.base_dn)
    if args.check_health is not None:
        check_health_access(entries, args.base_dn, args.check_health, args.ldapi_uri)


def check_health_access(
    entries: list[Entry], base_dn: str, config_dir: Path, uri: str
) -> None:
    root = next(
        attributes for dn, attributes in entries if dn_key(dn) == dn_key("cn=config")
    )
    try:
        ssf = int(text_values(root, "olclocalssf")[0]) if "olclocalssf" in root else 71
        listener = urlsplit(uri)
    except (ValueError, IndexError):
        raise ConfigurationError(
            "invalid local transport settings for health checks"
        ) from None
    if listener.scheme != "ldapi" or not listener.netloc or ssf < 0:
        raise ConfigurationError("health checks require a local LDAPI socket")
    socket = "PATH=" + unquote(listener.netloc)
    identity = f"gidNumber={os.getgid()}+uidNumber={os.getuid()},cn=peercred,cn=external,cn=auth"
    # slapacl returns zero even for DENIED; require both explicit ALLOWED results.
    command = [
        "slapacl",
        "-F",
        str(config_dir),
        "-b",
        base_dn,
        "-D",
        identity,
        "-X",
        "dn:" + identity,
        "-o",
        f"ssf={ssf}",
        "-o",
        f"transport_ssf={ssf}",
        "-o",
        f"sockurl={uri}",
        "-o",
        f"peername={socket}",
        "-o",
        f"sockname={socket}",
        "entry/read",
        "objectClass/search",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigurationError("cannot verify custom health-check access") from None
    required = {
        "read access to entry: ALLOWED",
        "search access to objectClass: ALLOWED",
    }
    if result.returncode != 0 or not required.issubset(result.stderr.splitlines()):
        raise ConfigurationError(
            "custom configuration must allow the LDAPI health-check identity to read its base entry and search objectClass"
        )


if __name__ == "__main__":
    try:
        main()
    except ConfigurationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(65) from None
