#!/usr/bin/python3

"""Create a users/groups definition with fresh UUIDs and credential-file references."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

import yaml

from generator.generate import parse_directory, validate_base_dn, validate_uid
from scripts.directory_data import ConfigurationError


# Implements: IP0008
def initialize(
    output: Path,
    *,
    directory_id: str,
    base_dn: str,
    organization: str | None = None,
    username: str = "alice",
    bind_username: str = "application",
    groupname: str = "staff",
) -> None:
    base_dn = validate_base_dn(base_dn, context="base_dn")
    username = validate_uid(username, context="username")
    bind_username = validate_uid(bind_username, context="bind_username")
    groupname = validate_uid(groupname, context="groupname")
    directory_uuid, user_uuid, group_uuid, bind_uuid = (
        str(uuid.uuid4()) for _ in range(4)
    )
    document: dict[str, Any] = {
        "format_version": 1,
        "directory_id": directory_id,
        "base_dn": base_dn,
        "revision": 1,
        "soft_ttl_seconds": 21600,
        "hard_ttl_seconds": 43200,
        "input_type": "users-groups",
        "entry_uuid": directory_uuid,
        "organization": organization if organization is not None else directory_id,
        "users": [
            {
                "entry_uuid": user_uuid,
                "username": username,
                "last_name": username,
                "active": True,
                "password_hash_file": f"/run/credentials/{username}.hash",
            }
        ],
        "groups": [
            {
                "entry_uuid": group_uuid,
                "groupname": groupname,
                "members": [user_uuid],
            }
        ],
        "bind_accounts": [
            {
                "entry_uuid": bind_uuid,
                "username": bind_username,
                "password_hash_file": f"/run/credentials/{bind_username}.hash",
            }
        ],
    }
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ConfigurationError("output path already exists")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix=".openldap-init-", dir=output.parent
    ) as stream:
        yaml.safe_dump(document, stream, sort_keys=False, allow_unicode=False)
        stream.flush()
        parse_directory(Path(stream.name))
        os.fsync(stream.fileno())
        # Publish a complete file without replacing a concurrent creator's output.
        try:
            os.link(stream.name, output)
        except FileExistsError:
            raise ConfigurationError("output path already exists") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory-id", required=True)
    parser.add_argument("--base-dn", required=True)
    parser.add_argument("--organization", help="defaults to the directory ID")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--bind-username", default="application")
    parser.add_argument("--groupname", default="staff")
    parser.add_argument("--output", type=Path, default=Path("/output/directory.yaml"))
    arguments = parser.parse_args()
    initialize(
        arguments.output,
        directory_id=arguments.directory_id,
        base_dn=arguments.base_dn,
        organization=arguments.organization,
        username=arguments.username,
        bind_username=arguments.bind_username,
        groupname=arguments.groupname,
    )
    print(f"created {arguments.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConfigurationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except OSError:
        print(
            "ERROR: cannot create the definition; check the output directory",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
