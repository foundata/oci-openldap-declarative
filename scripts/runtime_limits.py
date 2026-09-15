"""Bound the entrypoint's inherited limits before it launches OpenLDAP tools."""

from __future__ import annotations

import argparse
import os
import re
import resource
import sys


# Implements: IP0006
def open_files_cap() -> int:
    value = os.environ.get("LDAP_MAX_OPEN_FILES", "4096")
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > 2147483647:
        raise ValueError("LDAP_MAX_OPEN_FILES must be an integer from 1 to 2147483647")
    return int(value)


# Implements: IP0006
def clamp_open_files(pid: int, cap: int) -> None:
    current = resource.prlimit(pid, resource.RLIMIT_NOFILE)
    soft, hard = (
        cap if limit == resource.RLIM_INFINITY else min(limit, cap) for limit in current
    )
    if (soft, hard) != current:
        # slapd sizes its connection table from this limit, even before any binds.
        resource.prlimit(pid, resource.RLIMIT_NOFILE, (soft, hard))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pid", type=int)
    args = parser.parse_args(argv)
    if args.pid <= 0:
        parser.error("pid must be positive")
    try:
        cap = open_files_cap()
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 64
    try:
        clamp_open_files(args.pid, cap)
    except (OSError, ValueError) as error:
        print(f"ERROR: Cannot bound open-file limits: {error}", file=sys.stderr)
        return 70
    return 0


if __name__ == "__main__":
    sys.exit(main())
