#!/usr/bin/python3

"""Read one password from stdin and print an LDAP Argon2id verifier."""

from __future__ import annotations

import sys

from generator.generate import decode_credential, hash_password
from scripts.directory_data import ConfigurationError


def main() -> int:
    if sys.argv[1:] in (["-h"], ["--help"]):
        print("Usage: openldap-password < password-file\n\n" + str(__doc__))
        return 0
    if len(sys.argv) != 1 or sys.stdin.isatty():
        raise ConfigurationError("provide the password only through piped stdin")
    password = decode_credential(sys.stdin.buffer.read(4097), context="password input")
    print(hash_password(password))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConfigurationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except Exception:
        print("ERROR: password hashing failed", file=sys.stderr)
        raise SystemExit(1) from None
