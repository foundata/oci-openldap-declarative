"""Shared PHC format cases, not usable password fixtures or hashing benchmarks."""

from __future__ import annotations

import base64

import pytest


def verifier(
    *,
    parameters: str = "m=19456,t=2,p=1",
    salt: bytes = bytes(range(16)),
    digest: bytes = bytes(range(32)),
) -> str:
    encoded = [base64.b64encode(value).decode().rstrip("=") for value in (salt, digest)]
    return "{ARGON2}$argon2id$v=19$" + parameters + "$" + "$".join(encoded)


VALID_HASH = verifier()
HASH_CASES = [
    pytest.param("", False, id="empty-verifier"),
    pytest.param(VALID_HASH, True, id="minimum"),
    pytest.param(verifier(salt=bytes(17), digest=bytes(33)), True, id="longer"),
    pytest.param(verifier(salt=bytes(18), digest=bytes(34)), True, id="full-triplets"),
    pytest.param(
        verifier(parameters="m=4294967295,t=4294967295,p=16777215"),
        True,
        id="upper-parameter-bounds",
    ),
    pytest.param(verifier(parameters="m=19456,t=2,p=2432"), True, id="memory-per-lane"),
    *[
        pytest.param(VALID_HASH.replace(old, new), False, id=name)
        for name, old, new in [
            ("scheme", "{ARGON2}", "{SSHA}"),
            ("variant", "argon2id", "argon2i"),
            ("version", "v=19", "v=16"),
            ("weak-memory", "m=19456", "m=19455"),
            ("weak-time", "t=2", "t=1"),
            ("zero-lanes", "p=1", "p=0"),
            ("too-many-lanes", "p=1", "p=16777216"),
            ("insufficient-lane-memory", "p=1", "p=2433"),
            ("memory-overflow", "m=19456", "m=4294967296"),
            ("time-overflow", "t=2", "t=4294967296"),
            ("huge-integer", "m=19456", "m=" + "9" * 100),
            ("leading-zero", "t=2", "t=02"),
            ("exponent", "m=19456", "m=2e4"),
            ("parameter-order", "m=19456,t=2", "t=2,m=19456"),
            ("padded-salt", "DA0ODw$", "DA0ODw==$"),
            ("salt-unused-bits", "DA0ODw$", "DA0ODx$"),
            ("digest-unused-bits", "Hh8", "Hh9"),
            ("salt-invalid-length", "DA0ODw$", "DA0OD$"),
            ("digest-invalid-length", "Hh8", "Hh8AA"),
            ("salt-invalid-alphabet", "DA0ODw$", "DA0O_w$"),
            ("digest-invalid-alphabet", "Hh8", "Hh_"),
        ]
    ],
    pytest.param(verifier(salt=bytes(15)), False, id="short-salt"),
    pytest.param(verifier(digest=bytes(31)), False, id="short-digest"),
    pytest.param(verifier(salt=b""), False, id="empty-salt"),
    pytest.param(verifier(digest=b""), False, id="empty-digest"),
    pytest.param(VALID_HASH.rsplit("$", 2)[0] + "$x$x", False, id="reported-malformed"),
    pytest.param(VALID_HASH + "$extra", False, id="extra-field"),
    pytest.param(VALID_HASH + "=", False, id="padded-digest"),
    pytest.param(VALID_HASH + "\n", False, id="trailing-newline"),
    pytest.param(VALID_HASH + "\x00", False, id="trailing-nul"),
    pytest.param(VALID_HASH + "\n" + VALID_HASH, False, id="two-verifiers"),
    pytest.param(verifier(digest=bytes(3072)), False, id="too-long"),
]
