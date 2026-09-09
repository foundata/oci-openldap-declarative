"""Exercise the generator's input validation without containers or Podman."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
import yaml
from argon2 import PasswordHasher
from jsonschema import Draft202012Validator

from tests.namespace_cases import NAMESPACE_CASES
from tests.password_hash_cases import HASH_CASES, VALID_HASH

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples/generator"
NAMESPACE = uuid.UUID("7f38d690-8427-5ca2-98b4-bd5ee71ac31f")


@pytest.fixture(scope="module")
def generate() -> ModuleType:
    """Load the generator script as a module without touching sys.path."""
    spec = importlib.util.spec_from_file_location(
        "openldap_generate", ROOT / "generator/generate.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves string annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def example_directory(generate: ModuleType) -> object:
    return generate.parse_directory(EXAMPLES / "directory.yaml")


def write_secret(path: Path, content: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(content)
    path.chmod(mode)
    return path


def test_base_dn_is_canonicalized(generate: ModuleType) -> None:
    dn = generate.validate_base_dn(
        "DC=example-app, dc=services,dc=example,dc=org", context="dn"
    )

    assert dn == "DC=example-app,dc=services,dc=example,dc=org"


@pytest.mark.parametrize(("namespace", "valid"), NAMESPACE_CASES)
def test_namespace_parser_and_public_schemas_agree(
    generate: ModuleType, tmp_path: Path, namespace: str, valid: bool
) -> None:
    directory = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    directory["uuid_namespace"] = namespace
    source = tmp_path / "directory.yaml"
    source.write_text(yaml.safe_dump(directory), encoding="utf-8")
    if valid:
        assert str(generate.parse_directory(source).namespace) == namespace.lower()
    else:
        with pytest.raises(generate.ConfigurationError, match="uuid_namespace"):
            generate.parse_directory(source)
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    assert Draft202012Validator(schema).is_valid(directory) is valid
    schema = json.loads((ROOT / "schema/snapshot-manifest-v1.schema.json").read_text())
    manifest = json.loads(
        (ROOT / "tests/fixtures/snapshot-manifest-valid.json").read_text()
    )
    manifest["uuid_namespace"] = namespace.lower()
    assert Draft202012Validator(schema).is_valid(manifest) is valid


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            "ou=people,dc=example,dc=org", "must begin with one dc RDN", id="ou-first"
        ),
        pytest.param(
            "dc=a+ou=b,dc=example", "must begin with one dc RDN", id="multi-valued"
        ),
        pytest.param("not a dn", "is not a valid LDAP DN", id="syntax"),
        pytest.param(
            "dc=exämple", "must contain only ASCII characters", id="non-ascii"
        ),
    ],
)
def test_invalid_base_dns_are_rejected(
    generate: ModuleType, value: str, message: str
) -> None:
    with pytest.raises(generate.ConfigurationError, match=message):
        generate.validate_base_dn(value, context="dn")


def test_password_file_yields_one_line_without_its_terminator(
    generate: ModuleType, tmp_path: Path
) -> None:
    unix = write_secret(tmp_path / "unix", b"s3cret\n")
    windows = write_secret(tmp_path / "windows", b"s3cret\r\n")

    assert generate.read_credential_file(str(unix), context="unix") == "s3cret"
    assert generate.read_credential_file(str(windows), context="windows") == "s3cret"


@pytest.mark.parametrize(
    ("content", "mode", "message"),
    [
        pytest.param(
            b"s3cret\n", 0o640, "must not be readable or writable by group", id="group"
        ),
        pytest.param(b"\n", 0o600, "exactly one non-empty line", id="empty"),
        pytest.param(
            b"one\ntwo\n", 0o600, "exactly one non-empty line", id="two-lines"
        ),
        pytest.param(b"x" * 4097, 0o600, "exceeds the 4096-byte limit", id="oversized"),
        pytest.param(b"\xff\n", 0o600, "must contain valid UTF-8", id="not-utf-8"),
    ],
)
def test_unsafe_password_files_are_rejected(
    generate: ModuleType, tmp_path: Path, content: bytes, mode: int, message: str
) -> None:
    secret = write_secret(tmp_path / "secret", content, mode)

    with pytest.raises(generate.ConfigurationError, match=message):
        generate.read_credential_file(str(secret), context="secret")


def test_password_file_symlinks_are_rejected(
    generate: ModuleType, tmp_path: Path
) -> None:
    target = write_secret(tmp_path / "target", b"s3cret\n")
    link = tmp_path / "link"
    os.symlink(target, link)

    with pytest.raises(generate.ConfigurationError, match="not a symbolic link"):
        generate.read_credential_file(str(link), context="secret")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        pytest.param("a: 1\na: 2\n", "duplicate YAML key: a", id="duplicate-key"),
        pytest.param("a: &x 1\nb: *x\n", "YAML aliases are not accepted", id="alias"),
        pytest.param("- item\n", "must contain one top-level mapping", id="sequence"),
        pytest.param(
            "1: value\n", "all YAML mapping keys must be strings", id="integer-key"
        ),
    ],
)
def test_strict_yaml_loading_rejects_ambiguous_documents(
    generate: ModuleType, tmp_path: Path, content: str, message: str
) -> None:
    document = tmp_path / "input.yaml"
    document.write_text(content, encoding="utf-8")

    with pytest.raises(generate.ConfigurationError, match=message):
        generate.load_yaml(document, context="document")


def test_generation_time_defaults_to_whole_utc_seconds(generate: ModuleType) -> None:
    value = generate.parse_generated_at(None)

    assert value.tzinfo is UTC
    assert value.microsecond == 0
    assert generate.parse_generated_at("2030-01-01T00:00:00Z") == datetime(
        2030, 1, 1, tzinfo=UTC
    )


@pytest.mark.parametrize(
    ("value", "message"),
    [
        pytest.param(
            "2030-01-01T00:00:00+00:00",
            "must be an RFC 3339 UTC timestamp",
            id="offset",
        ),
        pytest.param("2030-01-01T00:00:00.5Z", "must use whole seconds", id="fraction"),
        pytest.param("yesterdayZ", "is invalid", id="garbage"),
    ],
)
def test_controlled_generation_times_are_strict(
    generate: ModuleType, value: str, message: str
) -> None:
    with pytest.raises(generate.ConfigurationError, match=message):
        generate.parse_generated_at(value)


def test_stable_uuids_derive_from_entity_type_and_source_id(
    generate: ModuleType,
) -> None:
    user = generate.stable_uuid(NAMESPACE, "user", "person-0001")

    assert user == str(uuid.uuid5(NAMESPACE, "user:person-0001"))
    assert user == generate.stable_uuid(NAMESPACE, "user", "person-0001")
    assert user != generate.stable_uuid(NAMESPACE, "group", "person-0001")


def test_password_hashes_use_the_documented_argon2id_parameters(
    generate: ModuleType,
) -> None:
    verifier = generate.hash_password("correct horse battery staple")

    assert verifier.startswith("{ARGON2}$argon2id$v=19$m=19456,t=2,p=1$")
    assert PasswordHasher().verify(
        verifier.removeprefix("{ARGON2}"), "correct horse battery staple"
    )


@pytest.fixture(scope="module")
def seeded_hash(generate: ModuleType) -> str:
    return str(generate.hash_password("TEST-ONLY-seeded-password"))


@pytest.mark.parametrize(("verifier", "valid"), HASH_CASES)
def test_generator_and_runtime_password_hash_contract(
    generate: ModuleType, tmp_path: Path, verifier: str, valid: bool
) -> None:
    if valid:
        assert (
            generate.validate_password_hash(verifier, context="credential") == verifier
        )
    else:
        with pytest.raises(generate.ConfigurationError) as raised:
            generate.validate_password_hash(verifier, context="credential")
        assert not verifier or verifier not in str(raised.value)

    # Each LDIF value is one record; the importer separately rejects embedded LF/NUL.
    if "\n" in verifier or "\x00" in verifier:
        return
    values = tmp_path / "hashes"
    values.write_text(VALID_HASH + "\n" + verifier + "\n", encoding="utf-8")
    result = subprocess.run(
        [
            "sh",
            "-c",
            '. "$1"; validate_password_hashes "$2"',
            "hash-validation",
            str(ROOT / "scripts/common.sh"),
            str(values),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == (0 if valid else 1), result.stdout + result.stderr
    assert not result.stdout and not result.stderr


@pytest.mark.parametrize("kind", ["hash", "hash-file", "plaintext-file"])
def test_credential_sources_are_explicit_and_hashes_are_preserved(
    generate: ModuleType, tmp_path: Path, seeded_hash: str, kind: str
) -> None:
    value = seeded_hash
    if kind != "hash":
        value = str(write_secret(tmp_path / "credential", (value + "\r\n").encode()))
    source = generate.credential_source(kind, value, context="credential")
    result = generate.password_verifier(source, context="credential")
    assert seeded_hash not in repr(source)
    if kind == "plaintext-file":
        # A hash-looking plaintext password must not silently change meaning.
        assert result != seeded_hash
        assert PasswordHasher().verify(result.removeprefix("{ARGON2}"), seeded_hash)
    else:
        assert result == seeded_hash


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("{ARGON2}", "{SSHA}"),
        ("argon2id", "argon2i"),
        ("v=19", "v=16"),
        ("m=19456", "m=8192"),
        ("t=2", "t=1"),
        ("p=1", "p=0"),
        ("p=1", "p=16777216"),
        ("p=1", "p=3000"),
        ("m=19456", "m=4294967296"),
        ("t=2", "t=4294967296"),
    ],
)
def test_unsupported_seeded_hashes_are_rejected_without_echoing_them(
    generate: ModuleType, seeded_hash: str, old: str, new: str
) -> None:
    invalid = seeded_hash.replace(old, new)
    with pytest.raises(generate.ConfigurationError) as raised:
        generate.validate_password_hash(invalid, context="credential")
    assert invalid not in str(raised.value)


@pytest.mark.parametrize(
    ("salt", "digest"),
    [
        ("YQ", "Yg" * 22),
        ("YQ" * 11, "Yg"),
        ("YQ" * 10 + "YR", "Yg" * 22),
        ("YQ" * 11 + "=", "Yg" * 22),
        ("YQ" * 11, "Yg" * 22 + "A"),
    ],
)
def test_seeded_hash_lengths_and_base64_are_checked(
    generate: ModuleType, salt: str, digest: str
) -> None:
    verifier = "{ARGON2}$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$" + digest
    with pytest.raises(generate.ConfigurationError):
        generate.validate_password_hash(verifier, context="credential")


@pytest.mark.parametrize(
    ("default", "override", "bind"),
    [
        ("password_file", "service_password_hash_files", "bind_password_hash"),
        ("password_hash_file", "service_password_hashes", "bind_password_file"),
        ("password_hash", "service_password_files", "bind_password_hash_file"),
    ],
)
def test_credentials_schema_and_parser_accept_mixed_sources(
    generate: ModuleType,
    tmp_path: Path,
    seeded_hash: str,
    default: str,
    override: str,
    bind: str,
) -> None:
    document = {
        "format_version": 1,
        "users": {
            "person-0001": {
                default: seeded_hash if default == "password_hash" else "/secret",
                override: {
                    "example-app": seeded_hash
                    if override == "service_password_hashes"
                    else "/override"
                },
            }
        },
        "services": {
            "example-app": {
                bind: seeded_hash if bind == "bind_password_hash" else "/bind"
            }
        },
    }
    source = write_secret(
        tmp_path / "credentials.yaml", yaml.safe_dump(document).encode()
    )
    schema = json.loads((ROOT / "schema/credentials-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(document)
    parsed = generate.parse_credentials(source)
    user = parsed.users["person-0001"]
    assert (
        generate.user_credential(parsed, "person-0001", "example-app")
        == user.services["example-app"]
    )
    assert (
        generate.user_credential(parsed, "person-0001", "example-mail") == user.default
    )
    assert seeded_hash not in repr(parsed)


@pytest.mark.parametrize("bind", [False, True])
@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("password_file", "password_hash_file"),
        ("password_file", "password_hash"),
        ("password_hash_file", "password_hash"),
    ],
)
def test_credentials_reject_conflicting_defaults(
    generate: ModuleType,
    tmp_path: Path,
    seeded_hash: str,
    bind: bool,
    first: str,
    second: str,
) -> None:
    prefix = "bind_" if bind else ""
    item = {
        prefix + key: seeded_hash if key == "password_hash" else "/secret"
        for key in (first, second)
    }
    document = {
        "format_version": 1,
        "users": {} if bind else {"person-0001": item},
        "services": {"example-app": item} if bind else {},
    }
    source = write_secret(
        tmp_path / "credentials.yaml", yaml.safe_dump(document).encode()
    )
    schema = json.loads((ROOT / "schema/credentials-v1.schema.json").read_text())
    assert not Draft202012Validator(schema).is_valid(document)
    with pytest.raises(generate.ConfigurationError, match="must not combine"):
        generate.parse_credentials(source)


def test_credentials_reject_conflicting_service_overrides(
    generate: ModuleType, tmp_path: Path, seeded_hash: str
) -> None:
    document = {
        "format_version": 1,
        "users": {
            "person-0001": {
                "service_password_files": {"example-app": "/secret"},
                "service_password_hashes": {"example-app": seeded_hash},
            }
        },
        "services": {},
    }
    source = write_secret(
        tmp_path / "credentials.yaml", yaml.safe_dump(document).encode()
    )
    with pytest.raises(generate.ConfigurationError, match="conflicting sources"):
        generate.parse_credentials(source)


def test_inline_hash_yaml_is_private_and_syntax_errors_do_not_leak_hashes(
    generate: ModuleType, tmp_path: Path, seeded_hash: str
) -> None:
    document = {
        "format_version": 1,
        "users": {},
        "services": {"example-app": {"bind_password_hash": seeded_hash}},
    }
    source = write_secret(
        tmp_path / "credentials.yaml", yaml.safe_dump(document).encode(), 0o644
    )
    with pytest.raises(generate.ConfigurationError, match="readable only by its owner"):
        generate.parse_credentials(source)
    source.write_text(f'password_hash: "{seeded_hash}\n')
    with pytest.raises(generate.ConfigurationError) as raised:
        generate.load_yaml(source, context="credentials YAML")
    assert seeded_hash not in str(raised.value)


def test_example_directory_selects_active_users_per_service(
    generate: ModuleType, example_directory: object
) -> None:
    directory = example_directory
    services = directory.services  # type: ignore[attr-defined]

    assert set(services) == {"example-app", "example-mail"}
    assert services["example-app"].revision == 1
    assert services["example-mail"].expiry_offset_seconds == 600
    assert generate.selected_users(directory, services["example-app"]) == {
        "person-0001"
    }
    assert generate.selected_users(directory, services["example-mail"]) == {
        "person-0001",
        "person-0003",
    }


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        pytest.param(
            "expiry_offset_seconds: 0",
            "expiry_offset_seconds: 21600",
            "expiry_offset_seconds must be less than soft_ttl_seconds",
            id="offset-reaches-soft-ttl",
        ),
        pytest.param(
            "expiry_offset_seconds: 0",
            "expiry_offset_seconds: -1",
            "expiry_offset_seconds must be an integer from 0 through 86400",
            id="negative-offset",
        ),
        pytest.param(
            "hard_ttl_seconds: 43200",
            "hard_ttl_seconds: 21600",
            "soft_ttl_seconds must be less than hard_ttl_seconds",
            id="soft-reaches-hard",
        ),
        pytest.param(
            '      - "group-staff"\n    users: []',
            '      - "group-missing"\n    users: []',
            "references unknown groups: group-missing",
            id="unknown-group",
        ),
        pytest.param(
            'uid: "bob"',
            'uid: "ALICE"',
            "duplicate user uid",
            id="case-insensitive-uid",
        ),
    ],
)
def test_directory_policy_violations_are_rejected(
    generate: ModuleType, tmp_path: Path, old: str, new: str, message: str
) -> None:
    content = (EXAMPLES / "directory.yaml").read_text(encoding="utf-8")
    assert old in content
    variant = tmp_path / "directory.yaml"
    variant.write_text(content.replace(old, new, 1), encoding="utf-8")

    with pytest.raises(generate.ConfigurationError, match=message):
        generate.parse_directory(variant)


def test_credentials_resolve_service_overrides_before_defaults(
    generate: ModuleType, example_directory: object
) -> None:
    credentials = generate.parse_credentials(EXAMPLES / "credentials.yaml.example")
    generate.validate_credential_references(example_directory, credentials)

    assert (
        generate.user_credential(credentials, "person-0001", "example-app").value
        == "/run/credentials/person-0001-example-app"
    )
    assert (
        generate.user_credential(credentials, "person-0001", "other").value
        == "/run/credentials/person-0001"
    )
    with pytest.raises(
        generate.ConfigurationError, match="no default or example-app-specific"
    ):
        generate.user_credential(credentials, "person-0003", "example-app")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        pytest.param(
            "format_version: 1\nusers:\n  person-0001: {}\nservices: {}\n",
            "must define at least one password source",
            id="no-password-source",
        ),
        pytest.param(
            "format_version: 1\nusers:\n  person-0001:\n"
            "    password_file: relative\nservices: {}\n",
            "must be an absolute path",
            id="relative-path",
        ),
    ],
)
def test_credential_documents_are_validated(
    generate: ModuleType, tmp_path: Path, content: str, message: str
) -> None:
    document = tmp_path / "credentials.yaml"
    document.write_text(content, encoding="utf-8")

    with pytest.raises(generate.ConfigurationError, match=message):
        generate.parse_credentials(document)


def test_credentials_for_unknown_users_are_rejected(
    generate: ModuleType, tmp_path: Path, example_directory: object
) -> None:
    document = tmp_path / "credentials.yaml"
    document.write_text(
        "format_version: 1\nusers:\n  person-9999:\n"
        "    password_file: /run/credentials/x\n"
        "services: {}\n",
        encoding="utf-8",
    )
    credentials = generate.parse_credentials(document)

    with pytest.raises(
        generate.ConfigurationError, match="reference unknown users: person-9999"
    ):
        generate.validate_credential_references(example_directory, credentials)
