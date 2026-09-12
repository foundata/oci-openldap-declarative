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

from tests.entry_uuid_cases import ENTRY_UUID_CASES
from tests.password_hash_cases import HASH_CASES, VALID_HASH

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples/generator"
DIRECTORY_UUID = "c5fa5db6-3963-44c2-9834-9409d1ab9f86"


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


@pytest.mark.parametrize(("entry_uuid", "valid"), ENTRY_UUID_CASES)
def test_base_uuid_parser_and_public_schemas_agree(
    generate: ModuleType, tmp_path: Path, entry_uuid: str, valid: bool
) -> None:
    directory = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    directory["entry_uuid"] = entry_uuid
    source = tmp_path / "directory.yaml"
    source.write_text(yaml.safe_dump(directory), encoding="utf-8")
    if valid:
        assert str(generate.parse_directory(source).entry_uuid) == entry_uuid
    else:
        with pytest.raises(generate.ConfigurationError, match="entry_uuid"):
            generate.parse_directory(source)
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    assert Draft202012Validator(schema).is_valid(directory) is valid
    schema = json.loads((ROOT / "schema/snapshot-manifest-v1.schema.json").read_text())
    manifest = json.loads(
        (ROOT / "tests/fixtures/snapshot-manifest-valid.json").read_text()
    )
    manifest["entry_uuid"] = entry_uuid
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
        pytest.param("a: 1\na: 2\n", "duplicate YAML key", id="duplicate-key"),
        pytest.param("a: &x 1\nb: *x\n", "YAML aliases are not accepted", id="alias"),
        pytest.param("- item\n", "must contain one top-level mapping", id="sequence"),
        pytest.param(
            "1: value\n",
            "all YAML mapping keys must be unencrypted strings",
            id="integer-key",
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


def test_container_uuids_derive_only_from_base_uuid_and_ou(
    generate: ModuleType,
) -> None:
    people = generate.container_uuid(DIRECTORY_UUID, "people")
    assert people == str(uuid.uuid5(uuid.UUID(DIRECTORY_UUID), "ou:people"))
    assert people == generate.container_uuid(DIRECTORY_UUID, "people")
    assert people != generate.container_uuid(DIRECTORY_UUID, "groups")


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

    entries = generate.parse_ldif((EXAMPLES / "native.ldif").read_bytes())
    entries[-1][1]["userpassword"] = [VALID_HASH.encode(), verifier.encode()]
    values = tmp_path / "data.ldif"
    generate.write_ldif(values, entries)
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/directory_data.py"),
            "--base-dn",
            "o=Example",
            str(values),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == (0 if valid else 65), result.stdout + result.stderr
    assert not verifier or verifier not in result.stdout + result.stderr


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
    "field", ["password", "password_file", "password_hash", "password_hash_file"]
)
@pytest.mark.parametrize("bind", [False, True])
def test_inline_credentials_and_schema_agree(
    generate: ModuleType, tmp_path: Path, seeded_hash: str, field: str, bind: bool
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    item = document["bind_accounts"][0] if bind else document["users"][0]
    del item["password_file"]
    item[field] = (
        seeded_hash
        if field == "password_hash"
        else "/secret"
        if field.endswith("_file")
        else "test-password"
    )
    source = write_secret(
        tmp_path / "directory.yaml", yaml.safe_dump(document).encode()
    )
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(document)
    directory = generate.parse_directory(source)
    credential = (
        directory.bind_accounts["843828e3-1e61-4114-b0a1-b0f4914f55a7"].credential
        if bind
        else directory.users["003ffd6f-3074-457f-9740-2547970687be"].credential
    )
    assert credential.kind == generate.PASSWORD_FIELDS[field]
    assert seeded_hash not in repr(directory)


@pytest.mark.parametrize("field", ["password", "password_hash", "password_hash_file"])
def test_conflicting_password_sources_are_rejected(
    generate: ModuleType, tmp_path: Path, seeded_hash: str, field: str
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["users"][0][field] = seeded_hash if field == "password_hash" else "/secret"
    source = write_secret(
        tmp_path / "directory.yaml", yaml.safe_dump(document).encode()
    )
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    assert not Draft202012Validator(schema).is_valid(document)
    with pytest.raises(generate.ConfigurationError, match="must not combine"):
        generate.parse_directory(source)


def test_inline_unencrypted_credentials_require_private_yaml(
    generate: ModuleType, tmp_path: Path, seeded_hash: str
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    del document["bind_accounts"][0]["password_file"]
    document["bind_accounts"][0]["password_hash"] = seeded_hash
    source = write_secret(
        tmp_path / "directory.yaml", yaml.safe_dump(document).encode(), 0o644
    )
    with pytest.raises(generate.ConfigurationError, match="readable only by its owner"):
        generate.parse_directory(source)
    source.write_text("secret: [" + seeded_hash + "\n", encoding="utf-8")
    with pytest.raises(generate.ConfigurationError) as raised:
        generate.parse_directory(source)
    assert seeded_hash not in str(raised.value)


def test_one_directory_includes_all_active_users(
    generate: ModuleType, example_directory: object
) -> None:
    directory = example_directory
    assert directory.directory_id == "example-app"  # type: ignore[attr-defined]
    assert directory.revision == 1  # type: ignore[attr-defined]
    assert set(directory.users) == {  # type: ignore[attr-defined]
        "003ffd6f-3074-457f-9740-2547970687be",
        "62d4e3af-b3f5-454f-8293-70d7eb92bf85",
        "df0ee4d6-fd01-48b6-9c66-713c52b5ed5a",
    }
    assert directory.users["df0ee4d6-fd01-48b6-9c66-713c52b5ed5a"].active  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("field", "attribute"),
    [
        ("first_name", "givenName"),
        ("last_name", "sn"),
        ("initials", "initials"),
        ("display_name", "displayName"),
        ("description", "description"),
        ("office", "physicalDeliveryOfficeName"),
        ("phone", "telephoneNumber"),
        ("mobile", "mobile"),
        ("email", "mail"),
        ("org", "o"),
        ("employee_number", "employeeNumber"),
        ("department", "ou"),
        ("job_title", "title"),
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        "Example",
        "",
        None,
        42,
        True,
        ["Example"],
        "bad\nvalue",
        "bad\rvalue",
        "bad\x00value",
        "x" * 1124,
    ],
)
def test_profile_fields_and_schema_agree(
    generate: ModuleType, tmp_path: Path, field: str, attribute: str, value: object
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["users"][0][field] = value
    source = write_secret(
        tmp_path / "directory.yaml", yaml.safe_dump(document).encode()
    )
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    valid = value == "Example"
    assert Draft202012Validator(schema).is_valid(document) is valid
    if valid:
        user = generate.parse_directory(source).users[
            "003ffd6f-3074-457f-9740-2547970687be"
        ]
        if field == "last_name":
            assert user.last_name == value
        else:
            assert generate.USER_TEXT_FIELDS[field][0] == attribute
            assert user.attributes[attribute] == (value,)
        assert attribute in generate.DEFAULT_READ_ATTRIBUTES
    else:
        with pytest.raises(generate.ConfigurationError):
            generate.parse_directory(source)


@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("first_name", 256),
        ("last_name", 256),
        ("email", 320),
        ("phone", 64),
        ("mobile", 64),
        ("org", 256),
        ("employee_number", 256),
    ],
)
@pytest.mark.parametrize("excess", [0, 1])
def test_profile_length_boundaries(
    generate: ModuleType, tmp_path: Path, field: str, maximum: int, excess: int
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["users"][0][field] = "x" * (maximum + excess)
    source = write_secret(
        tmp_path / "directory.yaml", yaml.safe_dump(document).encode()
    )
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    assert Draft202012Validator(schema).is_valid(document) is (excess == 0)
    if excess:
        with pytest.raises(generate.ConfigurationError):
            generate.parse_directory(source)
    else:
        generate.parse_directory(source)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("surname", "last_name"),
        ("given_name", "first_name"),
        ("mail", "email"),
        ("telephone_number", "phone"),
        ("company", "org"),
    ],
)
@pytest.mark.parametrize("keep_new", [False, True])
def test_old_profile_keys_are_rejected(
    generate: ModuleType, tmp_path: Path, old: str, new: str, keep_new: bool
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    user = document["users"][0]
    user[old] = user[new] if keep_new else user.pop(new)
    source = write_secret(
        tmp_path / "directory.yaml", yaml.safe_dump(document).encode()
    )
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    assert not Draft202012Validator(schema).is_valid(document)
    with pytest.raises(generate.ConfigurationError):
        generate.parse_directory(source)


def test_only_last_name_is_required_among_profile_fields(
    generate: ModuleType, tmp_path: Path
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    for user in document["users"]:
        for field in (*generate.USER_TEXT_FIELDS, "proxy_addresses"):
            user.pop(field, None)
    source = write_secret(
        tmp_path / "directory.yaml", yaml.safe_dump(document).encode()
    )
    schema = json.loads((ROOT / "schema/directory-v1.schema.json").read_text())
    assert Draft202012Validator(schema).is_valid(document)
    parsed = generate.parse_directory(source)
    assert all(not user.attributes for user in parsed.users.values())
    del document["users"][0]["last_name"]
    source.write_text(yaml.safe_dump(document))
    assert not Draft202012Validator(schema).is_valid(document)
    with pytest.raises(generate.ConfigurationError, match="last_name"):
        generate.parse_directory(source)


@pytest.mark.parametrize(
    "value",
    [
        [],
        ["smtp:old@example.org", "SMTP:primary@example.org"],
        "smtp:a@example.org",
        ["missing-prefix"],
        ["smtp:"],
        [" smtp:a@example.org"],
        ["smtp:a@example.org\n"],
        ["smtp:a@example.org"] * 2,
        ["smtp:a@example.org", "SMTP:A@example.org"],
        [f"smtp:a{i}@example.org" for i in range(65)],
    ],
)
def test_proxy_addresses_are_bounded_typed_values(
    generate: ModuleType, tmp_path: Path, value: object
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["users"][0]["proxy_addresses"] = value
    source = write_secret(
        tmp_path / "directory.yaml", yaml.safe_dump(document).encode()
    )
    valid = value in ([], ["smtp:old@example.org", "SMTP:primary@example.org"])
    if valid:
        user = generate.parse_directory(source).users[
            "003ffd6f-3074-457f-9740-2547970687be"
        ]
        assert isinstance(value, list)
        assert user.attributes.get("proxyAddresses", ()) == tuple(value)
    else:
        with pytest.raises(generate.ConfigurationError):
            generate.parse_directory(source)


@pytest.mark.parametrize(
    "damage",
    [
        "empty",
        "mapping",
        "missing-secret",
        "duplicate-id",
        "duplicate-name",
        "case-name",
        "old-key",
    ],
)
def test_bind_accounts_reject_invalid_lists(
    generate: ModuleType, tmp_path: Path, damage: str
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    account = document["bind_accounts"][0]
    if damage == "empty":
        document["bind_accounts"] = []
    elif damage == "mapping":
        document["bind_accounts"] = account
    elif damage == "missing-secret":
        del account["password_file"]
    elif damage == "old-key":
        document["bind_account"] = document.pop("bind_accounts")[0]
    else:
        second = {
            **account,
            "entry_uuid": "5b5e5bcc-58cc-4c41-b125-927b926fb8f4",
            "username": "second",
        }
        if damage == "duplicate-id":
            second["entry_uuid"] = account["entry_uuid"]
        else:
            second["username"] = (
                account["username"].upper()
                if damage == "case-name"
                else account["username"]
            )
        document["bind_accounts"].append(second)
    source = write_secret(
        tmp_path / "directory.yaml", yaml.safe_dump(document).encode()
    )
    with pytest.raises(generate.ConfigurationError):
        generate.parse_directory(source)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        (
            "expiry_offset_seconds: 0",
            "expiry_offset_seconds: 21600",
            "expiry_offset_seconds must be less than",
        ),
        (
            "expiry_offset_seconds: 0",
            "expiry_offset_seconds: -1",
            "expiry_offset_seconds must be an integer",
        ),
        (
            "hard_ttl_seconds: 43200",
            "hard_ttl_seconds: 21600",
            "soft_ttl_seconds must be less than",
        ),
        ('      - "disabled"', '      - "missing"', "references an unknown user"),
        ('username: "bob"', 'username: "ALICE"', "duplicate user"),
        ("format_version: 1", "format_version: 99", "format_version must be 1"),
        (
            'password_file: "/run/credentials/person-0001-example-app"',
            'password_file: "relative"',
            "absolute path",
        ),
    ],
)
def test_directory_policy_violations_are_rejected(
    generate: ModuleType, tmp_path: Path, old: str, new: str, message: str
) -> None:
    content = (EXAMPLES / "directory.yaml").read_text()
    assert old in content
    source = write_secret(
        tmp_path / "directory.yaml", content.replace(old, new, 1).encode()
    )
    with pytest.raises(generate.ConfigurationError, match=message):
        generate.parse_directory(source)
