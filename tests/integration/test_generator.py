"""Generate snapshots from both input routes, then exercise their LDAP behavior."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import pytest
import yaml
from argon2 import PasswordHasher
from ldap.schema import SubSchema
from ldap.schema.models import AttributeType, ObjectClass
from ldif import LDIFRecordList

from scripts.directory_data import DEFAULT_READ_ATTRIBUTES
from scripts.server_config import MODULES
from tests.entry_uuid_cases import ENTRY_UUID_CASES
from tests.integration.conftest import PROJECT, Images
from tests.integration.harness import Podman, Store
from tests.integration.image_checks import (
    assert_image_package_data,
    assert_image_privileges,
)
from tests.integration.lifecycle import LDAP_URI, LDAPI_URI, wait_until_healthy
from tests.validate_snapshot_manifest import validate_manifest

pytestmark = pytest.mark.integration
EXAMPLES = PROJECT / "examples/generator"
SCHEMA = PROJECT / "schema/snapshot-manifest-v1.schema.json"
APP_BASE = "dc=example-app,dc=services,dc=example,dc=org"
ALICE_DN = f"uid=alice,ou=people,{APP_BASE}"
APPLICATION_DN = f"uid=application,ou=services,{APP_BASE}"
PASSWORDS = {
    "person-0001-example-app": "TEST-ONLY-app-user",
    "person-0003": "TEST-ONLY-bob",
    "bind-example-app": "TEST-ONLY-app-bind",
    "vault-password": "TEST-ONLY-high-entropy-vault-key-2e8014d7",
}


def records(path: Path) -> dict[str, dict[str, list[bytes]]]:
    with path.open("rb") as stream:
        parser = LDIFRecordList(stream)
        parser.parse()
    return dict(parser.all_records)


def entry_uuid(ldif: str, dn_prefix: str) -> str:
    found = False
    for line in ldif.splitlines():
        if line.startswith(f"dn: {dn_prefix}"):
            found = True
        if found and line.startswith("entryUUID: "):
            return line.removeprefix("entryUUID: ")
    pytest.fail(f"no entryUUID for {dn_prefix}")


@dataclass
class Generator:
    podman: Podman
    image: str
    path: Path

    @property
    def credentials(self) -> Path:
        return self.path / "credentials"

    @property
    def output(self) -> Path:
        return self.path / "output"

    @property
    def inputs(self) -> Path:
        return self.path / "input"

    def container(
        self, *arguments: str, entrypoint: str | None = None, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return self.podman.run_container(
            "--rm",
            *(["-i"] if stdin is not None else []),
            "--userns=keep-id:uid=1001,gid=1001",
            "--network=none",
            "--read-only",
            "--read-only-tmpfs=false",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--memory=256m",
            "--pids-limit=64",
            "--env",
            "ANSIBLE_LOCAL_TEMP=/output/.ansible",
            "--volume",
            f"{self.inputs}:/input:ro,Z",
            "--volume",
            f"{self.credentials}:/run/credentials:ro,Z",
            "--volume",
            f"{self.output}:/output:rw,Z",
            *(["--entrypoint", entrypoint] if entrypoint else []),
            self.image,
            *arguments,
            check=False,
            stdin=stdin,
        )

    def run(
        self, name: str, *arguments: str, source: str = "directory.yaml"
    ) -> subprocess.CompletedProcess[str]:
        return self.container(
            "--directory",
            f"/input/{source}",
            "--signing-key",
            "/run/credentials/snapshot.key",
            "--output",
            f"/output/{name}",
            *arguments,
        )

    def variant(
        self, name: str, document: dict[str, object] | str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        path = self.inputs / f"{name}.yaml"
        path.write_text(
            document if isinstance(document, str) else yaml.safe_dump(document),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return self.run(name, *arguments, source=path.name)

    def encrypt(self, value: str, label: str = "directory") -> str:
        result = self.container(
            "encrypt",
            "--output",
            "-",
            "--vault-id",
            f"{label}@/run/credentials/vault-password",
            entrypoint="/usr/bin/ansible-vault",
            stdin=value,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout


@pytest.fixture(scope="module")
def generator(podman: Podman, store: Store, images: Images) -> Generator:
    path = store.workspace / "generator"
    path.mkdir()
    prepared = Generator(podman, images.require_generator(), path)
    shutil.copytree(EXAMPLES, prepared.inputs)
    prepared.credentials.mkdir()
    prepared.output.mkdir()
    for name, value in PASSWORDS.items():
        secret = prepared.credentials / name
        secret.write_text(value + "\n", encoding="utf-8")
        secret.chmod(0o600)
    result = podman.run_container(
        "--rm",
        "--userns=keep-id:uid=1001,gid=1001",
        "--network=none",
        "--entrypoint=minisign",
        "--volume",
        f"{prepared.credentials}:/keys:Z",
        prepared.image,
        "-G",
        "-W",
        "-p",
        "/keys/snapshot.pub",
        "-s",
        "/keys/snapshot.key",
    )
    assert result.returncode == 0, result.stderr
    (prepared.credentials / "snapshot.key").chmod(0o600)
    return prepared


@pytest.fixture(scope="module")
def generated(generator: Generator) -> Path:
    result = generator.run("generated")
    assert result.returncode == 0, result.stderr
    return generator.output / "generated"


def test_generator_image_boundary(generator: Generator) -> None:
    assert_image_package_data(generator.podman, generator.image)
    result = generator.container(
        "-c",
        "id -u; id -g; command -v ansible-vault; command -v openldap-password; command -v openssl; test ! -e /usr/sbin/slapd; test ! -e /tmp/export_schema.py; test ! -e /usr/local/lib/openldap-declarative/generator/export_schema.py; test ! -e /TEMP-Notes; test -s /usr/share/doc/ansible-core/copyright; test -s /usr/local/share/openldap-declarative/LICENSE.txt",
        entrypoint="sh",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("1001\n1001\n/usr/bin/ansible-vault\n")
    assert "/usr/local/bin/openldap-password\n/usr/bin/openssl\n" in result.stdout


def test_generator_image_privileges(podman: Podman, images: Images) -> None:
    assert_image_privileges(podman, images.require_generator(), {"/output"})


@pytest.fixture(scope="module")
def admin_generated(generator: Generator) -> Path:
    hashed = generator.container(
        entrypoint="openldap-password", stdin="TEST-ONLY-admin-workflow\n"
    )
    assert hashed.returncode == 0 and not hashed.stderr
    verifier = hashed.stdout.strip()
    assert verifier.startswith("{ARGON2}$argon2id$v=19$m=19456,t=2,p=1$")
    assert PasswordHasher().verify(
        verifier.removeprefix("{ARGON2}"), "TEST-ONLY-admin-workflow"
    )
    key = generator.container("rand", "-base64", "32", entrypoint="openssl")
    assert key.returncode == 0 and not key.stderr
    assert len(base64.b64decode(key.stdout.strip(), validate=True)) == 32
    key_file = generator.credentials / "admin-vault-password"
    key_file.write_text(key.stdout, encoding="utf-8")
    key_file.chmod(0o600)
    encrypted = generator.container(
        "encrypt_string",
        "--vault-id",
        "directory@/run/credentials/admin-vault-password",
        "--stdin-name",
        "password_hash",
        entrypoint="ansible-vault",
        stdin=verifier,
    )
    assert encrypted.returncode == 0, encrypted.stderr
    assert "$ANSIBLE_VAULT;1.2;AES256;directory" in encrypted.stdout
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    del document["users"][0]["password_file"]
    document["users"][0]["password_hash"] = "HASH_PLACEHOLDER"
    source = yaml.safe_dump(document).replace(
        "password_hash: HASH_PLACEHOLDER",
        "\n".join(
            ("  " if index else "") + line
            for index, line in enumerate(encrypted.stdout.rstrip().splitlines())
        ),
    )
    result = generator.variant(
        "admin-workflow",
        source,
        "--vault",
        "directory@/run/credentials/admin-vault-password",
    )
    assert result.returncode == 0, result.stderr
    return generator.output / "admin-workflow"


def test_generator_only_admin_tools_create_a_snapshot(admin_generated: Path) -> None:
    assert (admin_generated / "manifest.json.minisig").is_file()
    assert (
        b"TEST-ONLY-admin-workflow"
        not in (admin_generated / "directory.ldif").read_bytes()
    )
    validate_manifest(SCHEMA, admin_generated / "manifest.json")


def test_admin_generated_hash_authenticates(
    generator: Generator,
    admin_generated: Path,
    podman: Podman,
    images: Images,
    store: Store,
) -> None:
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-admin-tools"
    )
    running.start(admin_generated)
    assert running.bind(ALICE_DN, "TEST-ONLY-admin-workflow").returncode == 0
    assert running.bind(ALICE_DN, "TEST-ONLY-app-user").returncode == 49
    assert running.bind(APPLICATION_DN, "TEST-ONLY-app-bind").returncode == 0
    podman.stop(running.name)


@pytest.mark.parametrize("value", ["", "TEST-ONLY\nsecond", "x" * 4097])
def test_password_helper_rejects_bad_input_in_container(
    generator: Generator, value: str
) -> None:
    result = generator.container(entrypoint="openldap-password", stdin=value)
    assert result.returncode == 2 and not result.stdout
    assert "TEST-ONLY" not in result.stderr


def test_one_directory_exports_all_active_users(generated: Path) -> None:
    assert {path.name for path in generated.iterdir()} == {
        "directory.ldif",
        "manifest.json",
        "manifest.json.minisig",
    }
    entries = records(generated / "directory.ldif")
    assert ALICE_DN in entries
    assert f"uid=bob,ou=people,{APP_BASE}" in entries
    assert f"uid=disabled,ou=people,{APP_BASE}" not in entries
    assert "memberOf" not in entries[f"uid=bob,ou=people,{APP_BASE}"]
    validate_manifest(SCHEMA, generated / "manifest.json")
    assert generated.stat().st_mode & 0o777 == 0o700
    for path in generated.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
        assert not any(secret in path.read_text() for secret in PASSWORDS.values())


def test_profile_fields_are_readable_and_policy_can_hide_them(
    generator: Generator, generated: Path, podman: Podman, images: Images, store: Store
) -> None:
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-profile"
    )
    running.start(generated)
    result = running.search("-b", ALICE_DN, "-s", "base", "*", "+")
    assert result.returncode == 0, result.stderr
    parser = LDIFRecordList(BytesIO(result.stdout.encode()))
    parser.parse()
    entry = parser.all_records[0][1]
    expected = {
        "sn": [b"Example"],
        "givenName": [b"Alice"],
        "initials": [b"AE"],
        "displayName": [b"Alice Example"],
        "description": [b"Application directory user"],
        "physicalDeliveryOfficeName": [b"Main office"],
        "telephoneNumber": [b"+49 721 5550100"],
        "mobile": [b"+49 170 5550100"],
        "o": [b"Example Company"],
        "employeeNumber": [b"E-0001"],
        "mail": [b"alice@example.org"],
        "ou": [b"Operations"],
        "title": [b"Engineer"],
        "proxyAddresses": [
            b"smtp:alice.old@example.org",
            b"smtp:a.example@example.org",
        ],
    }
    for name, values in expected.items():
        assert set(entry[name]) == set(values), name
    assert "userPassword" not in entry
    assert b"openldapDeclarativeUser" in entry["objectClass"]
    assert running.bind(ALICE_DN, "TEST-ONLY-app-user").returncode == 0
    lookup = running.search(
        "-b", APP_BASE, "(proxyAddresses=SMTP:ALICE.OLD@example.org)", "uid"
    )
    assert lookup.returncode == 0 and "uid: alice" in lookup.stdout
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["revision"] = 2
    document["read_attributes"] = ["objectClass", "entryUUID", "uid", "cn", "mail"]
    generated_result = generator.variant("profile-restricted", document)
    assert generated_result.returncode == 0, generated_result.stderr
    running.start(generator.output / "profile-restricted")
    result = running.search("-b", ALICE_DN, "-s", "base", "*", "+")
    assert "mail: alice@example.org" in result.stdout
    for name in expected.keys() - {"mail"}:
        assert f"{name}:" not in result.stdout
    assert "userPassword:" not in result.stdout
    podman.stop(running.name)


def test_profile_updates_and_vault_preserve_directory_identity(
    generator: Generator, generated: Path, podman: Podman, images: Images, store: Store
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["revision"] = 2
    document["users"][0].update(
        first_name="Alicia",
        last_name="Renamed",
        email="alicia@example.org",
        phone="+49 721 5550200",
        mobile="+49 170 5550200",
        org="VAULT_COMPANY",
        employee_number="VAULT_EMPLOYEE",
    )
    source = yaml.safe_dump(document)
    for marker, value in (
        ("VAULT_COMPANY", "Another Company"),
        ("VAULT_EMPLOYEE", "00042"),
    ):
        encrypted = generator.encrypt(value)
        source = source.replace(
            marker,
            "!vault |\n" + "\n".join("    " + line for line in encrypted.splitlines()),
        )
    result = generator.variant(
        "profile-updated",
        source,
        "--vault",
        "directory@/run/credentials/vault-password",
    )
    assert result.returncode == 0, result.stderr
    assert "Another Company" not in result.stdout + result.stderr
    snapshot = generator.output / "profile-updated"
    original = records(generated / "directory.ldif")
    updated = records(snapshot / "directory.ldif")
    assert updated.keys() == original.keys()
    assert updated[APP_BASE] == original[APP_BASE]
    for dn, attributes in original.items():
        for name in ("entryUUID", "uid", "cn", "member", "memberOf"):
            assert updated[dn].get(name) == attributes.get(name)
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-profile-updated"
    )
    running.start(snapshot)
    result = running.search("-b", ALICE_DN, "-s", "base", "*", "+")
    assert result.returncode == 0, result.stderr
    for expected in (
        "givenName: Alicia",
        "sn: Renamed",
        "mail: alicia@example.org",
        "telephoneNumber: +49 721 5550200",
        "mobile: +49 170 5550200",
        "o: Another Company",
        "employeeNumber: 00042",
    ):
        assert expected in result.stdout
    assert "userPassword:" not in result.stdout
    assert running.bind(ALICE_DN, "TEST-ONLY-app-user").returncode == 0
    podman.stop(running.name)


def test_mixed_memberships_and_display_names_survive_account_renames(
    generator: Generator, podman: Podman, images: Images, store: Store
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    alice, _, bob = document["users"]
    group = document["groups"][0]
    bind = document["bind_accounts"][0]
    group["members"] = ["ALICE", bob["entry_uuid"]]
    bind["display_name"] = "Application reader"
    result = generator.variant("mixed-members", document)
    assert result.returncode == 0, result.stderr
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-mixed-members"
    )
    running.start(generator.output / "mixed-members")
    assert running.alice_uuid() == alice["entry_uuid"]
    assert running.bind(APPLICATION_DN, "TEST-ONLY-app-bind").returncode == 0
    result = running.search(
        "-b", APPLICATION_DN, "-s", "base", "uid", "cn", "displayName", "entryUUID"
    )
    assert result.returncode == 0, result.stderr
    for value in (
        "uid: application",
        "cn: Application reader",
        "displayName: Application reader",
        f"entryUUID: {bind['entry_uuid']}",
    ):
        assert value in result.stdout
    document["revision"] = 2
    alice.update(username="alicia", display_name="Alicia Example")
    group["groupname"] = "employees"
    result = generator.variant("mixed-dangling", document)
    assert result.returncode == 2 and "unknown user" in result.stderr
    assert not (generator.output / "mixed-dangling").exists()
    group["members"][0] = "alicia"
    result = generator.variant("mixed-renamed", document)
    assert result.returncode == 0, result.stderr
    running.start(generator.output / "mixed-renamed")
    renamed_dn = f"uid=alicia,ou=people,{APP_BASE}"
    result = running.search(
        "-b",
        renamed_dn,
        "-s",
        "base",
        "uid",
        "cn",
        "displayName",
        "entryUUID",
        "memberOf",
    )
    assert result.returncode == 0, result.stderr
    for value in (
        "cn: Alicia Example",
        "displayName: Alicia Example",
        f"entryUUID: {alice['entry_uuid']}",
        f"memberOf: cn=employees,ou=groups,{APP_BASE}",
    ):
        assert value in result.stdout
    assert running.bind(renamed_dn, "TEST-ONLY-app-user").returncode == 0
    result = running.search(
        "-b", f"cn=employees,ou=groups,{APP_BASE}", "-s", "base", "*", "+"
    )
    assert result.returncode == 0, result.stderr
    assert f"member: {renamed_dn}" in result.stdout
    assert f"member: uid=bob,ou=people,{APP_BASE}" in result.stdout
    assert f"entryUUID: {group['entry_uuid']}" in result.stdout
    snapshot = records(generator.output / "mixed-renamed/directory.ldif")
    assert snapshot[APP_BASE]["entryUUID"] == [document["entry_uuid"].encode()]
    assert "name" not in snapshot[f"cn=employees,ou=groups,{APP_BASE}"]
    podman.stop(running.name)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate-uuid",
        "generated-uuid",
        "duplicate-member",
        "ambiguous-member",
        "bind-username",
        "missing-uuid",
        "old-key",
    ],
)
def test_managed_identity_errors_stop_before_signing(
    generator: Generator, mutation: str
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    alice = document["users"][0]
    if mutation == "duplicate-uuid":
        document["bind_accounts"][0]["entry_uuid"] = document["users"][1]["entry_uuid"]
    elif mutation == "generated-uuid":
        alice["entry_uuid"] = str(
            uuid.uuid5(uuid.UUID(document["entry_uuid"]), "ou:people")
        )
        document["groups"][0]["members"] = ["alice"]
    elif mutation == "duplicate-member":
        document["groups"][0]["members"] = ["alice", alice["entry_uuid"]]
    elif mutation == "ambiguous-member":
        document["users"][2]["username"] = alice["entry_uuid"]
    elif mutation == "bind-username":
        document["bind_accounts"][0]["username"] = "ALICE"
    elif mutation == "missing-uuid":
        del alice["entry_uuid"]
    else:
        alice["common_name"] = "PRIVATE-MARKER"
    name = f"identity-reject-{mutation}"
    result = generator.variant(name, document)
    assert result.returncode == 2, result.stderr
    assert "PRIVATE-MARKER" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert not (generator.output / name).exists()


def test_yaml_extensions_preserve_identity_and_obey_read_policy(
    generator: Generator, generated: Path, podman: Podman, images: Images, store: Store
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["users"][0]["object_classes"] = ["posixAccount"]
    document["users"][0]["attributes"] = {
        "employeeType": ["Employee"],
        "preferredLanguage": ["en"],
        "uidNumber": ["10001"],
        "gidNumber": ["10000"],
        "homeDirectory": ["/home/alice"],
        "pager": ["+49 123", "+49 456"],
    }
    document["groups"][0]["attributes"] = {"description": ["Staff group"]}
    document["bind_accounts"][0]["attributes"] = {"description": ["Application reader"]}
    result = generator.variant("extensions-default", document)
    assert result.returncode == 0, result.stderr
    snapshot = generator.output / "extensions-default"
    original = records(generated / "directory.ldif")
    extended = records(snapshot / "directory.ldif")
    assert original.keys() == extended.keys()
    for dn, attributes in original.items():
        for name in ("entryUUID", "uid", "cn", "member", "memberOf"):
            assert extended[dn].get(name) == attributes.get(name)
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-extensions"
    )
    running.start(snapshot)
    before_uuid = running.alice_uuid()
    search = running.search("-b", APP_BASE, "(objectClass=*)", "*", "+")
    assert search.returncode == 0, search.stderr
    assert "description: Staff group" in search.stdout
    assert "description: Application reader" in search.stdout
    assert "employeeType:" not in search.stdout and "uidNumber:" not in search.stdout
    assert "pager:" not in search.stdout
    assert "userPassword:" not in search.stdout
    document["revision"] = 2
    document["read_attributes"] = [
        *DEFAULT_READ_ATTRIBUTES,
        "employeeType",
        "uidNumber",
        "gidNumber",
        "homeDirectory",
        "pager",
    ]
    result = generator.variant("extensions-readable", document)
    assert result.returncode == 0, result.stderr
    running.start(generator.output / "extensions-readable")
    assert running.alice_uuid() == before_uuid
    assert running.bind(ALICE_DN, "TEST-ONLY-app-user").returncode == 0
    assert running.bind(ALICE_DN, "TEST-ONLY-wrong-password").returncode == 49
    search = running.search("-b", ALICE_DN, "-s", "base", "*", "+")
    for expected in (
        "objectClass: posixAccount",
        "employeeType: Employee",
        "uidNumber: 10001",
        "gidNumber: 10000",
        "homeDirectory: /home/alice",
        "pager: +49 123",
        "pager: +49 456",
        f"memberOf: cn=staff,ou=groups,{APP_BASE}",
    ):
        assert expected in search.stdout
    assert (
        "preferredLanguage:" not in search.stdout
        and "userPassword:" not in search.stdout
    )
    write = podman.exec(
        running.name,
        "ldapmodify",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        APPLICATION_DN,
        "-w",
        "TEST-ONLY-app-bind",
        check=False,
        stdin=f"dn: {ALICE_DN}\nchangetype: modify\nreplace: employeeType\nemployeeType: changed\n\n",
    )
    assert write.returncode == 50, write.stderr
    podman.stop(running.name)


def test_yaml_custom_classes_and_vault_values_on_all_entities(
    generator: Generator, podman: Podman, images: Images, store: Store
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["schema_files"] = ["employee-schema.ldif"]
    document["read_attributes"] = [*DEFAULT_READ_ATTRIBUTES, "costCenter"]
    for kind in ("users", "groups", "bind_accounts"):
        document[kind][0]["object_classes"] = ["exampleEmployee"]
        document[kind][0]["attributes"] = {"costCenter": [f"center-{kind}"]}
    document["users"][0]["attributes"]["costCenter"] = ["VAULT_PLACEHOLDER"]
    encrypted = generator.encrypt("center-users")
    source = yaml.safe_dump(document).replace(
        "    - VAULT_PLACEHOLDER",
        "    - !vault |\n"
        + "\n".join("        " + line for line in encrypted.splitlines()),
    )
    assert "VAULT_PLACEHOLDER" not in source
    result = generator.variant(
        "custom-extensions",
        source,
        "--vault",
        "directory@/run/credentials/vault-password",
    )
    assert result.returncode == 0, result.stderr
    snapshot = generator.output / "custom-extensions"
    assert "center-users" in (snapshot / "directory.ldif").read_text()
    assert "center-users" not in result.stdout + result.stderr
    validate_manifest(SCHEMA, snapshot / "manifest.json")
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-custom-extensions"
    )
    running.start(snapshot)
    result = running.search(
        "-b", APP_BASE, "(objectClass=exampleEmployee)", "costCenter"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("dn: ") == 3
    for kind in ("users", "groups", "bind_accounts"):
        assert f"costCenter: center-{kind}" in result.stdout
    assert running.bind(ALICE_DN, "TEST-ONLY-app-user").returncode == 0
    assert running.bind(APPLICATION_DN, "TEST-ONLY-app-bind").returncode == 0
    podman.stop(running.name)


@pytest.mark.parametrize(
    "extension",
    [
        {"attributes": {"commonName": ["PRIVATE-MARKER"]}},
        {"attributes": {"2.5.4.35": ["PRIVATE-MARKER"]}},
        {"attributes": {"memberOf": ["PRIVATE-MARKER"]}},
        {"attributes": {"mail": ["PRIVATE-MARKER"]}},
        {"attributes": {"employeeNumber": ["PRIVATE-MARKER"]}},
        {"attributes": {"mobileTelephoneNumber": ["PRIVATE-MARKER"]}},
        {"attributes": {"organizationName": ["PRIVATE-MARKER"]}},
        {"attributes": {"creatorsName": ["PRIVATE-MARKER"]}},
        {"attributes": {"unknownAttribute": ["PRIVATE-MARKER"]}},
        {"attributes": {"employeeNumber": ["a"], "employeeNumber;lang-en": ["b"]}},
        {"object_classes": ["organization"]},
        {"object_classes": ["extensibleObject"]},
        {"object_classes": ["unknownClass"]},
        {"object_classes": ["openldapDeclarativeUser"]},
    ],
)
def test_yaml_extension_rejections_before_signing(
    generator: Generator, extension: dict[str, object], request: pytest.FixtureRequest
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["users"][0].update(extension)
    name = f"extension-reject-{request.node.callspec.id}"
    result = generator.variant(name, document)
    assert result.returncode == 2, result.stderr
    assert "PRIVATE-MARKER" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert not (generator.output / name).exists()


@pytest.mark.parametrize(
    "mutation", ["none", "missing-required", "invalid-integer", "missing-class"]
)
@pytest.mark.parametrize("input_type", ["users-groups", "ldif"])
def test_yaml_extensions_offline_preflight(
    generator: Generator, podman: Podman, images: Images, mutation: str, input_type: str
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["users"][0]["object_classes"] = ["posixAccount"]
    attributes = {
        "uidNumber": ["10001"],
        "gidNumber": ["10000"],
        "homeDirectory": ["/home/alice"],
    }
    document["users"][0]["attributes"] = attributes
    if mutation == "missing-required":
        del attributes["homeDirectory"]
    elif mutation == "invalid-integer":
        attributes["uidNumber"] = ["PRIVATE-MARKER"]
    elif mutation == "missing-class":
        del document["users"][0]["object_classes"]
    name = f"extension-preflight-{input_type}-{mutation}"
    result = generator.variant(name, document)
    assert result.returncode == 0, result.stderr
    if input_type == "ldif":
        shutil.copyfile(
            generator.output / name / "directory.ldif",
            generator.inputs / f"{name}.ldif",
        )
        for key in (
            "users",
            "groups",
            "bind_accounts",
            "entry_uuid",
            "organization",
        ):
            del document[key]
        document.update(
            input_type="ldif",
            ldif_files=[f"{name}.ldif"],
            config_files=yaml.safe_load((EXAMPLES / "native.yaml").read_text())[
                "config_files"
            ],
        )
        document.pop("read_attributes", None)
        config_path = generator.inputs / f"{name}-database.ldif"
        config_path.write_text(
            (EXAMPLES / "native-database.ldif")
            .read_text()
            .replace("o=Example", APP_BASE)
        )
        document["config_files"][-1] = config_path.name
        document["config_files"].insert(
            -1, "/usr/local/share/openldap-declarative/schema/application-user.ldif"
        )
        name += "-native"
        result = generator.variant(name, document)
        assert result.returncode == 0, result.stderr
    state = generator.path / f"{name}-state"
    state.mkdir(mode=0o700)
    result = podman.run_container(
        "--rm",
        "--network=none",
        "--read-only",
        "--read-only-tmpfs=false",
        "--userns=keep-id:uid=1001,gid=1001",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--memory=256m",
        "--pids-limit=128",
        "--tmpfs",
        "/run/openldap:rw,noexec,nosuid,nodev,mode=1777",
        "--volume",
        f"{generator.output / name}:/snapshot:ro,Z",
        "--volume",
        f"{generator.credentials}:/keys:ro,Z",
        "--volume",
        f"{state}:/state:ro,Z",
        "--env=LDAP_EXPECTED_DIRECTORY_ID=example-app",
        "--env=LDAP_SNAPSHOT_PUBLIC_KEY_FILE=/keys/snapshot.pub",
        "--entrypoint",
        "openldap-preflight",
        images.require_runtime(),
        check=False,
    )
    assert result.returncode == (0 if mutation == "none" else 65), (
        result.stdout + result.stderr
    )
    assert "PRIVATE-MARKER" not in result.stdout + result.stderr
    assert not list(state.iterdir())


def test_generator_schema_definitions_match_runtime_package(
    generator: Generator, podman: Podman, images: Images
) -> None:
    version = generator.container(
        "/usr/local/share/openldap-declarative/schema/openldap-version",
        entrypoint="cat",
    )
    runtime_version = podman.run_container(
        "--rm",
        "--network=none",
        "--entrypoint=dpkg-query",
        images.require_runtime(),
        "-W",
        "-f=${Version}",
        "slapd",
    )
    assert version.returncode == 0
    assert version.stdout.strip() == runtime_version.stdout.strip()
    checksums = generator.container(
        "/usr/local/share/openldap-declarative/schema/source-checksums.json",
        entrypoint="cat",
    )
    assert checksums.returncode == 0
    source_checksums = json.loads(checksums.stdout)
    assert set(source_checksums) == {
        f"{name}.ldif" for name in ("core", "cosine", "inetorgperson", "nis")
    }
    for schema, checksum in source_checksums.items():
        runtime_hash = podman.run_container(
            "--rm",
            "--network=none",
            "--entrypoint=sha256sum",
            images.require_runtime(),
            f"/etc/ldap/schema/{schema}",
        )
        assert checksum == runtime_hash.stdout.split()[0]
    result = generator.container(
        "-c",
        "test ! -e /tmp/openldap-schema && test -s /usr/share/doc/slapd-schema/copyright",
        entrypoint="sh",
    )
    assert result.returncode == 0


def test_generator_catalog_matches_the_effective_runtime_schema(
    generator: Generator, generated: Path, podman: Podman, images: Images, store: Store
) -> None:
    catalog = generator.container(
        "-c",
        "import json; from generator.extensions import SchemaCatalog; "
        "print(json.dumps(SchemaCatalog(()).schema.ldap_entry()))",
        entrypoint="python3",
    )
    assert catalog.returncode == 0, catalog.stderr
    expected = SubSchema(json.loads(catalog.stdout), check_uniqueness=2)
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-schema-parity"
    )
    running.start(generated)
    result = podman.exec(
        running.name,
        "ldapsearch",
        "-LLL",
        "-Y",
        "EXTERNAL",
        "-H",
        LDAPI_URI,
        "-b",
        "cn=Subschema",
        "-s",
        "base",
        "(objectClass=subschema)",
        "attributeTypes",
        "objectClasses",
    )
    parser = LDIFRecordList(BytesIO(result.stdout.encode()))
    parser.parse()
    assert len(parser.all_records) == 1
    actual = SubSchema(parser.all_records[0][1], check_uniqueness=2)
    for kind in (AttributeType, ObjectClass):
        for oid in expected.listall(kind):
            assert str(expected.get_obj(kind, oid)) == str(actual.get_obj(kind, oid))
    podman.stop(running.name)


def test_bind_accounts_rotate_rename_and_revoke_independently(
    generator: Generator, podman: Podman, images: Images, store: Store
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    secondary = {
        "entry_uuid": "5b5e5bcc-58cc-4c41-b125-927b926fb8f4",
        "username": "secondary",
        "display_name": "Secondary reader",
        "password": "SECONDARY_PLACEHOLDER",
    }
    document["bind_accounts"].append(secondary)
    encrypted = generator.encrypt("TEST-ONLY-secondary")
    source = yaml.safe_dump(document).replace(
        "password: SECONDARY_PLACEHOLDER",
        "password: !vault |\n"
        + "\n".join("    " + line for line in encrypted.splitlines()),
    )
    result = generator.variant(
        "multi-bind-1", source, "--vault", "directory@/run/credentials/vault-password"
    )
    assert result.returncode == 0, result.stderr
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-multi-bind"
    )
    running.start(generator.output / "multi-bind-1")
    secondary_dn = f"uid=secondary,ou=services,{APP_BASE}"
    original_uuid = records(generator.output / "multi-bind-1/directory.ldif")[
        secondary_dn
    ]["entryUUID"]
    assert running.bind(secondary_dn, "TEST-ONLY-secondary").returncode == 0
    assert running.bind(APPLICATION_DN, "TEST-ONLY-app-bind").returncode == 0
    identity = running.search(
        "-b", secondary_dn, "-s", "base", "uid", "cn", "displayName", "entryUUID"
    )
    assert identity.returncode == 0, identity.stderr
    assert "uid: secondary" in identity.stdout
    assert "cn: Secondary reader" in identity.stdout
    assert "displayName: Secondary reader" in identity.stdout
    assert f"entryUUID: {secondary['entry_uuid']}" in identity.stdout
    search = podman.exec(
        running.name,
        "ldapsearch",
        "-LLL",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        secondary_dn,
        "-w",
        "TEST-ONLY-secondary",
        "-b",
        ALICE_DN,
        "-s",
        "base",
        "uid",
        "userPassword",
        check=False,
    )
    assert (
        search.returncode == 0
        and "uid: alice" in search.stdout
        and "userPassword:" not in search.stdout
    )
    write = podman.exec(
        running.name,
        "ldapmodify",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        secondary_dn,
        "-w",
        "TEST-ONLY-secondary",
        check=False,
        stdin=f"dn: {ALICE_DN}\nchangetype: modify\nreplace: description\ndescription: forbidden\n",
    )
    assert write.returncode == 50
    document["revision"] = 2
    secondary.update(
        username="renamed", display_name="Renamed reader", password="TEST-ONLY-rotated"
    )
    result = generator.variant("multi-bind-2", document)
    assert result.returncode == 0, result.stderr
    renamed_dn = f"uid=renamed,ou=services,{APP_BASE}"
    assert (
        records(generator.output / "multi-bind-2/directory.ldif")[renamed_dn][
            "entryUUID"
        ]
        == original_uuid
    )
    running.start(generator.output / "multi-bind-2")
    assert running.bind(secondary_dn, "TEST-ONLY-secondary").returncode == 49
    assert running.bind(renamed_dn, "TEST-ONLY-secondary").returncode == 49
    assert running.bind(renamed_dn, "TEST-ONLY-rotated").returncode == 0
    assert running.bind(APPLICATION_DN, "TEST-ONLY-app-bind").returncode == 0
    document["revision"] = 3
    document["bind_accounts"].pop()
    result = generator.variant("multi-bind-3", document)
    assert result.returncode == 0, result.stderr
    running.start(generator.output / "multi-bind-3")
    assert running.bind(renamed_dn, "TEST-ONLY-rotated").returncode == 49
    assert running.bind(APPLICATION_DN, "TEST-ONLY-app-bind").returncode == 0
    podman.stop(running.name)


def test_expiry_policy_and_controlled_generation(generator: Generator) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["expiry_offset_seconds"] = 600
    result = generator.variant(
        "controlled", document, "--generated-at", "2030-01-01T00:00:00Z"
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads((generator.output / "controlled/manifest.json").read_text())
    assert (
        manifest["generated_at"],
        manifest["soft_expires_at"],
        manifest["expires_at"],
    ) == ("2030-01-01T00:00:00Z", "2030-01-01T05:50:00Z", "2030-01-01T11:50:00Z")


@pytest.mark.parametrize("offset", [-1, 86401, 21600])
def test_expiry_offset_rejections(generator: Generator, offset: int) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["expiry_offset_seconds"] = offset
    name = f"offset-{offset}"
    result = generator.variant(name, document)
    assert result.returncode == 2 and "expiry_offset_seconds" in result.stderr
    assert not (generator.output / name).exists()


def test_removed_service_selector_and_existing_output_rejected(
    generator: Generator, generated: Path
) -> None:
    result = generator.run("rejected", "--service", "example-app")
    assert result.returncode == 2 and "unrecognized arguments" in result.stderr
    assert not (generator.output / "rejected").exists()
    result = generator.run(generated.name)
    assert result.returncode == 2 and "output path already exists" in result.stderr


class RuntimeService:
    """A hardened runtime container fed from generated snapshots."""

    def __init__(
        self, podman: Podman, image: str, generator: Generator, prefix: str
    ) -> None:
        self.podman = podman
        self.image = image
        self.generator = generator
        self.name = f"{prefix}-runtime"
        self.runtime_volume = f"{self.name}-runtime"
        self.state_volume = f"{self.name}-state"
        podman.plan_container(self.name)
        podman.create_volume(self.runtime_volume)
        podman.create_volume(self.state_volume)

    def start(self, snapshot: Path, *options: str) -> None:
        public_key = self.generator.credentials / "snapshot.pub"
        if self.podman.container_exists(self.name):
            self.podman.stop(self.name)
            self.podman.run("container", "rm", self.name)
        self.podman.run(
            "create",
            "--name",
            self.name,
            "--userns=keep-id:uid=1001,gid=1001",
            "--network",
            "none",
            "--read-only",
            "--read-only-tmpfs=false",
            "--ulimit",
            "nofile=1024:1024",
            "--memory=256m",
            "--pids-limit=128",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--env",
            f"LDAP_EXPECTED_DIRECTORY_ID={json.loads((snapshot / 'manifest.json').read_text())['directory_id']}",
            "--mount",
            f"type=volume,source={self.runtime_volume},destination=/run/openldap",
            "--mount",
            f"type=volume,source={self.state_volume},destination=/state",
            "--volume",
            f"{snapshot}:/snapshot:ro,Z",
            "--volume",
            f"{public_key}:/run/credentials/snapshot-public-key:ro,Z",
            *options,
            self.image,
        )
        self.podman.run("start", self.name)
        wait_until_healthy(self.podman, self.name)
        self.podman.exec(
            self.name,
            "sh",
            "-c",
            "test ! -e /run/openldap/verified-snapshot "
            "&& test ! -e /run/openldap/verified-files",
        )

    def bind(self, dn: str, password: str) -> subprocess.CompletedProcess[str]:
        return self.podman.exec(
            self.name,
            "ldapwhoami",
            "-x",
            "-H",
            LDAP_URI,
            "-D",
            dn,
            "-w",
            password,
            check=False,
        )

    def search(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self.podman.exec(
            self.name,
            "ldapsearch",
            "-LLL",
            "-x",
            "-H",
            LDAP_URI,
            "-D",
            APPLICATION_DN,
            "-w",
            "TEST-ONLY-app-bind",
            *arguments,
            check=False,
        )

    def alice_uuid(self) -> str:
        entry = self.search("-b", ALICE_DN, "-s", "base", "entryUUID").stdout
        return entry_uuid(entry, "uid=alice,")

    def accepted_revision(self) -> str:
        return self.podman.exec_output(
            self.name, "awk", "{ print $1 }", "/state/highest-revision"
        ).strip()


@pytest.mark.parametrize(("entry_uuid", "valid"), ENTRY_UUID_CASES)
def test_base_uuid_validation_precedes_signing(
    generator: Generator, entry_uuid: str, valid: bool, request: pytest.FixtureRequest
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["entry_uuid"] = entry_uuid
    name = f"entry_uuid-{request.node.callspec.indices['entry_uuid']}"
    result = generator.variant(name, document)
    assert result.returncode == (0 if valid else 2), result.stderr
    if valid:
        validate_manifest(SCHEMA, generator.output / name / "manifest.json")
    else:
        assert not (generator.output / name).exists()


@pytest.mark.parametrize(
    "base_dn",
    [
        "DC=example-app,dc=services,dc=example,dc=org",
        "DC=Example-App, DC=Services,DC=Example,DC=Org",
        r"dc=example\2dapp,dc=services,dc=example,dc=org",
    ],
)
def test_equivalent_base_dns(
    podman: Podman,
    store: Store,
    images: Images,
    generator: Generator,
    base_dn: str,
    request: pytest.FixtureRequest,
) -> None:
    image = images.require_runtime()
    name = f"base-{request.node.callspec.indices['base_dn']}"
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["base_dn"] = base_dn
    result = generator.variant(name, document)
    assert result.returncode == 0, result.stderr
    running = RuntimeService(podman, image, generator, f"{store.prefix}-{name}")
    running.start(generator.output / name)
    assert running.bind(ALICE_DN, "TEST-ONLY-app-user").returncode == 0
    podman.stop(running.name)


@pytest.mark.parametrize(
    "field", ["password", "password_file", "password_hash", "password_hash_file"]
)
def test_all_credential_forms_with_vault(generator: Generator, field: str) -> None:
    verifier = "{ARGON2}" + PasswordHasher(
        memory_cost=19456, time_cost=2, parallelism=1
    ).hash("TEST-ONLY-vault-user")
    value = verifier if "hash" in field else "TEST-ONLY-vault-user"
    if field.endswith("_file"):
        secret = generator.credentials / f"vault-{field}"
        secret.write_text(value + "\n", encoding="utf-8")
        secret.chmod(0o600)
        value = f"/run/credentials/{secret.name}"
    encrypted = generator.encrypt(value)
    document = (EXAMPLES / "directory.yaml").read_text()
    document = document.replace(
        'password_file: "/run/credentials/person-0001-example-app"',
        field
        + ": !vault |\n"
        + "\n".join("      " + line for line in encrypted.splitlines()),
    )
    name = f"vault-{field}"
    result = generator.variant(
        name, document, "--vault", "directory@/run/credentials/vault-password"
    )
    assert result.returncode == 0, result.stderr
    actual = records(generator.output / name / "directory.ldif")[ALICE_DN][
        "userPassword"
    ][0].decode()
    if "hash" in field:
        assert actual == verifier
    else:
        assert PasswordHasher().verify(
            actual.removeprefix("{ARGON2}"), "TEST-ONLY-vault-user"
        )
    assert not any(
        "TEST-ONLY-vault-user" in path.read_text()
        for path in (generator.output / name).iterdir()
    )


@pytest.mark.parametrize("failure", ["missing", "wrong", "tampered", "unknown-label"])
def test_vault_failures_leave_no_snapshot(generator: Generator, failure: str) -> None:
    encrypted = generator.encrypt("TEST-ONLY-secret-not-for-logs")
    arguments = ["--vault", "directory@/run/credentials/vault-password"]
    if failure == "missing":
        arguments = []
    elif failure == "wrong":
        arguments[-1] = "directory@/run/credentials/person-0003"
    elif failure == "tampered":
        lines = encrypted.splitlines()
        lines[1] = ("0" if lines[1][0] != "0" else "1") + lines[1][1:]
        encrypted = "\n".join(lines) + "\n"
    else:
        encrypted = encrypted.replace(";directory", ";another")
    document = (
        (EXAMPLES / "directory.yaml")
        .read_text()
        .replace(
            'password_file: "/run/credentials/person-0001-example-app"',
            "password: !vault |\n"
            + "\n".join("      " + line for line in encrypted.splitlines()),
        )
    )
    name = "vault-failure-" + failure
    result = generator.variant(name, document, *arguments)
    assert result.returncode == 2, result.stderr
    assert "TEST-ONLY-secret-not-for-logs" not in result.stdout + result.stderr
    assert not (generator.output / name).exists()


def test_generated_directory_authentication_and_revisions(
    podman: Podman, store: Store, images: Images, generator: Generator, generated: Path
) -> None:
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-revisions"
    )
    running.start(generated)
    assert running.bind(ALICE_DN, "TEST-ONLY-app-user").returncode == 0
    assert running.bind(ALICE_DN, "wrong").returncode != 0
    assert (
        running.bind(f"uid=bob,ou=people,{APP_BASE}", "TEST-ONLY-bob").returncode == 0
    )
    before = running.alice_uuid()
    entry = running.search("-b", ALICE_DN, "-s", "base", "memberOf", "userPassword")
    assert "memberOf: cn=staff," in entry.stdout and "userPassword:" not in entry.stdout
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["revision"] = 2
    document["users"][0]["username"] = "alice.renamed"
    del document["users"][0]["password_file"]
    verifier = "{ARGON2}" + PasswordHasher(
        memory_cost=19456, time_cost=2, parallelism=1
    ).hash("TEST-ONLY-rotated")
    document["users"][0]["password_hash"] = verifier
    result = generator.variant("renamed", document)
    assert result.returncode == 0, result.stderr
    running.start(generator.output / "renamed")
    renamed_dn = f"uid=alice.renamed,ou=people,{APP_BASE}"
    assert running.bind(ALICE_DN, "TEST-ONLY-app-user").returncode != 0
    assert running.bind(renamed_dn, "TEST-ONLY-rotated").returncode == 0
    entry = running.search("-b", renamed_dn, "-s", "base", "entryUUID")
    assert entry_uuid(entry.stdout, "uid=alice.renamed,") == before
    document["revision"] = 3
    document["users"][0]["active"] = False
    result = generator.variant("offboarded", document)
    assert result.returncode == 0, result.stderr
    running.start(generator.output / "offboarded")
    assert running.bind(renamed_dn, "TEST-ONLY-rotated").returncode != 0
    assert running.accepted_revision() == "3"
    assert (
        "cn: staff"
        not in running.search("-b", APP_BASE, "(objectClass=groupOfNames)", "cn").stdout
    )
    podman.stop(running.name)


def test_native_ldif_custom_schema_and_read_policy(
    podman: Podman, store: Store, images: Images, generator: Generator
) -> None:
    image = images.require_runtime()
    result = generator.run("native", source="native.yaml")
    assert result.returncode == 0, result.stderr
    output = generator.output / "native"
    validate_manifest(SCHEMA, output / "manifest.json")
    expected_uuid = "1088fe7c-71e9-4b5f-b968-820d4bb24c37"
    assert records(output / "directory.ldif")["cn=router,ou=devices,o=Example"][
        "entryuuid"
    ] == [expected_uuid.encode()]
    running = RuntimeService(podman, image, generator, f"{store.prefix}-native")
    running.start(output)
    bind_dn = "cn=reader,o=Example"
    assert running.bind(bind_dn, "TEST-ONLY-native-bind").returncode == 0
    result = podman.exec(
        running.name,
        "ldapsearch",
        "-LLL",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        bind_dn,
        "-w",
        "TEST-ONLY-native-bind",
        "-b",
        "cn=router,ou=devices,o=Example",
        "-s",
        "base",
        "*",
        "+",
    )
    assert "deviceLabel: Main router" in result.stdout
    assert expected_uuid in result.stdout
    assert "description:" not in result.stdout and "userPassword:" not in result.stdout
    result = podman.exec(
        running.name,
        "ldapmodify",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        bind_dn,
        "-w",
        "TEST-ONLY-native-bind",
        stdin="dn: cn=router,ou=devices,o=Example\nchangetype: modify\nreplace: deviceLabel\ndeviceLabel: Changed\n\n",
        check=False,
    )
    assert result.returncode == 53, result.stderr
    podman.stop(running.name)


def test_native_admin_named_entry_has_no_implicit_privileges(
    podman: Podman, store: Store, images: Images, generator: Generator
) -> None:
    image = images.require_runtime()
    content = (EXAMPLES / "native.ldif").read_text()
    content = content.replace("cn=reader,o=Example", "cn=admin,o=Example").replace(
        "cn: reader", "cn: admin"
    )
    (generator.inputs / "admin-entry.ldif").write_text(content)
    document = yaml.safe_load((EXAMPLES / "native.yaml").read_text())
    document["ldif_files"] = ["admin-entry.ldif"]
    result = generator.variant("admin-entry", document)
    assert result.returncode == 0, result.stderr
    running = RuntimeService(podman, image, generator, f"{store.prefix}-admin-entry")
    running.start(generator.output / "admin-entry")
    assert running.bind("cn=admin,o=Example", "TEST-ONLY-native-bind").returncode == 0
    result = podman.exec(
        running.name,
        "ldapmodify",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        "cn=admin,o=Example",
        "-w",
        "TEST-ONLY-native-bind",
        stdin="dn: cn=router,ou=devices,o=Example\nchangetype: modify\nreplace: deviceLabel\ndeviceLabel: Changed\n\n",
        check=False,
    )
    assert result.returncode == 53, result.stderr
    result = podman.exec(
        running.name,
        "ldapsearch",
        "-LLL",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        "cn=admin,o=Example",
        "-w",
        "TEST-ONLY-native-bind",
        "-b",
        "cn=admin,o=Example",
        "userPassword",
    )
    assert "userPassword:" not in result.stdout
    podman.stop(running.name)


def custom_snapshot(
    generator: Generator,
    name: str,
    *,
    database: str | None = None,
    server: str | None = None,
    data: str | None = None,
    hard_ttl: int = 43200,
) -> Path:
    document = yaml.safe_load((EXAMPLES / "native.yaml").read_text())
    for kind, content, original in (
        ("server", server, "native-server.ldif"),
        ("database", database, "native-database.ldif"),
    ):
        if content is not None:
            path = generator.inputs / f"{name}-{kind}.ldif"
            path.write_text(content)
            document["config_files"][document["config_files"].index(original)] = (
                path.name
            )
    if data is not None:
        path = generator.inputs / f"{name}-data.ldif"
        path.write_text(data)
        document["ldif_files"] = [path.name]
    document["hard_ttl_seconds"] = hard_ttl
    document["soft_ttl_seconds"] = hard_ttl // 2
    result = generator.variant(name, document)
    assert result.returncode == 0, result.stderr
    return generator.output / name


def custom_preflight(
    generator: Generator,
    podman: Podman,
    images: Images,
    snapshot: Path,
    *environment: str,
) -> subprocess.CompletedProcess[str]:
    state = generator.path / f"{snapshot.name}-preflight-state"
    state.mkdir(mode=0o700, exist_ok=True)
    arguments = [
        "--rm",
        "--network=none",
        "--read-only",
        "--read-only-tmpfs=false",
        "--userns=keep-id:uid=1001,gid=1001",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--memory=256m",
        "--pids-limit=128",
        "--tmpfs",
        "/run/openldap:rw,noexec,nosuid,nodev,mode=1777",
        "--volume",
        f"{snapshot}:/snapshot:ro,Z",
        "--volume",
        f"{generator.credentials}:/keys:ro,Z",
        "--volume",
        f"{state}:/state:ro,Z",
        "--env=LDAP_EXPECTED_DIRECTORY_ID=native-example",
        "--env=LDAP_SNAPSHOT_PUBLIC_KEY_FILE=/keys/snapshot.pub",
        "--entrypoint",
        "openldap-preflight",
    ]
    for value in environment:
        arguments.extend(("--env", value))
    result = podman.run_container(
        *arguments,
        images.require_runtime(),
        check=False,
    )
    assert not list(state.iterdir())
    return result


def native_search(
    podman: Podman, name: str, *arguments: str
) -> subprocess.CompletedProcess[str]:
    return podman.exec(
        name,
        "ldapsearch",
        "-LLL",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        "cn=reader,o=Example",
        "-w",
        "TEST-ONLY-native-bind",
        *arguments,
        check=False,
    )


def test_custom_writes_are_disposable_and_preflight_cannot_touch_live_data(
    generator: Generator,
    podman: Podman,
    store: Store,
    images: Images,
) -> None:
    database = (
        (EXAMPLES / "native-database.ldif")
        .read_text()
        .replace("olcReadOnly: TRUE", "olcReadOnly: FALSE")
        .replace("by users read", "by users write")
    )
    snapshot = custom_snapshot(generator, "custom-writable", database=database)
    result = custom_preflight(generator, podman, images, snapshot)
    assert result.returncode == 0, result.stderr
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-writable"
    )
    running.start(snapshot)
    result = podman.exec(
        running.name,
        "ldapmodify",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        "cn=reader,o=Example",
        "-w",
        "TEST-ONLY-native-bind",
        check=False,
        stdin="dn: cn=router,ou=devices,o=Example\nchangetype: modify\nreplace: deviceLabel\ndeviceLabel: Changed\n\n",
    )
    assert result.returncode == 0, result.stderr
    before_revision = running.accepted_revision()
    result = podman.exec(
        running.name,
        "openldap-preflight",
        check=False,
    )
    assert result.returncode == 64 and "separate container" in result.stderr
    assert running.accepted_revision() == before_revision
    assert (
        "deviceLabel: Changed"
        in native_search(podman, running.name, "-b", "o=Example", "deviceLabel").stdout
    )
    running.start(snapshot)
    result = native_search(podman, running.name, "-b", "o=Example", "deviceLabel")
    assert "Main router" in result.stdout and "Changed" not in result.stdout
    podman.stop(running.name)


def test_custom_credentials_and_generated_entry_ids(
    generator: Generator,
    podman: Podman,
    store: Store,
    images: Images,
) -> None:
    password = "TEST-ONLY-native-legacy"
    salt = b"test-salt"
    verifier = (
        "{SSHA}"
        + base64.b64encode(
            hashlib.sha1(password.encode() + salt).digest() + salt
        ).decode()
    )
    data = "\n".join(
        "userPassword: " + verifier if line.startswith("userPassword:") else line
        for line in (EXAMPLES / "native.ldif").read_text().splitlines()
        if not line.startswith("entryUUID:")
    )
    snapshot = custom_snapshot(generator, "custom-legacy", data=data)
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-legacy"
    )
    running.start(snapshot)
    assert running.bind("cn=reader,o=Example", password).returncode == 0
    before = podman.exec_output(
        running.name, "slapcat", "-F", "/run/openldap/slapd.d", "-b", "o=Example"
    )
    running.start(snapshot)
    after = podman.exec_output(
        running.name, "slapcat", "-F", "/run/openldap/slapd.d", "-b", "o=Example"
    )
    assert entry_uuid(before, "cn=router,") != entry_uuid(after, "cn=router,")
    podman.stop(running.name)


def test_custom_module_loading_and_server_side_sorting(
    generator: Generator,
    podman: Podman,
    store: Store,
    images: Images,
) -> None:
    server = (EXAMPLES / "native-server.ldif").read_text().rstrip()
    server += (
        "".join(
            f"\nolcModuleLoad: {module}"
            for module in sorted(MODULES - {"back_mdb", "argon2", "memberof"})
        )
        + "\n"
    )
    database = (
        (EXAMPLES / "native-database.ldif").read_text()
        + "\n\n"
        + (
            "dn: olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config\n"
            "objectClass: olcOverlayConfig\nobjectClass: olcSssVlvConfig\n"
            "olcOverlay: {0}sssvlv\nolcSssVlvMax: 2\nolcSssVlvMaxKeys: 2\nolcSssVlvMaxPerConn: 1\n"
        )
    )
    data = (
        (EXAMPLES / "native.ldif").read_text()
        + "\n\ndn: cn=edge,ou=devices,o=Example\nobjectClass: device\ncn: edge\n\n"
    )
    plain = custom_snapshot(generator, "custom-unsorted", data=data)
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-sorting"
    )
    running.start(plain)
    result = native_search(
        podman,
        running.name,
        "-E",
        "!sss=cn:caseIgnoreOrderingMatch",
        "-b",
        "o=Example",
        "(objectClass=device)",
        "cn",
    )
    assert result.returncode == 12, result.stderr
    podman.stop(running.name)
    enabled = custom_snapshot(
        generator, "custom-sorting", server=server, database=database, data=data
    )
    # Use a distinct service state: these are deliberately different revision-1 inputs.
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-sorting-enabled"
    )
    running.start(enabled)
    result = native_search(
        podman,
        running.name,
        "-E",
        "!sss=cn:caseIgnoreOrderingMatch",
        "-E",
        "pr=1/noprompt",
        "-b",
        "o=Example",
        "(objectClass=device)",
        "cn",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.index("cn: edge") < result.stdout.index("cn: router")
    podman.stop(running.name)


@pytest.mark.parametrize(
    "setting",
    [
        "LDAP_SEARCH_SIZE_LIMIT=99",
        "LDAP_SEARCH_TIME_LIMIT=unlimited",
        "LDAP_TLS_CERT_FILE=/tls/cert.pem",
        "LDAP_TLS_KEY_FILE=/tls/cert.key",
        "LDAP_TLS_CA_FILE=/tls/ca.pem",
        "LDAP_ADMIN_PASSWORD_FILE=/keys/missing",
        "LDAP_ADMIN_PASSWORD=TEST-ONLY-rejected",
        "LDAP_SEARCH_SIZE_LIMIT=",
    ],
)
def test_custom_configuration_rejects_runtime_policy_overrides(
    generator: Generator,
    podman: Podman,
    images: Images,
    setting: str,
) -> None:
    snapshot = custom_snapshot(
        generator,
        "custom-conflict-"
        + setting.split("=", 1)[0]
        + ("-empty" if setting.endswith("=") else ""),
    )
    result = custom_preflight(generator, podman, images, snapshot, setting)
    assert result.returncode == 64 and "conflicts" in result.stderr
    assert "TEST-ONLY-rejected" not in result.stderr


def test_custom_configuration_digest_and_expiry_remain_enforced(
    generator: Generator,
    podman: Podman,
    store: Store,
    images: Images,
) -> None:
    snapshot = custom_snapshot(generator, "custom-tampered")
    config_path = snapshot / "config.ldif"
    config_path.write_text(config_path.read_text() + "\n# unsigned edit\n")
    result = custom_preflight(generator, podman, images, snapshot)
    assert result.returncode == 65 and "digest" in result.stderr
    snapshot = custom_snapshot(generator, "custom-expiry", hard_ttl=12)
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-custom-expiry"
    )
    running.start(snapshot)
    result = podman.run("wait", running.name)
    assert result.stdout.strip() == "78"


def test_custom_acl_can_limit_an_account_to_a_subtree(
    generator: Generator,
    podman: Podman,
    store: Store,
    images: Images,
) -> None:
    database = (
        (EXAMPLES / "native-database.ldif")
        .read_text()
        .replace(
            "olcAccess: {2}to attrs=entry,children,objectClass,entryUUID,o,ou,cn,deviceLabel by users read by * none",
            'olcAccess: {2}to dn.subtree="ou=devices,o=Example" attrs=entry,children,objectClass,cn,ou,deviceLabel,description by dn.exact="cn=reader,o=Example" read by * none',
        )
    )
    data = (EXAMPLES / "native.ldif").read_text()
    reader = data[data.index("dn: cn=reader,") :]
    data += "\n\n" + "\n".join(
        line.replace("cn=reader,", "cn=auditor,").replace("cn: reader", "cn: auditor")
        for line in reader.splitlines()
        if not line.startswith("entryUUID:")
    )
    snapshot = custom_snapshot(
        generator, "custom-subtree", database=database, data=data
    )
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-subtree"
    )
    running.start(snapshot)
    result = native_search(
        podman, running.name, "-b", "ou=devices,o=Example", "description", "cn"
    )
    assert result.returncode == 0 and "description: Not exposed" in result.stdout
    assert "cn: router" in result.stdout
    result = native_search(podman, running.name, "-b", "cn=reader,o=Example", "cn")
    assert result.returncode == 32 and "dn: " not in result.stdout
    assert running.bind("cn=auditor,o=Example", "TEST-ONLY-native-bind").returncode == 0
    result = podman.exec(
        running.name,
        "ldapsearch",
        "-LLL",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        "cn=auditor,o=Example",
        "-w",
        "TEST-ONLY-native-bind",
        "-b",
        "ou=devices,o=Example",
        "cn",
        check=False,
    )
    assert result.returncode == 32 and "cn: router" not in result.stdout
    podman.stop(running.name)


@pytest.mark.parametrize(
    "mutation", ["database-path", "data-config", "managed-policy", "second-config"]
)
def test_runtime_rechecks_signed_custom_inputs(
    generator: Generator,
    podman: Podman,
    images: Images,
    mutation: str,
) -> None:
    snapshot = custom_snapshot(generator, "custom-signed-invalid-" + mutation)
    manifest_path = snapshot / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if mutation == "database-path":
        path = snapshot / "config.ldif"
        path.write_text(
            path.read_text().replace("/run/openldap/data", "/state/forbidden")
        )
    elif mutation == "data-config":
        path = snapshot / "directory.ldif"
        path.write_text(
            path.read_text() + "\ndn: cn=config\nobjectClass: olcGlobal\ncn: config\n\n"
        )
    elif mutation == "managed-policy":
        manifest["read_attributes"] = ["cn"]
    else:
        shutil.copyfile(snapshot / "config.ldif", snapshot / "second.ldif")
        manifest["files"].append(
            {"path": "second.ldif", "kind": "config", "sha256": ""}
        )
    for record in manifest["files"]:
        record["sha256"] = hashlib.sha256(
            (snapshot / record["path"]).read_bytes()
        ).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    result = generator.container(
        "-S",
        "-q",
        "-s",
        "/run/credentials/snapshot.key",
        "-m",
        f"/output/{snapshot.name}/manifest.json",
        "-x",
        f"/output/{snapshot.name}/manifest.json.minisig",
        entrypoint="minisign",
    )
    assert result.returncode == 0, result.stderr
    result = custom_preflight(generator, podman, images, snapshot)
    assert result.returncode == 65, result.stderr


def test_readme_custom_input_uses_only_explicit_core_schema(
    generator: Generator,
    podman: Podman,
    images: Images,
) -> None:
    readme = (PROJECT / "README.md").read_text()
    native_section = (
        readme.split("##### Custom directory: LDIF", 1)[1]
        .split("```yaml\n", 1)[1]
        .split("```", 1)[0]
    )
    document = yaml.safe_load(native_section)
    document["directory_id"] = "native-example"
    shutil.copyfile(EXAMPLES / "native.ldif", generator.inputs / "directory.ldif")
    result = generator.variant("readme-custom", document)
    assert result.returncode == 0, result.stderr
    snapshot = generator.output / "readme-custom"
    assert (
        len(
            [
                entry
                for entry in records(snapshot / "config.ldif")
                if entry.startswith("cn=") and ",cn=schema," in entry
            ]
        )
        == 2
    )
    result = custom_preflight(generator, podman, images, snapshot)
    assert result.returncode == 0, result.stderr


def test_custom_preflight_rejects_missing_health_access(
    generator: Generator,
    podman: Podman,
    images: Images,
) -> None:
    database = (
        (EXAMPLES / "native-database.ldif")
        .read_text()
        .replace("read by * break", "none by * break")
    )
    snapshot = custom_snapshot(generator, "custom-health-denied", database=database)
    result = custom_preflight(generator, podman, images, snapshot)
    assert result.returncode == 65 and "health-check identity" in result.stderr


def test_custom_health_probe_respects_authentication_mapping_and_local_ssf(
    generator: Generator,
    podman: Podman,
    store: Store,
    images: Images,
) -> None:
    server = (
        (EXAMPLES / "native-server.ldif")
        .read_text()
        .replace(
            "olcThreads: 4",
            'olcThreads: 4\nolcLocalSSF: 256\nolcAuthzRegexp: ".*,cn=peercred,cn=external,cn=auth" "cn=reader,o=Example"',
        )
    )
    database = (
        (EXAMPLES / "native-database.ldif")
        .read_text()
        .replace("by users read", "by users ssf=256 read")
    )
    snapshot = custom_snapshot(
        generator, "custom-health-mapped", server=server, database=database
    )
    result = custom_preflight(generator, podman, images, snapshot)
    assert result.returncode == 0, result.stderr
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-health-mapped"
    )
    running.start(snapshot)
    result = podman.exec(
        running.name, "ldapwhoami", "-Q", "-Y", "EXTERNAL", "-H", LDAPI_URI
    )
    assert result.stdout.strip() == "dn:cn=reader,o=example"
    podman.stop(running.name)


def test_custom_tls_uses_signed_configuration(
    generator: Generator,
    podman: Podman,
    store: Store,
    images: Images,
) -> None:
    result = generator.container(
        "req",
        "-x509",
        "-nodes",
        "-newkey",
        "rsa:2048",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout",
        "/output/native-cert.key",
        "-out",
        "/output/native-cert.pem",
        entrypoint="openssl",
    )
    assert result.returncode == 0, result.stderr
    for filename in ("native-cert.key", "native-cert.pem"):
        shutil.copyfile(generator.output / filename, generator.credentials / filename)
        (generator.credentials / filename).chmod(0o600)
    server = (
        (EXAMPLES / "native-server.ldif")
        .read_text()
        .replace(
            "olcThreads: 4",
            "olcThreads: 4\nolcTLSCertificateFile: /keys/native-cert.pem\n"
            "olcTLSCertificateKeyFile: /keys/native-cert.key\nolcTLSProtocolMin: 3.3",
        )
    )
    snapshot = custom_snapshot(generator, "custom-tls", server=server)
    result = custom_preflight(generator, podman, images, snapshot)
    assert result.returncode == 0, result.stderr
    running = RuntimeService(
        podman, images.require_runtime(), generator, f"{store.prefix}-custom-tls"
    )
    running.start(
        snapshot,
        "--env",
        "LDAP_TRANSPORT=ldaps",
        "--volume",
        f"{generator.credentials / 'native-cert.pem'}:/keys/native-cert.pem:ro,Z",
        "--volume",
        f"{generator.credentials / 'native-cert.key'}:/keys/native-cert.key:ro,Z",
    )
    result = podman.exec(
        running.name,
        "env",
        "LDAPTLS_CACERT=/keys/native-cert.pem",
        "LDAPTLS_REQCERT=demand",
        "ldapwhoami",
        "-x",
        "-H",
        "ldaps://127.0.0.1:1636",
        "-D",
        "cn=reader,o=Example",
        "-w",
        "TEST-ONLY-native-bind",
        check=False,
    )
    assert result.returncode == 0 and "cn=reader" in result.stdout, result.stderr
    assert running.bind("cn=reader,o=Example", "TEST-ONLY-native-bind").returncode != 0
    podman.stop(running.name)


def test_vault_snapshot_authenticates(
    podman: Podman, store: Store, images: Images, generator: Generator
) -> None:
    image = images.require_runtime()
    document = (EXAMPLES / "directory.yaml").read_text()
    encrypted = generator.encrypt("TEST-ONLY-vault-bind")
    document = document.replace(
        'password_file: "/run/credentials/bind-example-app"',
        "password: !vault |\n"
        + "\n".join("      " + line for line in encrypted.splitlines()),
    )
    result = generator.variant(
        "vault-bind", document, "--vault", "directory@/run/credentials/vault-password"
    )
    assert result.returncode == 0, result.stderr
    running = RuntimeService(podman, image, generator, f"{store.prefix}-vault-bind")
    running.start(generator.output / "vault-bind")
    assert running.bind(APPLICATION_DN, "TEST-ONLY-vault-bind").returncode == 0
    assert running.bind(APPLICATION_DN, "TEST-ONLY-app-bind").returncode != 0
    podman.stop(running.name)
