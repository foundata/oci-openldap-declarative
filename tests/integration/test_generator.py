"""Generate snapshots from both input routes, then exercise their LDAP behavior."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import pytest
import yaml
from argon2 import PasswordHasher
from ldif import LDIFRecordList

from tests.integration.conftest import PROJECT, Images
from tests.integration.harness import Podman, Store
from tests.integration.lifecycle import LDAP_URI, wait_until_healthy
from tests.namespace_cases import NAMESPACE_CASES
from tests.validate_snapshot_manifest import validate_manifest

pytestmark = pytest.mark.integration
EXAMPLES = PROJECT / "examples/generator"
SCHEMA = PROJECT / "schema/snapshot-manifest-v1.schema.json"
APP_BASE = "dc=example-app,dc=services,dc=example,dc=org"
ALICE_DN = f"uid=alice,ou=people,{APP_BASE}"
APPLICATION_DN = f"cn=application,ou=services,{APP_BASE}"
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
    result = generator.container(
        "-c",
        "id -u; id -g; command -v ansible-vault; test ! -e /usr/sbin/slapd; test ! -e /TEMP-Notes; test -s /usr/share/doc/ansible-core/copyright; test -s /usr/local/share/openldap-declarative/LICENSE.txt",
        entrypoint="sh",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("1001\n1001\n/usr/bin/ansible-vault\n")


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
        "givenName": [b"Alice"],
        "initials": [b"AE"],
        "displayName": [b"Alice Example"],
        "description": [b"Application directory user"],
        "physicalDeliveryOfficeName": [b"Main office"],
        "telephoneNumber": [b"+49 721 5550100"],
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
    assert (
        "proxyAddresses:" not in result.stdout and "description:" not in result.stdout
    )
    assert "userPassword:" not in result.stdout
    podman.stop(running.name)


def test_bind_accounts_rotate_rename_and_revoke_independently(
    generator: Generator, podman: Podman, images: Images, store: Store
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    secondary = {
        "id": "bind-secondary",
        "common_name": "secondary",
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
    secondary_dn = f"cn=secondary,ou=services,{APP_BASE}"
    original_uuid = records(generator.output / "multi-bind-1/directory.ldif")[
        secondary_dn
    ]["entryUUID"]
    assert running.bind(secondary_dn, "TEST-ONLY-secondary").returncode == 0
    assert running.bind(APPLICATION_DN, "TEST-ONLY-app-bind").returncode == 0
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
    secondary.update(common_name="renamed", password="TEST-ONLY-rotated")
    result = generator.variant("multi-bind-2", document)
    assert result.returncode == 0, result.stderr
    renamed_dn = f"cn=renamed,ou=services,{APP_BASE}"
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

    def start(self, snapshot: Path) -> None:
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


@pytest.mark.parametrize(("namespace", "valid"), NAMESPACE_CASES)
def test_namespace_validation_precedes_signing(
    generator: Generator, namespace: str, valid: bool, request: pytest.FixtureRequest
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["uuid_namespace"] = namespace
    name = f"namespace-{request.node.callspec.indices['namespace']}"
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
    document["users"][0]["uid"] = "alice.renamed"
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
    assert result.returncode == 50, result.stderr
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
    assert result.returncode == 50, result.stderr
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
