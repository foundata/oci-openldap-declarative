"""Exercise YAML generation and consume its output with the runtime image."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pytest
import testinfra
import yaml
from argon2 import PasswordHasher
from ldif import LDIFRecordList

from tests.integration.conftest import PROJECT, Images
from tests.integration.harness import Podman, Store
from tests.integration.lifecycle import LDAP_URI, wait_until_healthy
from tests.namespace_cases import NAMESPACE_CASES
from tests.validate_snapshot_manifest import validate_manifest

pytestmark = pytest.mark.integration

SCHEMA = PROJECT / "schema/snapshot-manifest-v1.schema.json"
EXAMPLES = PROJECT / "examples/generator"
FIXTURES = PROJECT / "tests/fixtures"
APP_BASE = "dc=example-app,dc=services,dc=example,dc=org"
ALICE_DN = f"uid=alice,ou=people,{APP_BASE}"
APPLICATION_DN = f"cn=application,ou=services,{APP_BASE}"
PASSWORDS = {
    "person-0001": "TEST-ONLY-default-user",
    "person-0001-example-app": "TEST-ONLY-app-user",
    "person-0001-example-mail": "TEST-ONLY-mail-user",
    "person-0003-example-mail": "TEST-ONLY-bob-mail",
    "bind-example-app": "TEST-ONLY-app-bind",
    "bind-example-mail": "TEST-ONLY-mail-bind",
}


def epoch(manifest: Path, field: str) -> int:
    document = json.loads(manifest.read_text(encoding="utf-8"))
    value = str(document[field]).replace("Z", "+00:00")
    return int(datetime.fromisoformat(value).timestamp())


@dataclass
class Generator:
    """Run the generator image against a private credential workspace."""

    podman: Podman
    image: str
    path: Path

    @property
    def credentials(self) -> Path:
        return self.path / "credentials"

    @property
    def output(self) -> Path:
        return self.path / "output"

    def run(
        self,
        directory_mount: str,
        directory_path: str,
        output_name: str,
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        return self.podman.run_container(
            "--rm",
            "--userns=keep-id",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--network",
            "none",
            "--volume",
            directory_mount,
            "--volume",
            f"{self.credentials}:/run/credentials:ro,Z",
            "--volume",
            f"{self.output}:/output:Z",
            self.image,
            "--directory",
            directory_path,
            "--credentials",
            "/run/credentials/credentials.yaml",
            "--signing-key",
            "/run/credentials/snapshot.key",
            *arguments,
            "--output",
            f"/output/{output_name}",
            check=False,
        )

    def generate_examples(
        self, output_name: str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            f"{self.path / 'examples'}:/input:ro,Z",
            "/input/directory.yaml",
            output_name,
            *arguments,
        )

    def generate_fixture(
        self, fixture: str, output_name: str
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            f"{self.path / 'fixtures'}:/input:ro,Z",
            f"/input/{fixture}",
            output_name,
            "--service",
            "example-app",
        )

    def generate_variant(
        self, name: str, content: str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        variant = self.path / f"{name}.yaml"
        variant.write_text(content, encoding="utf-8")
        variant.chmod(0o644)
        return self.run(
            f"{variant}:/input/directory.yaml:ro,Z",
            "/input/directory.yaml",
            name,
            *arguments,
        )


@pytest.fixture(scope="module")
def generator(podman: Podman, store: Store, images: Images) -> Generator:
    image = images.require_generator()
    path = store.workspace / "generator"
    path.mkdir()
    prepared = Generator(podman, image, path)
    shutil.copytree(EXAMPLES, path / "examples")
    shutil.copytree(FIXTURES, path / "fixtures")
    prepared.credentials.mkdir()
    prepared.output.mkdir()
    (prepared.credentials / "credentials.yaml").write_bytes(
        (EXAMPLES / "credentials.yaml.example").read_bytes()
    )
    for name, secret in PASSWORDS.items():
        (prepared.credentials / name).write_text(f"{secret}\n", encoding="utf-8")
    for item in prepared.credentials.iterdir():
        item.chmod(0o600)
    podman.run_container(
        "--rm",
        "--user",
        "0:0",
        "--entrypoint",
        "minisign",
        "--volume",
        f"{path}:/work:Z",
        image,
        "-G",
        "-W",
        "-p",
        "/work/credentials/snapshot.pub",
        "-s",
        "/work/credentials/snapshot.key",
    )
    (prepared.credentials / "snapshot.key").chmod(0o600)
    return prepared


@pytest.fixture(scope="module")
def generated(generator: Generator) -> Path:
    completed = generator.generate_examples("generated")
    assert completed.returncode == 0, completed.stderr
    return generator.output / "generated"


@pytest.fixture
def generator_sleeper(podman: Podman, images: Images) -> str:
    image = images.require_generator()
    name = podman.transient_name()
    podman.run(
        "run",
        "--detach",
        "--name",
        name,
        "--network",
        "none",
        "--entrypoint",
        "sh",
        image,
        "-c",
        "sleep 600",
    )
    return name


def test_generator_image_contents_match_the_declared_boundary(
    podman: Podman, generator_sleeper: str
) -> None:
    host = testinfra.get_host(f"podman://{generator_sleeper}")
    try:
        assert host.check_output("id -u") == "1001"
        assert host.check_output("id -g") == "1001"
        for path in (
            "/usr/local/share/openldap-declarative/package-versions.txt",
            "/usr/local/share/openldap-declarative/LICENSE.txt",
            "/usr/share/doc/python3-ldap/copyright",
        ):
            assert host.file(path).size > 0, path
        entrypoint = host.file("/usr/local/bin/openldap-snapshot-generator")
        assert (entrypoint.uid, entrypoint.gid, entrypoint.mode) == (0, 0, 0o555)
        license_file = host.file("/usr/local/share/openldap-declarative/LICENSE.txt")
        assert (license_file.uid, license_file.gid, license_file.mode) == (0, 0, 0o444)
        for path in ("/input", "/run/credentials"):
            directory = host.file(path)
            assert (directory.uid, directory.gid, directory.mode) == (0, 0, 0o555), path
        output = host.file("/output")
        assert (output.uid, output.gid, output.mode) == (1001, 1001, 0o700)
    finally:
        podman.run("rm", "--force", generator_sleeper)


def test_generated_snapshots_select_active_users_per_service(generated: Path) -> None:
    for service_id in ("example-app", "example-mail"):
        for required in ("directory.ldif", "manifest.json", "manifest.json.minisig"):
            assert (generated / service_id / required).is_file()
    for root, directories, files in os.walk(generated):
        for directory in directories:
            assert (Path(root) / directory).stat().st_mode & 0o777 == 0o700
        for file in files:
            assert (Path(root) / file).stat().st_mode & 0o777 == 0o600

    app_ldif = (generated / "example-app/directory.ldif").read_text(encoding="utf-8")
    mail_ldif = (generated / "example-mail/directory.ldif").read_text(encoding="utf-8")
    assert "uid: alice" in app_ldif
    assert "uid: bob" not in app_ldif and "uid: disabled" not in app_ldif
    assert "uid: bob" in mail_ldif and "uid: disabled" not in mail_ldif
    assert entry_uuid(app_ldif, "uid=alice,") == entry_uuid(mail_ldif, "uid=alice,")
    for path in generated.rglob("*"):
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            assert not any(secret in content for secret in PASSWORDS.values()), path


def entry_uuid(ldif: str, dn_prefix: str) -> str:
    found = False
    for line in ldif.splitlines():
        if line.startswith(f"dn: {dn_prefix}"):
            found = True
        if found and line.startswith("entryUUID: "):
            return line.removeprefix("entryUUID: ")
    pytest.fail(f"no entryUUID for {dn_prefix}")


def test_generated_manifests_match_the_schema_and_expiry_policy(
    generated: Path,
) -> None:
    app = generated / "example-app/manifest.json"
    mail = generated / "example-mail/manifest.json"
    validate_manifest(SCHEMA, app)
    validate_manifest(SCHEMA, mail)
    assert epoch(app, "generated_at") == epoch(mail, "generated_at")
    assert epoch(app, "soft_expires_at") - epoch(app, "generated_at") == 21600
    assert epoch(app, "expires_at") - epoch(app, "generated_at") == 43200
    assert epoch(mail, "soft_expires_at") - epoch(mail, "generated_at") == 21000
    assert epoch(mail, "expires_at") - epoch(mail, "generated_at") == 42600
    assert epoch(app, "soft_expires_at") - epoch(mail, "soft_expires_at") == 600
    assert epoch(app, "expires_at") - epoch(mail, "expires_at") == 600


def test_controlled_generation_time_staggers_deadlines(generator: Generator) -> None:
    completed = generator.generate_examples(
        "controlled", "--generated-at", "2030-01-01T00:00:00Z"
    )
    assert completed.returncode == 0, completed.stderr
    app = json.loads(
        (generator.output / "controlled/example-app/manifest.json").read_text(
            encoding="utf-8"
        )
    )
    mail = json.loads(
        (generator.output / "controlled/example-mail/manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert (app["generated_at"], app["soft_expires_at"], app["expires_at"]) == (
        "2030-01-01T00:00:00Z",
        "2030-01-01T06:00:00Z",
        "2030-01-01T12:00:00Z",
    )
    assert (mail["generated_at"], mail["soft_expires_at"], mail["expires_at"]) == (
        "2030-01-01T00:00:00Z",
        "2030-01-01T05:50:00Z",
        "2030-01-01T11:50:00Z",
    )


@pytest.mark.parametrize(
    ("offset", "message"),
    [
        pytest.param(
            -1,
            "expiry_offset_seconds must be an integer from 0 through 86400",
            id="negative",
        ),
        pytest.param(
            86401,
            "expiry_offset_seconds must be an integer from 0 through 86400",
            id="excessive",
        ),
        pytest.param(
            21600,
            "expiry_offset_seconds must be less than soft_ttl_seconds",
            id="soft-boundary",
        ),
    ],
)
def test_expiry_offset_boundaries_are_rejected(
    generator: Generator, offset: int, message: str, request: pytest.FixtureRequest
) -> None:
    name = f"offset-{request.node.callspec.id}"
    content = (EXAMPLES / "directory.yaml").read_text(encoding="utf-8")
    completed = generator.generate_variant(
        name,
        content.replace(
            "expiry_offset_seconds: 0", f"expiry_offset_seconds: {offset}", 1
        ),
    )
    assert completed.returncode == 2
    assert message in completed.stdout + completed.stderr
    assert not (generator.output / name).exists()


def test_unknown_service_and_existing_output_are_rejected(
    generator: Generator, generated: Path
) -> None:
    unknown = generator.generate_examples("rejected", "--service", "unknown-service")
    assert unknown.returncode == 2
    assert (
        "unknown selected services: unknown-service" in unknown.stdout + unknown.stderr
    )
    assert not (generator.output / "rejected").exists()

    existing = generator.generate_examples(generated.name)
    assert existing.returncode == 2
    assert (
        "output path already exists: /output/generated"
        in existing.stdout + existing.stderr
    )


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
            "LDAP_EXPECTED_SERVICE_ID=example-app",
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
            "&& test ! -e /run/openldap/verified-files "
            '&& ! grep -R -F -q "nis.ldif" /run/openldap/slapd.d',
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
def test_generator_namespace_validation_precedes_signing(
    generator: Generator, namespace: str, valid: bool, request: pytest.FixtureRequest
) -> None:
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["uuid_namespace"] = namespace
    name = f"namespace-{request.node.callspec.indices['namespace']}"
    result = generator.generate_variant(name, yaml.safe_dump(document))
    assert result.returncode == (0 if valid else 2), result.stdout + result.stderr
    if valid:
        manifest = generator.output / name / "example-app/manifest.json"
        validate_manifest(SCHEMA, manifest)
        assert json.loads(manifest.read_text())["uuid_namespace"] == namespace.lower()
    else:
        assert "uuid_namespace" in result.stderr
        assert not (generator.output / name).exists()


@pytest.mark.parametrize(
    "base_dn",
    [
        "DC=example-app,dc=services,dc=example,dc=org",
        "DC=Example-App, DC=Services,DC=Example,DC=Org",
        r"dc=example\2dapp,dc=services,dc=example,dc=org",
    ],
)
def test_accepted_base_dns_start_authenticate_and_report_healthy(
    podman: Podman,
    store: Store,
    images: Images,
    generator: Generator,
    base_dn: str,
    request: pytest.FixtureRequest,
) -> None:
    image = images.require_runtime()
    name = f"base-dn-{request.node.callspec.indices['base_dn']}"
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["services"][0]["base_dn"] = base_dn
    result = generator.generate_variant(name, yaml.safe_dump(document))
    assert result.returncode == 0, result.stderr
    service = RuntimeService(podman, image, generator, f"{store.prefix}-{name}")
    service.start(generator.output / name / "example-app")
    assert service.bind(ALICE_DN, "TEST-ONLY-app-user").returncode == 0
    status = podman.exec(service.name, "/usr/local/lib/openldap-declarative/status.sh")
    assert json.loads(status.stdout)["ldap"] == "available"
    assert json.loads(status.stdout)["state"] == "healthy"
    podman.stop(service.name)


@pytest.fixture(scope="module")
def service(
    podman: Podman, store: Store, images: Images, generator: Generator
) -> RuntimeService:
    return RuntimeService(podman, images.require_runtime(), generator, store.prefix)


@pytest.mark.parametrize(
    ("user_field", "bind_field"),
    [
        ("password_hash", "bind_password_hash_file"),
        ("password_hash_file", "bind_password_hash"),
        ("service_password_hashes", "bind_password_file"),
        ("service_password_hash_files", "bind_password_hash"),
    ],
)
def test_seeded_hashes_authenticate_unchanged(
    podman: Podman,
    store: Store,
    images: Images,
    generator: Generator,
    user_field: str,
    bind_field: str,
) -> None:
    image = images.require_runtime()
    name = f"seeded-{user_field}"
    # Native OpenLDAP hashing from stdin is also the documented admin workflow.
    user_hash = podman.run_container(
        "--rm",
        "-i",
        "--network",
        "none",
        "--entrypoint",
        "slappasswd",
        image,
        "-o",
        "module-path=/usr/lib/ldap",
        "-o",
        "module-load=argon2 m=19456 t=2 p=1",
        "-h",
        "{ARGON2}",
        "-T",
        "/dev/stdin",
        stdin="TEST-ONLY-seeded-user",
    ).stdout.strip()
    assert user_hash.startswith("{ARGON2}$argon2id$v=19$m=19456,t=2,p=1$")
    bind_hash = "{ARGON2}" + PasswordHasher(
        memory_cost=65536, time_cost=3, parallelism=4
    ).hash("TEST-ONLY-app-bind")
    for suffix, value in (("user", user_hash), ("bind", bind_hash)):
        path = generator.credentials / f"{name}-{suffix}.hash"
        path.write_text(value + "\n", encoding="utf-8")
        path.chmod(0o600)
    user_value = (
        f"/run/credentials/{name}-user.hash"
        if user_field.endswith(("file", "files"))
        else user_hash
    )
    user = (
        {
            "password_file": "/run/credentials/person-0001",
            user_field: {"example-app": user_value},
        }
        if user_field.startswith("service_")
        else {user_field: user_value}
    )
    bind_value = {
        "bind_password_hash": bind_hash,
        "bind_password_hash_file": f"/run/credentials/{name}-bind.hash",
        "bind_password_file": "/run/credentials/bind-example-app",
    }[bind_field]
    credential_path = generator.credentials / f"{name}.yaml"
    credential_path.write_text(
        yaml.safe_dump(
            {
                "format_version": 1,
                "users": {"person-0001": user},
                "services": {"example-app": {bind_field: bind_value}},
            }
        ),
        encoding="utf-8",
    )
    credential_path.chmod(0o600)
    result = generator.generate_examples(
        name,
        "--service",
        "example-app",
        "--credentials",
        f"/run/credentials/{credential_path.name}",
    )
    assert result.returncode == 0, result.stderr
    assert set(path.name for path in (generator.output / name).iterdir()) == {
        "example-app"
    }
    snapshot = generator.output / name / "example-app"
    with (snapshot / "directory.ldif").open("rb") as stream:
        parser = LDIFRecordList(stream)
        parser.parse()
    entries = dict(parser.all_records)
    assert entries[ALICE_DN]["userPassword"] == [user_hash.encode()]
    if bind_field != "bind_password_file":
        assert entries[APPLICATION_DN]["userPassword"] == [bind_hash.encode()]
    running = RuntimeService(podman, image, generator, f"{store.prefix}-{name}")
    running.start(snapshot)
    assert running.bind(ALICE_DN, "TEST-ONLY-seeded-user").returncode == 0
    assert running.bind(ALICE_DN, "TEST-ONLY-default-user").returncode != 0
    assert running.bind(APPLICATION_DN, "TEST-ONLY-app-bind").returncode == 0
    assert running.bind(APPLICATION_DN, "TEST-ONLY-wrong-bind").returncode != 0
    podman.stop(running.name)


def test_group_optional_users_empty_groups_and_per_service_ttls(
    podman: Podman,
    store: Store,
    images: Images,
    generator: Generator,
) -> None:
    image = images.require_runtime()
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["users"][2]["uid"] = "foo.bar"
    document["services"][0]["users"] = ["person-0003"]
    document["services"][1]["soft_ttl_seconds"] = 3600
    document["services"][1]["hard_ttl_seconds"] = 7200
    for group_id, members in (("empty", []), ("inactive", ["person-0002"])):
        document["groups"].append(
            {
                "id": group_id,
                "common_name": group_id,
                "members": members,
            }
        )
        document["services"][0]["groups"].append(group_id)
    credentials = yaml.safe_load(
        (generator.credentials / "credentials.yaml").read_text()
    )
    credentials["users"]["person-0003"]["password_file"] = (
        "/run/credentials/person-0003-example-mail"
    )
    source = generator.credentials / "group-optional.yaml"
    source.write_text(yaml.safe_dump(credentials), encoding="utf-8")
    source.chmod(0o600)
    result = generator.generate_variant(
        "group-optional",
        yaml.safe_dump(document),
        "--credentials",
        "/run/credentials/group-optional.yaml",
    )
    assert result.returncode == 0, result.stderr
    output = generator.output / "group-optional"
    app = output / "example-app/manifest.json"
    mail = output / "example-mail/manifest.json"
    assert epoch(app, "generated_at") == epoch(mail, "generated_at")
    assert epoch(app, "expires_at") - epoch(app, "generated_at") == 43200
    assert epoch(mail, "soft_expires_at") - epoch(mail, "generated_at") == 3000
    assert epoch(mail, "expires_at") - epoch(mail, "generated_at") == 6600
    running = RuntimeService(podman, image, generator, f"{store.prefix}-group-optional")
    running.start(output / "example-app")
    user_dn = f"uid=foo.bar,ou=people,{APP_BASE}"
    assert running.bind(user_dn, "TEST-ONLY-bob-mail").returncode == 0
    user = running.search("-b", user_dn, "-s", "base", "uid", "memberOf")
    assert user.returncode == 0 and "uid: foo.bar" in user.stdout
    assert "memberOf:" not in user.stdout
    groups = running.search(
        "-b", f"ou=groups,{APP_BASE}", "(objectClass=groupOfNames)", "cn"
    )
    assert groups.returncode == 0 and "cn: staff" in groups.stdout
    assert "cn: empty" not in groups.stdout and "cn: inactive" not in groups.stdout
    podman.stop(running.name)


def test_runtime_authenticates_against_generated_output(
    service: RuntimeService, generated: Path
) -> None:
    service.start(generated / "example-app")
    accepted = service.bind(ALICE_DN, "TEST-ONLY-app-user")
    assert accepted.returncode == 0 and f"dn:{ALICE_DN}" in accepted.stdout
    assert service.bind(ALICE_DN, "TEST-ONLY-default-user").returncode != 0
    membership = service.search("-b", ALICE_DN, "-s", "base", "uid", "memberOf")
    assert f"memberOf: cn=staff,ou=groups,{APP_BASE}" in membership.stdout
    enumeration = service.search(
        "-b",
        APP_BASE,
        "-s",
        "sub",
        "(objectClass=*)",
        "dn",
        "uid",
        "cn",
        "userPassword",
    )
    assert enumeration.returncode == 0
    assert f"dn: {ALICE_DN}" in enumeration.stdout
    assert "userPassword:" not in enumeration.stdout


def test_password_rotation_and_offboarding_revisions(
    service: RuntimeService, generator: Generator, generated: Path
) -> None:
    service.start(generated / "example-app")
    initial_uuid = service.alice_uuid()

    rotated = generator.credentials / "person-0001-example-app"
    rotated.write_text("TEST-ONLY-rotated-app-user\n", encoding="utf-8")
    rotated.chmod(0o600)
    assert (
        generator.generate_fixture(
            "directory-revision-2.yaml", "generated-2"
        ).returncode
        == 0
    )
    service.start(generator.output / "generated-2/example-app")
    assert service.bind(ALICE_DN, "TEST-ONLY-app-user").returncode != 0
    assert service.bind(ALICE_DN, "TEST-ONLY-rotated-app-user").returncode == 0
    assert service.alice_uuid() == initial_uuid

    assert (
        generator.generate_fixture(
            "directory-revision-3.yaml", "generated-3"
        ).returncode
        == 0
    )
    service.start(generator.output / "generated-3/example-app")
    assert service.bind(ALICE_DN, "TEST-ONLY-app-user").returncode != 0
    assert service.bind(ALICE_DN, "TEST-ONLY-rotated-app-user").returncode != 0
    assert (
        "uid: alice" not in service.search("-b", ALICE_DN, "-s", "base", "uid").stdout
    )
    assert service.accepted_revision() == "3"
