"""Exercise the signed snapshot contract of the runtime image in rootless Podman."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
import testinfra

from tests.integration.conftest import PROJECT, Images
from tests.integration.harness import (
    OWNER_LABEL,
    Podman,
    Store,
    iso_timestamp,
    sha256_file,
    utc_now,
)
from tests.integration.lifecycle import (
    LDAP_URI,
    LDAPI_URI,
    LIB,
    POLL_INTERVAL,
    assert_build_artifacts_absent,
    wait_until_healthy,
    wait_until_initializing,
)
from tests.namespace_cases import NAMESPACE_CASES

pytestmark = pytest.mark.integration

BACKSTOP = PROJECT / "examples/systemd/openldap-expiry-backstop"
BASE_DN = "dc=example,dc=org"
TEST_USER_DN = f"uid=test,ou=people,{BASE_DN}"
APP_DN = f"cn=app,ou=services,{BASE_DN}"
TEST_USER_UUID = "a4bcb5de-4982-51e9-b7e8-7e8d6b6f4c22"
MAXIMUM_IMAGE_SIZE = 185_000_000
MINUTES = timedelta(minutes=1)
SECONDS = timedelta(seconds=1)


@dataclass
class RuntimeWorkspace:
    """Signed test snapshots, keys, certificates and helper containers."""

    podman: Podman
    image: str
    path: Path
    prefix: str

    def image_tool(self, tool: str, *arguments: str) -> str:
        completed = self.podman.run_container(
            "--rm",
            "--user",
            "0:0",
            "--entrypoint",
            tool,
            "--volume",
            f"{self.path}:/work:Z",
            self.image,
            *arguments,
        )
        return completed.stdout.strip()

    def argon2_hash(self, secret: str) -> str:
        return self.image_tool(
            "slappasswd",
            "-o",
            "module-path=/usr/lib/ldap",
            "-o",
            "module-load=argon2 m=19456 t=2 p=1",
            "-h",
            "{ARGON2}",
            "-s",
            secret,
        )

    def write_directory_ldif(self) -> None:
        user_hash = self.argon2_hash("test-user-password")
        service_hash = self.argon2_hash("test-bind-password")
        lines = [
            f"dn: {BASE_DN}",
            "objectClass: top",
            "objectClass: dcObject",
            "objectClass: organization",
            "dc: example",
            "o: Example",
            "entryUUID: 032e4d5a-6605-5d20-8d88-370c02d99f91",
            "",
            f"dn: ou=people,{BASE_DN}",
            "objectClass: organizationalUnit",
            "ou: people",
            "entryUUID: 58b79d55-a592-57dc-839f-019da88df033",
            "",
            f"dn: ou=groups,{BASE_DN}",
            "objectClass: organizationalUnit",
            "ou: groups",
            "entryUUID: 91d893b5-0871-5158-8548-3b7011e29444",
            "",
            f"dn: ou=services,{BASE_DN}",
            "objectClass: organizationalUnit",
            "ou: services",
            "entryUUID: 107f56d7-a8c4-5b73-b0f6-44bd2194b221",
            "",
            f"dn: {TEST_USER_DN}",
            "objectClass: inetOrgPerson",
            "uid: test",
            "cn: Test User",
            "sn: User",
            "description: internal snapshot metadata",
            f"entryUUID: {TEST_USER_UUID}",
            f"memberOf: cn=users,ou=groups,{BASE_DN}",
            f"userPassword: {user_hash}",
            "",
            f"dn: {APP_DN}",
            "objectClass: organizationalRole",
            "objectClass: simpleSecurityObject",
            "cn: app",
            "entryUUID: f04d74d9-4295-5226-a6cb-72b3a94d92ef",
            f"userPassword: {service_hash}",
            "",
            f"dn: cn=users,ou=groups,{BASE_DN}",
            "objectClass: groupOfNames",
            "cn: users",
            "entryUUID: 03f6d440-aabe-59f5-83fb-3fa8bd132942",
            f"member: {TEST_USER_DN}",
        ]
        (self.path / "directory.ldif").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )

    def sign_manifest(self, snapshot_dir: Path) -> None:
        relative = snapshot_dir.relative_to(self.path)
        (snapshot_dir / "manifest.json.minisig").unlink(missing_ok=True)
        self.image_tool(
            "minisign",
            "-S",
            "-W",
            "-s",
            "/work/private/snapshot.key",
            "-m",
            f"/work/{relative}/manifest.json",
            "-x",
            f"/work/{relative}/manifest.json.minisig",
            "-t",
            "integration test snapshot",
        )

    def refresh_signature(self, snapshot_dir: Path) -> None:
        manifest = snapshot_dir / "manifest.json"
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document["files"][0]["sha256"] = sha256_file(snapshot_dir / "directory.ldif")
        manifest.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        manifest.chmod(0o644)
        self.sign_manifest(snapshot_dir)

    def create_snapshot(
        self,
        name: str,
        revision: int,
        soft: timedelta,
        hard: timedelta,
        generated: timedelta = timedelta(0),
    ) -> Path:
        snapshot_dir = self.path / name
        snapshot_dir.mkdir()
        shutil.copy(self.path / "directory.ldif", snapshot_dir / "directory.ldif")
        now = utc_now()
        manifest = {
            "format_version": 1,
            "service_id": "test-service",
            "base_dn": BASE_DN,
            "revision": revision,
            "generated_at": iso_timestamp(now + generated),
            "soft_expires_at": iso_timestamp(now + soft),
            "expires_at": iso_timestamp(now + hard),
            "uuid_namespace": "7f38d690-8427-5ca2-98b4-bd5ee71ac31f",
            "files": [
                {
                    "path": "directory.ldif",
                    "sha256": sha256_file(snapshot_dir / "directory.ldif"),
                }
            ],
        }
        (snapshot_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        self.sign_manifest(snapshot_dir)
        self.publish_permissions(snapshot_dir)
        return snapshot_dir

    def copy_snapshot(self, source: str, destination: str) -> Path:
        destination_dir = self.path / destination
        shutil.copytree(self.path / source, destination_dir)
        self.publish_permissions(destination_dir)
        return destination_dir

    @staticmethod
    def publish_permissions(snapshot_dir: Path) -> None:
        snapshot_dir.chmod(0o755)
        for item in snapshot_dir.iterdir():
            item.chmod(0o644)

    def modify_ldif(self, snapshot_dir: Path, edit: Callable[[str], str]) -> None:
        ldif = snapshot_dir / "directory.ldif"
        ldif.write_text(edit(ldif.read_text(encoding="utf-8")), encoding="utf-8")
        self.refresh_signature(snapshot_dir)


@dataclass(frozen=True)
class Container:
    name: str
    runtime_volume: str
    state_volume: str


class Runtime:
    """Create hardened runtime containers and assert their behavior."""

    def __init__(self, podman: Podman, workspace: RuntimeWorkspace) -> None:
        self.podman = podman
        self.workspace = workspace
        self.image = workspace.image
        self.prefix = workspace.prefix

    def state_volume(self, test_name: str) -> str:
        return f"{self.prefix}-{test_name}-state"

    def create(
        self,
        test_name: str,
        snapshot_name: str,
        service_id: str = "test-service",
        state_volume: str | None = None,
        transport: str = "ldap",
        key_mode: str = "file",
        extra_environment: str = "LDAP_TLS_CA_FILE=/tls/ca.pem",
    ) -> Container:
        workspace = self.workspace.path
        name = f"{self.prefix}-{test_name}"
        runtime_volume = f"{name}-runtime"
        state = state_volume or self.state_volume(test_name)
        key_target = "/run/credentials/snapshot-public-key"
        key_environment, key_mount = {
            "directory": (
                "LDAP_SNAPSHOT_PUBLIC_KEY_DIR=/run/credentials/snapshot-public-keys",
                f"{workspace}/public:/run/credentials/snapshot-public-keys:ro,z",
            ),
            "file": (
                f"LDAP_SNAPSHOT_PUBLIC_KEY_FILE={key_target}",
                f"{workspace}/public/snapshot.pub:{key_target}:ro,z",
            ),
            "rotated": (
                f"LDAP_SNAPSHOT_PUBLIC_KEY_FILE={key_target}",
                f"{workspace}/public/rotated.pub:{key_target}:ro,z",
            ),
        }[key_mode]
        self.podman.create_volume(runtime_volume)
        if not self.podman.volume_exists(state):
            self.podman.create_volume(state)
        self.podman.plan_container(name)
        self.podman.run(
            "create",
            "--name",
            name,
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
            f"LDAP_EXPECTED_SERVICE_ID={service_id}",
            "--env",
            f"LDAP_TRANSPORT={transport}",
            "--env",
            key_environment,
            "--env",
            extra_environment,
            "--mount",
            f"type=volume,source={runtime_volume},destination=/run/openldap",
            "--mount",
            f"type=volume,source={state},destination=/state",
            "--volume",
            f"{workspace}/{snapshot_name}:/snapshot:ro,z",
            "--volume",
            key_mount,
            "--volume",
            f"{workspace}/admin:/run/credentials/admin:ro,Z",
            "--volume",
            f"{workspace}/tls:/tls:ro,Z",
            self.image,
        )
        return Container(name, runtime_volume, state)

    def start_healthy(self, container: Container) -> None:
        self.podman.run("start", container.name)
        wait_until_healthy(self.podman, container.name)

    def stop(self, container: Container) -> int:
        self.podman.stop(container.name)
        return int(self.podman.inspect(container.name, "{{.State.ExitCode}}"))

    def expect_exit(self, container: Container, status: int, message: str = "") -> None:
        self.podman.run("start", container.name)
        actual = self.podman.wait(container.name)
        logs = self.podman.logs(container.name)
        assert actual == status, (
            f"{container.name} exited {actual}, expected {status}:\n{logs}"
        )
        assert message in logs, f"{container.name} did not log {message!r}:\n{logs}"
        assert_build_artifacts_absent(self.podman, self.image, container.runtime_volume)

    def ldap_search(self, container: Container, *arguments: str) -> str:
        return self.podman.exec_output(
            container.name, "ldapsearch", "-LLL", "-x", "-H", LDAP_URI, *arguments
        )

    def whoami(
        self, container: Container, bind_dn: str, password: str
    ) -> subprocess.CompletedProcess[str]:
        return self.podman.exec(
            container.name,
            "ldapwhoami",
            "-x",
            "-H",
            LDAP_URI,
            "-D",
            bind_dn,
            "-w",
            password,
            check=False,
        )

    def status(self, container: Container) -> tuple[int, dict[str, object]]:
        completed = self.podman.exec(container.name, f"{LIB}/status.sh", check=False)
        document: dict[str, object] = json.loads(completed.stdout)
        return completed.returncode, document

    def run_backstop(
        self,
        container: Container,
        snapshot: Path,
        *,
        public_key: Path | None = None,
        expected_status: int = 0,
    ) -> None:
        environment = {
            **os.environ,
            "PODMAN": str(self.workspace.path / "podman-backstop"),
        }
        completed = subprocess.run(
            [
                str(BACKSTOP),
                container.name,
                str(snapshot),
                str(public_key or self.workspace.path / "public/snapshot.pub"),
                "test-service",
            ],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert completed.returncode == expected_status, (
            completed.stdout + completed.stderr
        )

    def preflight(
        self, snapshot: Path, state_dir: Path, runtime_dir: Path
    ) -> subprocess.CompletedProcess[str]:
        return self.podman.run_container(
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--read-only-tmpfs=false",
            "--ulimit",
            "nofile=1024:1024",
            "--memory=256m",
            "--pids-limit=128",
            "--userns",
            "keep-id:uid=1001,gid=1001",
            "--user",
            "1001:1001",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--volume",
            f"{runtime_dir}:/run/openldap:rw,Z",
            "--volume",
            f"{snapshot}:/candidate:ro,z",
            "--volume",
            f"{self.workspace.path}/public/snapshot.pub:/keys/snapshot.pub:ro,z",
            "--volume",
            f"{state_dir}:/existing-state:ro,Z",
            "--entrypoint",
            f"{LIB}/preflight-snapshot.sh",
            self.image,
            "/candidate",
            "/keys/snapshot.pub",
            "test-service",
            "/existing-state/highest-revision",
            check=False,
        )

    def assert_valid(self, container: Container) -> None:
        status, document = self.status(container)
        assert status == 0
        assert document["state"] == "healthy"
        assert document["ldap"] == "available"
        assert document["service_id"] == "test-service"
        assert document["revision"] == 1
        assert isinstance(document["seconds_until_hard_expiry"], int)
        assert document["seconds_until_hard_expiry"] > 0

        whoami = self.whoami(container, TEST_USER_DN, "test-user-password")
        assert whoami.returncode == 0 and f"dn:{TEST_USER_DN}" in whoami.stdout

        entry = self.ldap_search(
            container,
            "-D",
            APP_DN,
            "-w",
            "test-bind-password",
            "-b",
            TEST_USER_DN,
            "-s",
            "base",
            "uid",
            "entryUUID",
            "memberOf",
            "description",
            "userPassword",
        )
        assert f"entryUUID: {TEST_USER_UUID}" in entry
        assert f"memberOf: cn=users,ou=groups,{BASE_DN}" in entry
        assert "userPassword" not in entry
        assert "description:" not in entry

        enumeration = self.ldap_search(
            container,
            "-D",
            APP_DN,
            "-w",
            "test-bind-password",
            "-b",
            BASE_DN,
            "-s",
            "sub",
            "(objectClass=*)",
            "dn",
            "uid",
            "cn",
            "description",
            "userPassword",
        )
        assert f"dn: {TEST_USER_DN}" in enumeration
        assert f"dn: cn=users,ou=groups,{BASE_DN}" in enumeration
        assert not any(
            line.startswith(("description:", "userPassword:"))
            for line in enumeration.splitlines()
        )
        config_read = self.podman.exec(
            container.name,
            "ldapsearch",
            "-LLL",
            "-x",
            "-H",
            LDAP_URI,
            "-D",
            APP_DN,
            "-w",
            "test-bind-password",
            "-b",
            "cn=config",
            "-s",
            "base",
            "olcRootPW",
            check=False,
        )
        assert config_read.returncode != 0

        modify = self.podman.exec(
            container.name,
            "ldapmodify",
            "-Q",
            "-Y",
            "EXTERNAL",
            "-H",
            LDAPI_URI,
            check=False,
            stdin=(
                f"dn: {BASE_DN}\nchangetype: modify\nreplace: description\n"
                "description: changed at runtime\n"
            ),
        )
        assert modify.returncode != 0

        anonymous = self.podman.exec(
            container.name,
            "ldapsearch",
            "-LLL",
            "-x",
            "-H",
            LDAP_URI,
            "-b",
            BASE_DN,
            "-s",
            "base",
            "dn",
            check=False,
        )
        assert anonymous.returncode != 0

        assert (
            self.podman.inspect(container.name, "{{.HostConfig.ReadonlyRootfs}}")
            == "true"
        )
        self.podman.exec(
            container.name,
            "sh",
            "-c",
            "slapd_pid=$(cat /run/openldap/slapd.pid) || exit 1; "
            'grep -F -q "Max open files            1024                 1024" '
            '"/proc/${slapd_pid}/limits" || exit 1; '
            "test ! -e /run/openldap/verified-snapshot || exit 1; "
            "test ! -e /run/openldap/verified-files || exit 1; "
            'if grep -R -F -q "nis.ldif" /run/openldap/slapd.d; then exit 1; fi',
        )


@pytest.fixture(scope="module")
def workspace(podman: Podman, store: Store, images: Images) -> RuntimeWorkspace:
    image = images.require_runtime()
    path = store.workspace / "runtime"
    path.mkdir()
    prepared = RuntimeWorkspace(podman, image, path, store.prefix)
    for name in ("admin", "private", "public", "tls"):
        (path / name).mkdir()
    prepared.image_tool(
        "minisign",
        "-G",
        "-W",
        "-p",
        "/work/public/snapshot.pub",
        "-s",
        "/work/private/snapshot.key",
    )
    prepared.image_tool(
        "minisign",
        "-G",
        "-W",
        "-p",
        "/work/public/rotated.pub",
        "-s",
        "/work/private/rotated.key",
    )
    prepared.write_directory_ldif()
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(path / "tls/cert.key"),
            "-out",
            str(path / "tls/cert.pem"),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    shutil.copy(path / "tls/cert.pem", path / "tls/ca.pem")
    (path / "admin/lf-password").write_text(
        "recovery-root-password\n", encoding="utf-8"
    )
    (path / "admin/crlf-password").write_text(
        "recovery-root-password\r\n", encoding="utf-8"
    )
    for directory in (path, path / "admin", path / "public", path / "tls"):
        directory.chmod(0o755)
    for file in (
        "admin/lf-password",
        "admin/crlf-password",
        "public/snapshot.pub",
        "tls/cert.pem",
        "tls/ca.pem",
    ):
        (path / file).chmod(0o644)
    for file in ("private/snapshot.key", "private/rotated.key"):
        (path / file).chmod(0o600)
    # This test-only key is mounted read-only into a user-namespaced container.
    (path / "tls/cert.key").chmod(0o644)

    backstop_container = f"{store.prefix}-backstop"
    podman.plan_container(backstop_container)
    wrapper = path / "podman-backstop"
    wrapper.write_text(
        "#!/usr/bin/env sh\n"
        'if [ "${1:-}" = run ]; then\n'
        "  shift\n"
        f'  exec "{podman.binary}" run --name "{backstop_container}" '
        f'--label "{OWNER_LABEL}={store.run_key}" "$@"\n'
        "fi\n"
        f'exec "{podman.binary}" "$@"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    prepared.create_snapshot("valid", 1, 30 * MINUTES, 60 * MINUTES)
    return prepared


@pytest.fixture(scope="module")
def runtime(podman: Podman, workspace: RuntimeWorkspace) -> Runtime:
    return Runtime(podman, workspace)


@pytest.fixture
def sleeper(podman: Podman, images: Images) -> Iterator[str]:
    image = images.require_runtime()
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
    yield name
    podman.run("rm", "--force", name)


def test_image_contents_match_the_production_boundary(
    podman: Podman, images: Images, sleeper: str
) -> None:
    image = images.require_runtime()
    assert int(podman.inspect_image(image, "{{.Size}}")) < MAXIMUM_IMAGE_SIZE
    host = testinfra.get_host(f"podman://{sleeper}")
    assert host.check_output("id -u") == "1001"
    assert host.check_output("id -g") == "1001"
    for path in (
        "/usr/local/share/openldap-declarative/package-versions.txt",
        "/usr/local/share/openldap-declarative/LICENSE.txt",
        "/usr/share/doc/slapd/copyright",
        "/usr/lib/ldap/back_mdb.so",
        "/usr/lib/ldap/argon2.so",
        "/usr/lib/ldap/memberof.so",
    ):
        assert host.file(path).size > 0, path
    for path in ("/ARCHITECTURE.md", "/TEMP-Notes"):
        assert not host.file(path).exists, path
    for path in ("/snapshot", "/tls", "/run/credentials"):
        directory = host.file(path)
        assert (directory.uid, directory.gid, directory.mode) == (0, 0, 0o555), path
    for path in ("/run/openldap", "/state"):
        directory = host.file(path)
        assert (directory.uid, directory.gid, directory.mode) == (1001, 1001, 0o700), (
            path
        )
    license_file = host.file("/usr/local/share/openldap-declarative/LICENSE.txt")
    assert (license_file.uid, license_file.gid, license_file.mode) == (0, 0, 0o444)
    scripts = host.check_output(f"ls {LIB}").split()
    assert scripts
    for script in scripts:
        immutable = host.file(f"{LIB}/{script}")
        assert (immutable.uid, immutable.gid, immutable.mode) == (0, 0, 0o555), script
        assert host.run(f"chmod u+w {LIB}/{script}").rc != 0, script
    assert (
        host.check_output(
            'find /usr/lib/ldap -mindepth 1 ! -name "back_mdb.*" '
            '! -name "argon2.*" ! -name "memberof.*"'
        )
        == ""
    )
    for tool in ("cc", "gcc", "make", "sudo", "vim", "ip", "ping", "ps"):
        assert not host.exists(tool), tool


def test_valid_snapshot_serves_and_stops_cleanly(
    runtime: Runtime, workspace: RuntimeWorkspace
) -> None:
    container = runtime.create("valid", "valid")
    runtime.start_healthy(container)
    runtime.assert_valid(container)
    runtime.run_backstop(container, workspace.path / "valid")

    large = workspace.copy_snapshot("valid", "valid-large")
    padding = "".join(
        f"# padding {line:06d} exceeds 2 MiB within the accepted 16 MiB bound\n"
        for line in range(60000)
    )
    workspace.modify_ldif(large, lambda content: content + padding)
    runtime.run_backstop(container, large)
    assert runtime.podman.inspect(container.name, "{{.State.Running}}") == "true"

    assert runtime.stop(container) == 0
    assert_build_artifacts_absent(
        runtime.podman, runtime.image, container.runtime_volume
    )

    key_directory = runtime.create("key-directory", "valid", key_mode="directory")
    runtime.start_healthy(key_directory)
    assert runtime.stop(key_directory) == 0


@pytest.mark.parametrize("missing", ["snapshot", "public-key"])
def test_backstop_stops_when_trust_input_disappears(
    runtime: Runtime, workspace: RuntimeWorkspace, missing: str
) -> None:
    container = runtime.create(f"backstop-missing-{missing}", "valid")
    runtime.start_healthy(container)
    runtime.run_backstop(
        container,
        workspace.path / ("absent-snapshot" if missing == "snapshot" else "valid"),
        public_key=workspace.path / "absent-key" if missing == "public-key" else None,
        expected_status=66,
    )
    assert runtime.podman.inspect(container.name, "{{.State.Running}}") == "false"


@pytest.mark.parametrize(("namespace", "valid"), NAMESPACE_CASES)
def test_runtime_namespace_verification_matches_the_public_contract(
    runtime: Runtime,
    workspace: RuntimeWorkspace,
    namespace: str,
    valid: bool,
    request: pytest.FixtureRequest,
) -> None:
    snapshot = workspace.copy_snapshot(
        "valid", f"namespace-{request.node.callspec.indices['namespace']}"
    )
    manifest = snapshot / "manifest.json"
    document = json.loads(manifest.read_text())
    document["uuid_namespace"] = namespace.lower()
    manifest.write_text(json.dumps(document), encoding="utf-8")
    workspace.sign_manifest(snapshot)
    completed = runtime.podman.run_container(
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--userns=keep-id:uid=1001,gid=1001",
        "--user",
        "1001:1001",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--tmpfs",
        "/run/openldap:rw,noexec,nosuid,nodev,size=20m,mode=1777",
        "--env",
        "LDAP_EXPECTED_SERVICE_ID=test-service",
        "--volume",
        f"{snapshot}:/snapshot:ro,Z",
        "--volume",
        f"{workspace.path}/public/snapshot.pub:/run/credentials/snapshot-public-key:ro,Z",
        "--entrypoint",
        f"{LIB}/verify-snapshot.sh",
        runtime.image,
        check=False,
    )
    assert completed.returncode == (0 if valid else 65), (
        completed.stdout + completed.stderr
    )


@pytest.mark.parametrize("password_file", ["lf-password", "crlf-password"])
def test_recovery_password_files_bind_the_root_dn(
    runtime: Runtime, password_file: str
) -> None:
    password_path = f"/run/credentials/admin/{password_file}"
    container = runtime.create(
        f"admin-{password_file}",
        "valid",
        extra_environment=f"LDAP_ADMIN_PASSWORD_FILE={password_path}",
    )
    runtime.start_healthy(container)
    whoami = runtime.whoami(container, f"cn=admin,{BASE_DN}", "recovery-root-password")
    assert whoami.returncode == 0 and f"dn:cn=admin,{BASE_DN}" in whoami.stdout
    secret = runtime.ldap_search(
        container,
        "-D",
        f"cn=admin,{BASE_DN}",
        "-w",
        "recovery-root-password",
        "-b",
        TEST_USER_DN,
        "-s",
        "base",
        "userPassword",
    )
    assert "userPassword:" in secret
    runtime.podman.run(
        "exec",
        "-i",
        container.name,
        "ldapmodify",
        "-x",
        "-H",
        LDAP_URI,
        "-D",
        f"cn=admin,{BASE_DN}",
        "-w",
        "recovery-root-password",
        stdin=f"dn: {TEST_USER_DN}\nchangetype: modify\nreplace: description\ndescription: recovery edit\n",
    )
    changed = runtime.ldap_search(
        container,
        "-D",
        f"cn=admin,{BASE_DN}",
        "-w",
        "recovery-root-password",
        "-b",
        TEST_USER_DN,
        "-s",
        "base",
        "description",
    )
    assert "description: recovery edit" in changed
    assert runtime.stop(container) == 0


def test_default_runtime_has_no_network_recovery_password(runtime: Runtime) -> None:
    container = runtime.create("no-recovery", "valid")
    runtime.start_healthy(container)
    config = runtime.podman.exec_output(
        container.name,
        "ldapsearch",
        "-LLL",
        "-Q",
        "-Y",
        "EXTERNAL",
        "-H",
        LDAPI_URI,
        "-b",
        "cn=config",
        "(objectClass=olcMdbConfig)",
        "olcRootDN",
        "olcRootPW",
        "olcAccess",
    )
    assert f"olcRootDN: cn=admin,{BASE_DN}" in config
    assert "olcRootPW:" not in config
    assert " manage" not in config
    assert (
        runtime.whoami(
            container, f"cn=admin,{BASE_DN}", "recovery-root-password"
        ).returncode
        != 0
    )
    assert runtime.stop(container) == 0


def test_shutdown_during_initialization_exits_cleanly(runtime: Runtime) -> None:
    container = runtime.create("immediate-stop", "valid")
    runtime.podman.run("start", container.name)
    wait_until_initializing(runtime.podman, container.name)
    runtime.podman.stop(container.name, seconds=15)
    assert int(runtime.podman.inspect(container.name, "{{.State.ExitCode}}")) == 0
    assert_build_artifacts_absent(
        runtime.podman, runtime.image, container.runtime_volume
    )


def test_revision_state_rejects_replay_and_conflicts(
    runtime: Runtime, workspace: RuntimeWorkspace
) -> None:
    state = runtime.state_volume("replay")
    workspace.create_snapshot("revision-2", 2, 30 * MINUTES, 60 * MINUTES)
    for test_name in ("revision-2", "revision-2-repeat"):
        container = runtime.create(test_name, "revision-2", state_volume=state)
        runtime.start_healthy(container)
        assert runtime.stop(container) == 0

    conflict = workspace.copy_snapshot("revision-2", "revision-2-conflict")
    workspace.modify_ldif(
        conflict,
        lambda content: content.replace(
            "o: Example\n", "o: Example\ndescription: conflicting content\n", 1
        ),
    )
    runtime.expect_exit(
        runtime.create(
            "revision-2-conflict", "revision-2-conflict", state_volume=state
        ),
        65,
        "was already accepted with different content",
    )
    runtime.expect_exit(
        runtime.create("replay", "valid", state_volume=state),
        65,
        "is older than accepted revision",
    )


@pytest.mark.parametrize(
    ("state_content", "terminated", "status", "message"),
    [
        pytest.param(None, True, 0, "(new)", id="new"),
        pytest.param("1 {digest}", True, 0, "(exact-replay)", id="exact"),
        pytest.param("1", True, 0, "(legacy-state-migration)", id="legacy"),
        pytest.param("1 {digest}", False, 0, "(exact-replay)", id="unterminated"),
        pytest.param("", False, 66, "must contain one revision", id="empty"),
        pytest.param(
            "2 {digest}", True, 65, "is older than accepted revision 2", id="lower"
        ),
        pytest.param(
            "not-a-revision",
            True,
            66,
            "must contain one revision",
            id="malformed",
        ),
        pytest.param(
            "1 " + "0" * 64,
            True,
            65,
            "was already accepted with different content",
            id="conflict",
        ),
        pytest.param("9" * 40, True, 66, "must contain one revision", id="overflow"),
        pytest.param(
            "9007199254740992", True, 66, "must contain one revision", id="out-of-range"
        ),
        pytest.param("0", True, 66, "must contain one revision", id="zero"),
        pytest.param("01", True, 66, "must contain one revision", id="leading-zero"),
        pytest.param(
            "9007199254740991",
            True,
            65,
            "is older than accepted revision",
            id="maximum",
        ),
        pytest.param(
            "1 {digest}\n2 {digest}",
            True,
            66,
            "must contain one revision",
            id="extra-record",
        ),
        pytest.param(
            "1\n\n", False, 66, "must contain one revision", id="extra-newline"
        ),
        pytest.param(
            "1 trailing", True, 66, "must contain one revision", id="bad-digest"
        ),
        pytest.param(
            Path("missing"),
            True,
            66,
            "not a readable regular file",
            id="dangling-symlink",
        ),
    ],
)
def test_preflight_validates_staged_revisions_without_mutating_state(
    runtime: Runtime,
    workspace: RuntimeWorkspace,
    state_content: str | Path | None,
    terminated: bool,
    status: int,
    message: str,
    request: pytest.FixtureRequest,
) -> None:
    case_name = request.node.callspec.id
    digest = sha256_file(workspace.path / "valid/manifest.json")
    state_dir = workspace.path / f"preflight-{case_name}"
    state_dir.mkdir(mode=0o755)
    runtime_dir = workspace.path / f"preflight-runtime-{case_name}"
    runtime_dir.mkdir(mode=0o700)
    state_path = state_dir / "highest-revision"
    before: str | None = None
    if isinstance(state_content, Path):
        state_path.symlink_to(state_content)
    elif state_content is not None:
        content = state_content.format(digest=digest) + ("\n" if terminated else "")
        state_path.write_text(content, encoding="utf-8")
        state_path.chmod(0o644)
        before = sha256_file(state_path)

    completed = runtime.preflight(workspace.path / "valid", state_dir, runtime_dir)
    output = completed.stdout + completed.stderr
    assert completed.returncode == status, output
    assert message in output, output
    if isinstance(state_content, Path):
        assert state_path.is_symlink() and state_path.readlink() == state_content
    elif before is None:
        assert not state_path.exists()
    else:
        assert sha256_file(state_path) == before
    assert not list(runtime_dir.iterdir())


@pytest.mark.parametrize(
    ("damage", "message"),
    [
        ("ldif", "Offline import failed"),
        ("uuid", "entryUUID"),
        ("password", "valid Argon2id"),
        (
            "membership",
            "member and memberOf attributes must describe the same relationships",
        ),
        ("none", "Preflight accepted"),
    ],
)
def test_preflight_imports_candidates_without_touching_active_runtime(
    runtime: Runtime,
    workspace: RuntimeWorkspace,
    damage: str,
    message: str,
) -> None:
    candidate = workspace.create_snapshot(
        f"candidate-{damage}", 2, 30 * MINUTES, 60 * MINUTES
    )
    if damage != "none":

        def edit(content: str) -> str:
            if damage == "ldif":
                return content + "\nnot valid LDIF\n"
            if damage == "uuid":
                return content.replace(f"entryUUID: {TEST_USER_UUID}\n", "")
            if damage == "password":
                return content.replace("{ARGON2}", "{INVALID}", 1)
            return content.replace(f"memberOf: cn=users,ou=groups,{BASE_DN}\n", "")

        workspace.modify_ldif(candidate, edit)
    active = runtime.create(f"preflight-active-{damage}", "valid")
    runtime.start_healthy(active)
    state_dir = workspace.path / f"candidate-state-{damage}"
    state_dir.mkdir(mode=0o700)
    state = state_dir / "highest-revision"
    accepted = runtime.podman.exec_output(active.name, "cat", "/state/highest-revision")
    state.write_text(accepted, encoding="utf-8")
    state_before = state.read_bytes()
    runtime_dir = workspace.path / f"candidate-runtime-{damage}"
    runtime_dir.mkdir(mode=0o700)
    for name in ("active-manifest.json", "slapd.d/config", "data/database"):
        sentinel = runtime_dir / name
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        sentinel.write_text("protected active runtime fixture\n", encoding="utf-8")
    before = {
        p.relative_to(runtime_dir): p.read_bytes()
        for p in runtime_dir.rglob("*")
        if p.is_file()
    }
    for _ in range(2):
        result = runtime.preflight(candidate, state_dir, runtime_dir)
        assert result.returncode == (0 if damage == "none" else 65), (
            result.stdout + result.stderr
        )
        assert message.lower() in (result.stdout + result.stderr).lower()
        assert state.read_bytes() == state_before
        assert {
            p.relative_to(runtime_dir): p.read_bytes()
            for p in runtime_dir.rglob("*")
            if p.is_file()
        } == before
        assert not list(runtime_dir.glob("preflight.*"))
        runtime.assert_valid(active)
        assert (
            runtime.podman.exec_output(active.name, "cat", "/state/highest-revision")
            == accepted
        )
    assert runtime.stop(active) == 0


@dataclass(frozen=True)
class Rejection:
    prepare: Callable[[RuntimeWorkspace], str]
    status: int
    message: str = ""
    service_id: str = "test-service"
    transport: str = "ldap"
    key_mode: str = "file"
    extra_environment: str = "LDAP_TLS_CA_FILE=/tls/ca.pem"


def _tampered_data(workspace: RuntimeWorkspace) -> str:
    snapshot = workspace.copy_snapshot("valid", "tampered")
    with (snapshot / "directory.ldif").open("a", encoding="utf-8") as stream:
        stream.write("# tampered\n")
    return "tampered"


def _tampered_manifest(workspace: RuntimeWorkspace) -> str:
    snapshot = workspace.copy_snapshot("valid", "tampered-manifest")
    manifest = snapshot / "manifest.json"
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["revision"] = 99
    manifest.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    manifest.chmod(0o644)
    return "tampered-manifest"


def _unsigned(workspace: RuntimeWorkspace) -> str:
    snapshot = workspace.copy_snapshot("valid", "unsigned")
    (snapshot / "manifest.json.minisig").unlink()
    return "unsigned"


def _expired(workspace: RuntimeWorkspace) -> str:
    workspace.create_snapshot(
        "expired", 3, -2 * MINUTES, -1 * MINUTES, generated=-3 * MINUTES
    )
    return "expired"


def _missing_uuid(workspace: RuntimeWorkspace) -> str:
    snapshot = workspace.create_snapshot("missing-uuid", 4, 30 * MINUTES, 60 * MINUTES)
    workspace.modify_ldif(
        snapshot, lambda content: content.replace(f"entryUUID: {TEST_USER_UUID}\n", "")
    )
    return "missing-uuid"


def _weak_password(workspace: RuntimeWorkspace) -> str:
    snapshot = workspace.create_snapshot("weak-password", 5, 30 * MINUTES, 60 * MINUTES)

    def weaken(content: str) -> str:
        lines = content.splitlines(keepends=True)
        index = next(
            i for i, line in enumerate(lines) if line.startswith("userPassword: ")
        )
        lines[index] = "userPassword: {CLEARTEXT}weak\n"
        return "".join(lines)

    workspace.modify_ldif(snapshot, weaken)
    return "weak-password"


def _inconsistent_membership(workspace: RuntimeWorkspace) -> str:
    snapshot = workspace.create_snapshot(
        "inconsistent-membership", 6, 30 * MINUTES, 60 * MINUTES
    )
    workspace.modify_ldif(
        snapshot,
        lambda content: content.replace(
            f"memberOf: cn=users,ou=groups,{BASE_DN}\n", ""
        ),
    )
    return "inconsistent-membership"


def _too_many_files(workspace: RuntimeWorkspace) -> str:
    snapshot = workspace.copy_snapshot("valid", "too-many-files")
    manifest = snapshot / "manifest.json"
    document = json.loads(manifest.read_text(encoding="utf-8"))
    digest = sha256_file(snapshot / "directory.ldif")
    document["files"] = [
        {"path": f"directory-{index}.ldif", "sha256": digest} for index in range(33)
    ]
    manifest.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    manifest.chmod(0o644)
    workspace.sign_manifest(snapshot)
    return "too-many-files"


REJECTIONS = {
    "tampered-data": Rejection(
        _tampered_data, 65, "Snapshot data digest does not match the manifest"
    ),
    "tampered-manifest": Rejection(
        _tampered_manifest, 65, "Snapshot manifest signature verification failed"
    ),
    "unsigned": Rejection(
        _unsigned,
        66,
        "Required input is not a regular file: /snapshot/manifest.json.minisig",
    ),
    "wrong-key": Rejection(
        lambda _: "valid",
        65,
        "Snapshot manifest signature verification failed",
        key_mode="rotated",
    ),
    "wrong-service": Rejection(
        lambda _: "valid",
        65,
        "Snapshot service ID does not match LDAP_EXPECTED_SERVICE_ID",
        service_id="another-service",
    ),
    "expired": Rejection(_expired, 78, "Snapshot has expired"),
    "missing-uuid": Rejection(
        _missing_uuid, 65, "Every directory entryUUID must be a lowercase UUIDv5 value"
    ),
    "weak-password": Rejection(
        _weak_password, 65, "Every userPassword must use a valid Argon2id verifier"
    ),
    "inconsistent-membership": Rejection(
        _inconsistent_membership,
        65,
        "member and memberOf attributes must describe the same relationships",
    ),
    "too-many-files": Rejection(
        _too_many_files, 65, "Snapshot manifest does not match format version 1"
    ),
    "tls-missing-ca": Rejection(
        lambda _: "valid",
        66,
        transport="ldaps",
        extra_environment="LDAP_TLS_CA_FILE=/tls/missing.pem",
    ),
    "same-port": Rejection(
        lambda _: "valid",
        64,
        "LDAP_PORT and LDAP_LDAPS_PORT must differ when LDAP_TRANSPORT is both",
        transport="both",
        extra_environment="LDAP_LDAPS_PORT=1389",
    ),
}


@pytest.mark.parametrize("case", list(REJECTIONS.values()), ids=list(REJECTIONS))
def test_rejected_input_never_opens_a_listener(
    runtime: Runtime,
    workspace: RuntimeWorkspace,
    case: Rejection,
    request: pytest.FixtureRequest,
) -> None:
    snapshot_name = case.prepare(workspace)
    container = runtime.create(
        request.node.callspec.id,
        snapshot_name,
        service_id=case.service_id,
        transport=case.transport,
        key_mode=case.key_mode,
        extra_environment=case.extra_environment,
    )
    runtime.expect_exit(container, case.status, case.message)


def test_hard_expiry_stops_slapd_with_status_78(
    runtime: Runtime, workspace: RuntimeWorkspace
) -> None:
    workspace.create_snapshot("short-lived", 7, 10 * SECONDS, 30 * SECONDS)
    container = runtime.create("expiry", "short-lived")
    runtime.expect_exit(container, 78, "active directory snapshot has expired")


def test_soft_deadline_reports_without_stopping(
    runtime: Runtime, workspace: RuntimeWorkspace
) -> None:
    workspace.create_snapshot("soft-deadline", 8, 10 * SECONDS, 2 * MINUTES)
    container = runtime.create("soft-deadline", "soft-deadline")
    runtime.start_healthy(container)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        status, document = runtime.status(container)
        assert status != 2, document
        if status == 1:
            assert document["state"] == "soft-expired"
            assert document["ldap"] == "available"
            assert document["revision"] == 8
            assert isinstance(document["seconds_until_soft_expiry"], int)
            assert document["seconds_until_soft_expiry"] <= 0
            assert isinstance(document["seconds_until_hard_expiry"], int)
            assert document["seconds_until_hard_expiry"] > 0
            runtime.podman.exec(container.name, f"{LIB}/healthcheck.sh")
            assert runtime.stop(container) == 0
            return
        time.sleep(POLL_INTERVAL)
    pytest.fail("status never reported the soft deadline")


def test_watchdog_failure_stops_slapd_with_status_75(runtime: Runtime) -> None:
    container = runtime.create("watchdog-failure", "valid")
    runtime.start_healthy(container)
    runtime.podman.exec(
        container.name, "sh", "-c", 'kill "$(cat /run/openldap/watchdog.pid)"'
    )
    assert runtime.podman.wait(container.name) == 75
    assert "snapshot expiry watchdog failed" in runtime.podman.logs(container.name)


def test_ldaps_requires_tls_1_2_and_validates_the_chain(runtime: Runtime) -> None:
    container = runtime.create("tls", "valid", transport="ldaps")
    runtime.start_healthy(container)
    verified = runtime.podman.exec_output(
        container.name,
        "sh",
        "-c",
        "openssl s_client -connect 127.0.0.1:1636 -servername localhost "
        "-CAfile /tls/ca.pem "
        "-verify_return_error -verify_hostname localhost -tls1_2 </dev/null 2>&1",
    )
    assert "Verify return code: 0 (ok)" in verified
    legacy = runtime.podman.exec(
        container.name,
        "sh",
        "-c",
        "openssl s_client -connect 127.0.0.1:1636 -servername localhost "
        "-CAfile /tls/ca.pem "
        "-verify_return_error -tls1_1 </dev/null >/dev/null 2>&1",
        check=False,
    )
    assert legacy.returncode != 0
    assert runtime.stop(container) == 0
