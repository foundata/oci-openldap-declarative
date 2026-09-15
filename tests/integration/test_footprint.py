"""Opt-in cgroup measurements for representative directory and credential workloads."""

from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
import yaml
from argon2 import PasswordHasher

from generator.initialize import initialize
from tests.integration.conftest import Images
from tests.integration.harness import Podman, Store, iso_timestamp, utc_now
from tests.integration.test_generator import (
    APP_BASE,
    Generator,
    RuntimeService,
    prepare_generator,
)

pytestmark = [pytest.mark.integration, pytest.mark.benchmark]
PASSWORD = "TEST-ONLY-footprint-password"
LOAD_CLIENT = """
import concurrent.futures, json, sys, time
import ldap
settings = json.load(sys.stdin)
def worker(index):
    for iteration in range(10):
        user = (index * 10 + iteration) % settings['users']
        dn = f"uid=user-{user:05d},ou=people,{settings['base']}"
        connection = ldap.initialize('ldap://127.0.0.1:1389')
        connection.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        try:
            connection.simple_bind_s(dn, settings['password'])
            assert connection.search_s(dn, ldap.SCOPE_BASE, '(objectClass=*)', ['uid'])
        finally:
            connection.unbind_s()
started = time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=settings['clients']) as pool:
    list(pool.map(worker, range(settings['clients'])))
print(json.dumps({'bind_search_pairs': settings['clients'] * 10,
                  'seconds': time.monotonic() - started}))
"""


class VaultText(str):
    pass


class DefinitionDumper(yaml.SafeDumper):
    pass


DefinitionDumper.add_representer(
    VaultText,
    lambda dumper, value: dumper.represent_scalar("!vault", str(value), style="|"),
)


@pytest.fixture(scope="module")
def benchmark_generator(podman: Podman, images: Images, store: Store) -> Generator:
    return prepare_generator(
        podman, images.require_generator(), store.workspace / "footprint"
    )


def definition(
    generator: Generator,
    name: str,
    users: int,
    memory_kib: int,
    credentials: str = "hash",
) -> Path:
    path = generator.inputs / f"{name}.yaml"
    initialize(path, directory_id="footprint", base_dn=APP_BASE)
    document = yaml.safe_load(path.read_text())
    verifier = "{ARGON2}" + PasswordHasher(
        memory_cost=memory_kib, time_cost=2, parallelism=1
    ).hash(PASSWORD)
    value = (
        VaultText(generator.encrypt(verifier)) if credentials == "vault" else verifier
    )
    document["users"] = [
        {
            "entry_uuid": str(uuid.uuid4()),
            "username": f"user-{number:05d}",
            "last_name": "Footprint",
            "active": True,
            "password" if credentials == "plaintext" else "password_hash": PASSWORD
            if credentials == "plaintext"
            else value,
        }
        for number in range(users)
    ]
    document["groups"][0]["members"] = [
        user["entry_uuid"] for user in document["users"]
    ]
    document["bind_accounts"][0].pop("password_hash_file")
    document["bind_accounts"][0]["password_hash"] = verifier
    path.write_text(yaml.dump(document, Dumper=DefinitionDumper, sort_keys=False))
    assert path.stat().st_size <= 1024 * 1024
    return path


class Observation:
    """Read the owned container's cgroup from the host, without in-container sampling."""

    def __init__(
        self, podman: Podman, name: str, cgroup_root: Path = Path("/sys/fs/cgroup")
    ) -> None:
        path = podman.inspect(name, "{{.State.CgroupPath}}")
        assert path.startswith("/") and path != "/" and ".." not in Path(path).parts, (
            "container cgroup v2 path is unavailable"
        )
        self.path = cgroup_root / path.lstrip("/")
        self.max_open_files: int | None = None

    def sample(self) -> dict[str, Any]:
        counters: dict[str, Any] = {
            name: int((self.path / name).read_text())
            for name in ("memory.current", "memory.peak", "pids.current", "pids.peak")
        }
        for filename in ("memory.stat", "memory.events"):
            counters[filename] = {
                line.split()[0]: int(line.split()[1])
                for line in (self.path / filename).read_text().splitlines()
            }
        try:
            pids = {
                pid
                for path in self.path.glob("**/cgroup.procs")
                for pid in path.read_text().split()
            }
            descriptors = sum(
                len(list((Path("/proc") / pid / "fd").iterdir())) for pid in pids
            )
            self.max_open_files = max(self.max_open_files or 0, descriptors)
        except (FileNotFoundError, PermissionError):
            pass
        return {**counters, "sampled_open_files_max": self.max_open_files}


def record(
    store: Store, podman: Podman, image: str, name: str, data: dict[str, Any]
) -> None:
    entry = {
        "timestamp": iso_timestamp(utc_now()),
        "name": name,
        "image": podman.inspect_image(image, "{{.Id}}"),
        "architecture": podman.inspect_image(image, "{{.Architecture}}"),
        "memory_limit_bytes": 256 * 1024 * 1024,
        **data,
    }
    with (store.base / "footprints.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")


@pytest.mark.parametrize("repeat", [1, 2])
@pytest.mark.parametrize(
    ("profile", "users", "memory_kib", "clients"),
    [
        ("small", 2, 19456, 4),
        ("directory", 2000, 19456, 4),
        ("strong-hash", 2000, 65536, 2),
    ],
)
def test_runtime_footprint(
    benchmark_generator: Generator,
    podman: Podman,
    images: Images,
    store: Store,
    profile: str,
    users: int,
    memory_kib: int,
    clients: int,
    repeat: int,
) -> None:
    generator = benchmark_generator
    name = f"runtime-{profile}-{repeat}"
    path = definition(generator, name, users, memory_kib)
    result = generator.run(name, source=path.name)
    assert result.returncode == 0, result.stderr
    image = images.require_runtime()
    service = RuntimeService(podman, image, generator, f"{store.prefix}-{name}")
    started = time.monotonic()
    service.start(generator.output / name, "--cpus=1")
    observation = Observation(podman, service.name)
    time.sleep(2)
    data: dict[str, Any] = {
        "users": users,
        "argon2_memory_kib": memory_kib,
        "clients": clients,
        "nofile": 1024,
        "pids_limit": 128,
        "startup_seconds": time.monotonic() - started,
        "before_load": observation.sample(),
    }
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                podman.exec,
                service.name,
                "python3",
                "-c",
                LOAD_CLIENT,
                check=False,
                stdin=json.dumps(
                    {
                        "users": users,
                        "clients": clients,
                        "base": APP_BASE,
                        "password": PASSWORD,
                    }
                ),
            )
            while not future.done():
                observation.sample()
                time.sleep(0.05)
            result = future.result()
        data["after_load"] = observation.sample()
        data["client_status"] = result.returncode
        if result.returncode == 0:
            data["load"] = json.loads(result.stdout)
        record(store, podman, image, name, data)
        assert result.returncode == 0, result.stderr
        assert data["after_load"]["memory.events"]["oom"] == 0
    finally:
        podman.stop(service.name)
    assert podman.inspect(service.name, "{{.State.ExitCode}}") == "0"


@pytest.mark.parametrize("repeat", [1, 2])
@pytest.mark.parametrize(
    ("credentials", "users"), [("hash", 2000), ("plaintext", 100), ("vault", 64)]
)
def test_generator_footprint(
    benchmark_generator: Generator,
    podman: Podman,
    store: Store,
    credentials: str,
    users: int,
    repeat: int,
) -> None:
    generator = benchmark_generator
    name = f"generator-{credentials}-{repeat}"
    path = definition(generator, name, users, 19456, credentials)
    container = f"{store.prefix}-{name}"
    podman.plan_container(container)
    started = time.monotonic()
    podman.run(
        "run",
        "-d",
        "--name",
        container,
        "--userns=keep-id:uid=1001,gid=1001",
        "--user=1001:1001",
        "--network=none",
        "--read-only",
        "--read-only-tmpfs=false",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--memory=256m",
        "--pids-limit=64",
        "--ulimit=nofile=512:512",
        "--cpus=1",
        "-v",
        f"{generator.inputs}:/input:ro,Z",
        "-v",
        f"{generator.credentials}:/run/credentials:ro,Z",
        "-v",
        f"{generator.output}:/output:rw,Z",
        "--entrypoint=sh",
        generator.image,
        "-ec",
        'python3 -m generator.generate "$@"\nexec sleep 300',
        "generate",
        "--directory",
        f"/input/{path.name}",
        "--signing-key",
        "/run/credentials/snapshot.key",
        "--output",
        f"/output/{name}",
        *(
            ["--vault", "directory@/run/credentials/vault-password"]
            if credentials == "vault"
            else []
        ),
    )
    observation = Observation(podman, container)
    # The snapshot is published only after signing; the wrapper preserves its cgroup.
    try:
        while not (generator.output / name).exists():
            assert time.monotonic() - started < 180, "generator benchmark timed out"
            assert podman.state(container) == "running", podman.logs(container)
            observation.sample()
            time.sleep(0.1)
        data = observation.sample()
        record(
            store,
            podman,
            generator.image,
            name,
            {
                "users": users,
                "credentials": credentials,
                "nofile": 512,
                "pids_limit": 64,
                "generation_seconds": time.monotonic() - started,
                "footprint": data,
            },
        )
        assert data["memory.events"]["oom"] == 0
        assert (generator.output / name / "manifest.json.minisig").is_file()
    finally:
        podman.stop(container)
