"""Session fixtures: isolated store, image inputs and the Testinfra host."""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.integration.harness import Podman, Store

PROJECT = Path(__file__).resolve().parents[2]
SUITE_NAMES = {
    "conclear": "runtime-integration",
    "conclear-runtime": "generator-integration",
    "conclear-generator": "generator-integration",
    "developer-build": "developer-build",
}


@dataclass(frozen=True)
class Images:
    mode: str
    runtime: str | None
    generator: str | None

    def require_runtime(self) -> str:
        if self.runtime is None:
            pytest.skip(f"the runtime image is not an input of mode {self.mode}")
        return self.runtime

    def require_generator(self) -> str:
        if self.generator is None:
            pytest.skip(f"the generator image is not an input of mode {self.mode}")
        return self.generator


@pytest.fixture(scope="session")
def mode(request: pytest.FixtureRequest) -> str:
    selected = request.config.getoption("--mode")
    if selected is None:
        pytest.fail(
            "select --mode conclear, conclear-generator, conclear-runtime "
            "or developer-build"
        )
    return str(selected)


@pytest.fixture(scope="session")
def input_manifest(mode: str) -> Path | None:
    if mode == "developer-build":
        return None
    manifest = os.environ.get("CC_TEST_INPUT_MANIFEST", "")
    path = Path(manifest)
    if not manifest or not path.is_file() or path.is_symlink():
        pytest.fail("ConClear modes require CC_TEST_INPUT_MANIFEST")
    return path


@pytest.fixture(scope="session")
def store(
    request: pytest.FixtureRequest,
    mode: str,
    input_manifest: Path | None,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Store]:
    if input_manifest is not None:
        base = input_manifest.parent
    else:
        run_dir = request.config.getoption("--run-dir")
        if run_dir is None:
            base = tmp_path_factory.mktemp("openldap")
        else:
            base = Path(str(run_dir))
            if not base.is_dir() or base.is_symlink():
                pytest.fail("--run-dir must name an existing directory")
    isolated = Store(base.resolve(), SUITE_NAMES[mode])
    isolated.create()
    previous = os.environ.get("CONTAINERS_STORAGE_CONF")
    os.environ["CONTAINERS_STORAGE_CONF"] = str(isolated.storage_conf)
    yield isolated
    if previous is None:
        del os.environ["CONTAINERS_STORAGE_CONF"]
    else:
        os.environ["CONTAINERS_STORAGE_CONF"] = previous
    if os.environ.get("KEEP_TEST_RESOURCES", "false") == "true":
        reporter = request.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(f"Retained resource manifest: {isolated.manifest}")
            reporter.write_line(f"Inspect with: {isolated.inspect_command()}")
        return
    isolated.finish(Podman(isolated).binary)


@pytest.fixture(scope="session")
def podman(store: Store) -> Podman:
    return Podman(store)


@pytest.fixture(scope="session")
def images(
    mode: str, podman: Podman, store: Store, input_manifest: Path | None
) -> Images:
    runtime_name = f"localhost/{store.prefix}:runtime"
    generator_name = f"localhost/{store.prefix}:generator"
    if mode == "developer-build":
        podman.build_image(runtime_name, PROJECT)
        podman.build_image(generator_name, PROJECT, PROJECT / "Containerfile.generator")
        return Images(mode, runtime_name, generator_name)
    assert input_manifest is not None
    if mode == "conclear":
        podman.import_image("primary", "runtime", runtime_name, input_manifest)
        return Images(mode, runtime_name, None)
    if mode == "conclear-runtime":
        podman.import_image("primary", "runtime", runtime_name, input_manifest)
        podman.import_image("dependency", "generator", generator_name, input_manifest)
        return Images(mode, runtime_name, generator_name)
    podman.import_image("primary", "generator", generator_name, input_manifest)
    return Images(mode, None, generator_name)
