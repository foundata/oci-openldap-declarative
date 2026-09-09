"""Prove cleanup isolation between two disposable stores, never the host store."""

from __future__ import annotations

import pytest

from tests.integration.conftest import Images
from tests.integration.harness import Podman, Store

pytestmark = pytest.mark.integration


def test_cleanup_preserves_another_stores_running_sentinel(
    podman: Podman, store: Store, images: Images
) -> None:
    image = images.require_runtime()
    sentinel = f"{store.prefix}-sentinel"
    volume = f"{sentinel}-data"
    podman.plan_container(sentinel)
    podman.create_volume(volume)
    podman.run(
        "run",
        "--detach",
        "--name",
        sentinel,
        "--network",
        "none",
        "--user",
        "0:0",
        "--volume",
        f"{volume}:/sentinel",
        "--entrypoint",
        "sleep",
        image,
        "600",
    )
    podman.exec(sentinel, "sh", "-c", "printf '%s' sentinel-data > /sentinel/marker")
    pid = podman.inspect(sentinel, "{{.State.Pid}}")
    alive = store.tmpdir / "alive"
    alive_before = (alive.stat().st_ino, alive.stat().st_mtime_ns, alive.read_bytes())
    archive = store.workspace / "sentinel-image.tar"
    store.record("image-archive", str(archive))
    podman.run("save", "--format", "oci-archive", "--output", str(archive), image)

    disposable = Store(store.base, f"{store.suite}-cleanup-probe")
    disposable.create()
    other = Podman(disposable)
    try:
        disposable.record("imported-image", image)
        other.run("load", "--input", str(archive))
        other_name = f"{disposable.prefix}-sleep"
        other.plan_container(other_name)
        other.create_volume(f"{disposable.prefix}-data")
        other.run(
            "run",
            "--detach",
            "--name",
            other_name,
            "--network",
            "none",
            "--entrypoint",
            "sleep",
            image,
            "600",
        )
    finally:
        disposable.finish(other.binary)

    assert not disposable.root.exists()
    assert not disposable.runroot.exists()
    assert not disposable.tmpdir.exists()
    assert podman.inspect(sentinel, "{{.State.Running}}") == "true"
    assert podman.inspect(sentinel, "{{.State.Pid}}") == pid
    assert podman.exec_output(sentinel, "cat", "/sentinel/marker") == "sentinel-data"
    assert (
        alive.stat().st_ino,
        alive.stat().st_mtime_ns,
        alive.read_bytes(),
    ) == alive_before
    podman.run("rm", "--force", sentinel)
    podman.run("volume", "rm", volume)
    archive.unlink()
