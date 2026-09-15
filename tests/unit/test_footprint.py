"""Resource reports retain cgroup totals, including file cache."""

from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.integration.harness import Podman
from tests.integration.test_footprint import Observation


def test_footprint_records_kernel_counters(tmp_path: Path) -> None:
    cgroup = tmp_path / "owned"
    cgroup.mkdir()
    for name, value in {
        "memory.current": "4096",
        "memory.peak": "8192",
        "pids.current": "2",
        "pids.peak": "5",
        "memory.stat": "anon 1024\nfile 2048\nkernel 1024\n",
        "memory.events": "oom 0\noom_kill 0\n",
        "cgroup.procs": "",
    }.items():
        (cgroup / name).write_text(value)
    podman = Mock(spec=Podman)
    podman.inspect.return_value = "/owned"
    result = Observation(podman, "owned", tmp_path).sample()
    assert result["memory.current"] == 4096
    assert result["memory.peak"] == 8192
    assert result["memory.stat"]["file"] == 2048
    assert result["pids.peak"] == 5
    assert result["memory.events"]["oom"] == 0
    assert result["sampled_open_files_max"] == 0


@pytest.mark.parametrize("path", ["", "/", "relative", "/../outside"])
def test_footprint_requires_a_container_cgroup(tmp_path: Path, path: str) -> None:
    podman = Mock(spec=Podman)
    podman.inspect.return_value = path
    with pytest.raises(AssertionError, match="cgroup"):
        Observation(podman, "owned", tmp_path)
