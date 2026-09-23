"""Route README podman run commands through the existing isolated test harness."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from tests.integration.harness import Podman, Store


def main() -> int:
    arguments = sys.argv[1:]
    if not arguments or arguments[0] != "run":
        raise SystemExit("README test wrapper only accepts podman run")
    os.environ["HOME"] = os.environ["README_ORIGINAL_HOME"]
    podman = Podman(
        Store(Path(os.environ["README_RUN_DIR"]), os.environ["README_SUITE"])
    )
    result = podman.run_container(
        *arguments[1:],
        check=False,
        stdin=sys.stdin.read() if "-i" in arguments else None,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
