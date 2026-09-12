"""Inspect the pristine image filesystem, including root-only directories."""

from tests.integration.harness import Podman


def assert_image_privileges(podman: Podman, image: str, writable: set[str]) -> None:
    def find(*predicate: str) -> set[str]:
        result = podman.run_container(
            "--rm",
            "--user=0:0",
            "--network=none",
            "--read-only",
            "--read-only-tmpfs=false",
            "--cap-drop=all",
            "--cap-add=DAC_OVERRIDE",
            "--security-opt=no-new-privileges",
            "--entrypoint=find",
            image,
            "/",
            "-xdev",
            "(",
            "-path",
            "/proc",
            "-o",
            "-path",
            "/sys",
            "-o",
            "-path",
            "/dev",
            ")",
            "-prune",
            "-o",
            *predicate,
            "-print",
        )
        return set(result.stdout.splitlines())

    setid = find("-type", "f", "-perm", "/6000")
    owned = find(
        "(",
        "-uid",
        "1001",
        "-o",
        "-gid",
        "1001",
        "-o",
        "-nouser",
        "-o",
        "-nogroup",
        ")",
    )
    unexpected_ownership = owned - writable
    assert not setid and not unexpected_ownership, (
        f"set-ID files: {sorted(setid)}; "
        f"unexpected ownership: {sorted(unexpected_ownership)}"
    )
