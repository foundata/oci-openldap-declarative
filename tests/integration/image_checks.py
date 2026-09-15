"""Inspect the pristine image filesystem, including root-only directories."""

from tests.integration.harness import Podman


def assert_image_package_data(podman: Podman, image: str) -> None:
    result = podman.run_container(
        "--rm",
        "--user=0:0",
        "--network=none",
        "--read-only",
        "--read-only-tmpfs=false",
        "--cap-drop=all",
        "--cap-add=DAC_OVERRIDE",
        "--security-opt=no-new-privileges",
        "--entrypoint=sh",
        image,
        "-ec",
        """
for path in /usr/share/locale /usr/share/ieee-data /var/cache/apt \\
  /usr/lib/python3/dist-packages/ansible/galaxy/data \\
  /usr/lib/python3/dist-packages/ansible_test /usr/bin/ansible-test; do
  test ! -e "$path"
  test ! -L "$path"
done
test -z "$(find /usr -xdev -type d -name __pycache__ -print -quit)"
test -z "$(find /var/log /var/cache/debconf -mindepth 1 -print -quit)"
LC_ALL=C.UTF-8 locale charmap
""",
    )
    assert result.stdout.strip() == "UTF-8"


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
