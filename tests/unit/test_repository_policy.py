"""Project-specific build-context and deployment-policy regression tests."""

from __future__ import annotations

import json
import shlex
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = (
    "*",
    "!Containerfile",
    "!Containerfile.generator",
    "!LICENSES",
    "!LICENSES/**",
    "!generator",
    "!generator/**",
    "!scripts",
    "!scripts/**",
    "!schema",
    "!schema/application-user.ldif",
)


def included_by_project_allowlist(path: str) -> bool:
    return path in {
        "Containerfile",
        "Containerfile.generator",
        "schema/application-user.ldif",
    } or path.startswith(("LICENSES/", "generator/", "scripts/"))


def copy_sources(containerfile: Path) -> set[str]:
    sources: set[str] = set()
    for line in containerfile.read_text(encoding="utf-8").splitlines():
        if not line.startswith("COPY "):
            continue
        fields = shlex.split(line)
        if any(field.startswith("--from=") for field in fields):
            continue
        positional = [field for field in fields[1:] if not field.startswith("--")]
        sources.update(positional[:-1])
    return sources


def test_containerignore_is_the_reviewed_default_deny_allowlist() -> None:
    lines = tuple(
        line.strip()
        for line in (ROOT / ".containerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    assert lines == ALLOWLIST


def test_required_copy_sources_remain_in_both_effective_contexts() -> None:
    for name in ("Containerfile", "Containerfile.generator"):
        sources = copy_sources(ROOT / name)
        assert sources
        assert all(included_by_project_allowlist(path) for path in sources)
        assert all((ROOT / path).is_file() for path in sources)


def test_dangerous_tracked_and_untracked_inputs_are_excluded() -> None:
    dangerous_inputs = (
        ".git/config",
        "TEMP-Notes",
        "PROMPT-remediate-open-findings.md",
        "private/snapshot.key",
        "credentials.yaml",
        "snapshots/example/manifest.json",
        "release-evidence/runtime/sbom.spdx.json",
        "test-runs/retained/credentials.yaml",
        "tests/fixtures/plaintext-password",
        "untracked-secret.env",
        "schema/private-directory.ldif",
    )
    assert not any(included_by_project_allowlist(path) for path in dangerous_inputs)


def test_deployment_policy_rejects_by_default_and_scopes_both_repositories() -> None:
    path = ROOT / "examples/policy/containers-policy.json"
    with path.open(encoding="utf-8") as stream:
        policy = json.load(stream)
    assert policy["default"] == [{"type": "reject"}]
    repositories = policy["transports"]["docker"]
    assert set(repositories) == {
        "quay.io/foundata/openldap-declarative",
        "quay.io/foundata/openldap-declarative-generator",
    }
    for requirement in repositories.values():
        assert requirement == [
            {
                "type": "sigstoreSigned",
                "keyPath": "/etc/foundata/container-trust/openldap-release.pub",
                "signedIdentity": {"type": "matchRepository"},
            }
        ]


def test_release_tags_publish_exact_versions_and_latest() -> None:
    with (ROOT / "conclear.toml").open("rb") as stream:
        config = tomllib.load(stream)
    assert {image["id"] for image in config["images"]} == {"runtime", "generator"}
    for image in config["images"]:
        assert image["release"]["version_tags"] == ["{version}"]
        assert image["release"]["moving_tags"] == ["latest"]


def test_release_version_is_checked_against_changelog() -> None:
    with (ROOT / "conclear.toml").open("rb") as stream:
        config = tomllib.load(stream)
    assert config["project"]["version_sources"] == [
        {"kind": "changelog", "path": "CHANGELOG.md"}
    ]
    assert (ROOT / "CHANGELOG.md").is_file()


def test_qualification_hooks_allow_bounded_emulation_waits() -> None:
    with (ROOT / "conclear.toml").open("rb") as stream:
        config = tomllib.load(stream)
    hooks = [hook for image in config["images"] for hook in image["hooks"]]
    assert len(hooks) == 3
    for hook in hooks:
        assert "--ldap-readiness-timeout=120" in hook["command"]
        assert hook["timeout_seconds"] == 3600
        assert hook.get("required", True)


def test_public_image_metadata_uses_project_page() -> None:
    project_url = "https://foundata.com/en/projects/oci-openldap-declarative/"
    for name in ("Containerfile", "Containerfile.generator"):
        labels = {
            key: value
            for line in (ROOT / name).read_text().splitlines()
            if line.startswith("LABEL ")
            for key, value in (shlex.split(line)[1].split("=", 1),)
        }
        assert labels["org.opencontainers.image.url"] == project_url
        assert labels["org.opencontainers.image.documentation"] == project_url + "#doc"
    with (ROOT / "REUSE.toml").open("rb") as stream:
        reuse = tomllib.load(stream)
    assert reuse["SPDX-PackageDownloadLocation"] == project_url + "#releases"
