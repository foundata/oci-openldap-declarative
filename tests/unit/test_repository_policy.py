"""Project-specific build-context and deployment-policy regression tests."""

from __future__ import annotations

import json
import shlex
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
)


def included_by_project_allowlist(path: str) -> bool:
    return path in {"Containerfile", "Containerfile.generator"} or path.startswith(
        ("LICENSES/", "generator/", "scripts/")
    )


def copy_sources(containerfile: Path) -> set[str]:
    sources: set[str] = set()
    for line in containerfile.read_text(encoding="utf-8").splitlines():
        if not line.startswith("COPY "):
            continue
        fields = shlex.split(line)
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
