"""JSON Schema and runtime-semantic snapshot manifest contract tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from tests.validate_snapshot_manifest import validate_manifest

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schema/snapshot-manifest-v1.schema.json"
VALID_PATH = ROOT / "tests/fixtures/snapshot-manifest-valid.json"


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def validator() -> Draft202012Validator:
    schema = load_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_representative_manifest_matches_meta_validated_schema() -> None:
    validator().validate(load_json(VALID_PATH))
    validate_manifest(SCHEMA_PATH, VALID_PATH)


@pytest.mark.parametrize(
    "missing_key",
    [
        "format_version",
        "service_id",
        "base_dn",
        "revision",
        "generated_at",
        "soft_expires_at",
        "expires_at",
        "uuid_namespace",
        "files",
    ],
)
def test_required_manifest_keys_are_enforced(missing_key: str) -> None:
    manifest = load_json(VALID_PATH)
    del manifest[missing_key]
    with pytest.raises(ValidationError):
        validator().validate(manifest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("service_id", "Wrong Service"),
        ("generated_at", "not-a-timestamp"),
        ("soft_expires_at", "2030-01-01"),
        ("expires_at", "tomorrow"),
    ],
)
def test_manifest_identity_and_timestamps_are_strict(field: str, value: str) -> None:
    manifest = load_json(VALID_PATH)
    manifest[field] = value
    with pytest.raises(ValidationError):
        validator().validate(manifest)


@pytest.mark.parametrize(
    "files",
    [
        {"directory.ldif": "0" * 64},
        [{"path": "directory.ldif", "sha256": "not-a-digest"}],
        [
            {"path": "directory.ldif", "sha256": "0" * 64},
            {"path": "directory.ldif", "sha256": "0" * 64},
        ],
    ],
)
def test_manifest_files_shape_digest_and_uniqueness_are_enforced(files: object) -> None:
    manifest = load_json(VALID_PATH)
    manifest["files"] = files
    with pytest.raises(ValidationError):
        validator().validate(manifest)


def test_additional_properties_are_rejected() -> None:
    manifest = load_json(VALID_PATH)
    manifest["unsigned_override"] = True
    with pytest.raises(ValidationError):
        validator().validate(manifest)


def test_semantic_validator_rejects_duplicate_paths_with_different_digests(
    tmp_path: Path,
) -> None:
    manifest = load_json(VALID_PATH)
    duplicate = copy.deepcopy(manifest["files"][0])
    duplicate["sha256"] = "1" * 64
    manifest["files"].append(duplicate)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="paths must be unique"):
        validate_manifest(SCHEMA_PATH, path)


def test_semantic_validator_rejects_unordered_deadlines(tmp_path: Path) -> None:
    manifest = load_json(VALID_PATH)
    manifest["soft_expires_at"] = manifest["expires_at"]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="deadlines are not ordered"):
        validate_manifest(SCHEMA_PATH, path)
