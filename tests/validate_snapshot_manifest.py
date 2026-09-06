#!/usr/bin/env python3

"""Validate one snapshot manifest against the repository contract."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def validate_manifest(schema_path: Path, manifest_path: Path) -> None:
    schema = load_json(schema_path)
    manifest = load_json(manifest_path)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)

    paths = [item["path"] for item in manifest["files"]]
    if len(paths) != len(set(paths)):
        raise ValueError("manifest file paths must be unique")
    generated_at = datetime.fromisoformat(
        manifest["generated_at"].replace("Z", "+00:00")
    )
    soft_expires_at = datetime.fromisoformat(
        manifest["soft_expires_at"].replace("Z", "+00:00")
    )
    expires_at = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00"))
    if not generated_at <= soft_expires_at < expires_at:
        raise ValueError("manifest deadlines are not ordered")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_snapshot_manifest.py MANIFEST", file=sys.stderr)
        return 64
    repository_root = Path(__file__).resolve().parents[1]
    validate_manifest(
        repository_root / "schema/snapshot-manifest-v1.schema.json",
        Path(sys.argv[1]),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: invalid snapshot manifest: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
