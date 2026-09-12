"""Custom LDIF owns server policy while preserving the snapshot runtime envelope."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from generator.generate import generate_snapshot, parse_directory
from scripts.directory_data import (
    ConfigurationError,
    Entry,
    parse_ldif,
    validate_entries,
    write_ldif,
)
from scripts.server_config import MODULES, check_health_access, validate_config

PROJECT = Path(__file__).resolve().parents[2]
EXAMPLES = PROJECT / "examples/generator"


def config() -> list[Entry]:
    return parse_ldif((EXAMPLES / "native-server.ldif").read_bytes()) + parse_ldif(
        (EXAMPLES / "native-database.ldif").read_bytes()
    )


def test_custom_configuration_preserves_administrator_policy() -> None:
    entries = config()
    entries[-1][1]["olcaccess"] = [b"to * by * write"]
    entries[-1][1]["olcreadonly"] = [b"FALSE"]
    entries[-1][1]["olcrootpw"] = [b"{SSHA}ADMIN-OWNED"]
    entries[-1][1]["olcdbmaxsize"] = [b"1073741824"]
    validate_config(entries, "o=Example")


@pytest.mark.parametrize("module", sorted(MODULES))
@pytest.mark.parametrize("suffix", ["", ".la", ".so"])
def test_packaged_modules_can_be_selected(module: str, suffix: str) -> None:
    entries = config()
    entries[2][1]["olcmoduleload"].append(f"{{9}}{module}{suffix}".encode())
    validate_config(entries, "o=Example")


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("olcdbdirectory", "/state/TOP-SECRET"),
        ("olcsuffix", "o=TOP-SECRET"),
        ("olcdatabase", "{1}ldap"),
        ("olcloglevel", "TOP-SECRET"),
        ("olcsyncrepl", "TOP-SECRET"),
        ("olcmodulepath", "/snapshot/TOP-SECRET"),
        ("olcmoduleload", "/usr/lib/ldap/back_mdb.la"),
        ("olcmoduleload", "TOP-SECRET"),
        ("olcpidfile", "/state/TOP-SECRET"),
        ("olcargsfile", "/state/TOP-SECRET"),
        ("olcdbdirectory;binary", "TOP-SECRET"),
        ("1.2.3.4", "TOP-SECRET"),
    ],
)
def test_runtime_envelope_rejects_conflicts_without_values(
    attribute: str, value: str
) -> None:
    entries = config()
    entries[-1][1][attribute] = [value.encode()]
    with pytest.raises(ConfigurationError) as raised:
        validate_config(entries, "o=Example")
    assert "TOP-SECRET" not in str(raised.value)


@pytest.mark.parametrize(
    "mutation", ["root", "schema", "mdb", "duplicate", "outside", "second-mdb"]
)
def test_incomplete_or_ambiguous_config_is_rejected(mutation: str) -> None:
    entries = config()
    if mutation == "root":
        del entries[0]
    elif mutation == "schema":
        del entries[1]
    elif mutation == "mdb":
        entries.pop()
    elif mutation == "duplicate":
        entries.append(entries[0])
    elif mutation == "outside":
        entries.append(("o=Example", {"objectclass": [b"organization"]}))
    else:
        entries.append(("olcDatabase={2}mdb,cn=config", entries[-1][1]))
    with pytest.raises(ConfigurationError):
        validate_config(entries, "o=Example")


def native_document(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    source = tmp_path / "native.yaml"
    document = yaml.safe_load((EXAMPLES / "native.yaml").read_text())
    document["config_files"] = [
        str(EXAMPLES / "native-server.ldif"),
        str(EXAMPLES / "native-database.ldif"),
    ]
    document["ldif_files"] = [str(EXAMPLES / "native.ldif")]
    source.write_text(yaml.safe_dump(document))
    return source, document


@pytest.mark.parametrize(
    "field",
    [
        "read_attributes",
        "schema_files",
        "entry_uuid",
        "users",
        "configuration_mode",
    ],
)
def test_native_rejects_managed_settings(tmp_path: Path, field: str) -> None:
    source, document = native_document(tmp_path)
    document[field] = []
    source.write_text(yaml.safe_dump(document))
    schema = json.loads((PROJECT / "schema/directory-v1.schema.json").read_text())
    assert not Draft202012Validator(schema).is_valid(document)
    with pytest.raises(ConfigurationError, match="unknown keys"):
        parse_directory(source)


def test_config_files_are_required_and_only_accepted_for_native(tmp_path: Path) -> None:
    source, document = native_document(tmp_path)
    schema = json.loads((PROJECT / "schema/directory-v1.schema.json").read_text())
    assert Draft202012Validator(schema).is_valid(document)
    del document["config_files"]
    source.write_text(yaml.safe_dump(document))
    assert not Draft202012Validator(schema).is_valid(document)
    with pytest.raises(ConfigurationError, match="config_files"):
        parse_directory(source)
    document = yaml.safe_load((EXAMPLES / "directory.yaml").read_text())
    document["config_files"] = ["server.ldif"]
    source.write_text(yaml.safe_dump(document))
    assert not Draft202012Validator(schema).is_valid(document)
    with pytest.raises(ConfigurationError, match="unknown keys"):
        parse_directory(source)


def test_native_credentials_and_missing_uuids_are_admin_owned() -> None:
    entries = parse_ldif((EXAMPLES / "native.ldif").read_bytes())
    for _, attributes in entries:
        attributes.pop("entryuuid")
    entries[-1][1]["userpassword"] = [b"{SSHA}ADMIN-OWNED"]
    validate_entries(entries, "o=Example", application_policy=False)
    with pytest.raises(ConfigurationError):
        validate_entries(entries, "o=Example")


def test_native_snapshot_signs_complete_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = native_document(tmp_path)
    directory = parse_directory(source)
    output = tmp_path / "snapshot"
    output.mkdir()
    signed = []
    monkeypatch.setattr(
        "generator.generate.sign_manifest", lambda *args: signed.append(args)
    )
    generate_snapshot(
        output, directory, tmp_path / "key", datetime.now(UTC).replace(microsecond=0)
    )
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["format_version"] == 1
    assert "read_attributes" not in manifest
    assert [record["kind"] for record in manifest["files"]] == ["data", "config"]
    assert parse_ldif((output / "config.ldif").read_bytes()) == config()
    assert len(signed) == 1
    schema = json.loads(
        (PROJECT / "schema/snapshot-manifest-v1.schema.json").read_text()
    )
    validator = Draft202012Validator(schema)
    assert validator.is_valid(manifest)
    for mutation in ("read_attributes", "missing-config", "second-config", "schema"):
        altered = json.loads(json.dumps(manifest))
        if mutation == "read_attributes":
            altered[mutation] = ["cn"]
        elif mutation == "missing-config":
            altered["files"].pop()
        elif mutation == "second-config":
            altered["files"].append({**altered["files"][-1], "path": "second.ldif"})
        else:
            altered["files"][-1]["kind"] = "schema"
        assert not validator.is_valid(altered), mutation


def test_standalone_runtime_validator_reports_errors_without_values(
    tmp_path: Path,
) -> None:
    source = tmp_path / "config.ldif"
    entries = config()
    entries[-1][1]["olcsuffix"] = [b"o=TOP-SECRET"]
    write_ldif(source, entries)
    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT / "scripts/server_config.py"),
            "--base-dn",
            "o=Example",
            str(source),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 65
    assert "TOP-SECRET" not in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "output",
    [
        "read access to entry: ALLOWED\nsearch access to objectClass: ALLOWED\n",
        "read access to entry: DENIED\nsearch access to objectClass: ALLOWED\n",
        "read access to entry: ALLOWED\nsearch access to objectClass: DENIED\n",
        "TOP-SECRET",
    ],
)
def test_health_access_checks_results_not_only_exit_status(
    monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    commands = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        assert kwargs["timeout"] == 15 and kwargs["capture_output"]
        return subprocess.CompletedProcess(command, 0, "", output)

    monkeypatch.setattr("scripts.server_config.subprocess.run", run)
    entries = config()
    entries[0][1]["olclocalssf"] = [b"256"]
    if output.count("ALLOWED") == 2:
        check_health_access(
            entries,
            "o=Example",
            Path("/run/openldap/slapd.d"),
            "ldapi://%2Frun%2Fopenldap%2Fldapi",
        )
        assert "ssf=256" in commands[0]
        assert "transport_ssf=256" in commands[0]
        assert "sockname=PATH=/run/openldap/ldapi" in commands[0]
        assert "-X" in commands[0]
    else:
        with pytest.raises(ConfigurationError) as raised:
            check_health_access(
                entries,
                "o=Example",
                Path("/run/openldap/slapd.d"),
                "ldapi://%2Frun%2Fopenldap%2Fldapi",
            )
        assert "TOP-SECRET" not in str(raised.value)


@pytest.mark.parametrize(
    "failure",
    [
        OSError("TOP-SECRET"),
        subprocess.TimeoutExpired("slapacl", 15, stderr="TOP-SECRET"),
    ],
)
def test_health_access_tool_failures_do_not_leak_values(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    def run(*args: Any, **kwargs: Any) -> None:
        raise failure

    monkeypatch.setattr("scripts.server_config.subprocess.run", run)
    with pytest.raises(ConfigurationError) as raised:
        check_health_access(
            config(),
            "o=Example",
            Path("/run/openldap/slapd.d"),
            "ldapi://%2Frun%2Fopenldap%2Fldapi",
        )
    assert "TOP-SECRET" not in str(raised.value)
