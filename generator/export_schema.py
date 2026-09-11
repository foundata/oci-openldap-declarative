"""Export the loaded schema during the generator image build over private LDAPI."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import ldap
from ldif import LDIFWriter

SCHEMAS = ("core", "cosine", "inetorgperson", "nis")


def export_schema(schema: dict[str, list[bytes]], destination: Path) -> None:
    with destination.open("w", encoding="utf-8") as stream:
        LDIFWriter(stream).unparse(
            "cn=openldap,cn=schema,cn=config",
            {
                "objectClass": [b"olcSchemaConfig"],
                "cn": [b"openldap"],
                "olcAttributeTypes": schema["attributeTypes"],
                "olcObjectClasses": schema["objectClasses"],
            },
        )


def collect_schema(destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="openldap-schema-") as directory:
        path = Path(directory)
        config = path / "slapd.conf"
        config.write_text(
            "".join(f"include /etc/ldap/schema/{name}.schema\n" for name in SCHEMAS)
            + f"pidfile {path}/slapd.pid\nargsfile {path}/slapd.args\n",
            encoding="utf-8",
        )
        uri = "ldapi://" + str(path / "ldapi").replace("/", "%2F")
        with (path / "slapd.log").open("wb") as log:
            process = subprocess.Popen(
                ["/usr/sbin/slapd", "-f", str(config), "-h", uri, "-d", "0"],
                stdout=log,
                stderr=log,
            )
            try:
                connection = ldap.initialize(uri)
                connection.set_option(ldap.OPT_NETWORK_TIMEOUT, 2)
                connection.set_option(ldap.OPT_TIMEOUT, 2)
                deadline = time.monotonic() + 15
                while process.poll() is None and time.monotonic() < deadline:
                    try:
                        result = connection.search_s(
                            "cn=Subschema",
                            ldap.SCOPE_BASE,
                            "(objectClass=subschema)",
                            ["attributeTypes", "objectClasses"],
                        )
                    except ldap.SERVER_DOWN:
                        time.sleep(0.05)
                        continue
                    if len(result) != 1:
                        raise RuntimeError("expected one LDAP subschema entry")
                    export_schema(result[0][1], destination / "openldap.ldif")
                    break
                else:
                    raise RuntimeError("build-only slapd did not expose its schema")
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
    checksums = {
        f"{name}.ldif": hashlib.sha256(
            Path(f"/etc/ldap/schema/{name}.ldif").read_bytes()
        ).hexdigest()
        for name in SCHEMAS
    }
    (destination / "source-checksums.json").write_text(
        json.dumps(checksums, indent=2) + "\n"
    )


if __name__ == "__main__":
    collect_schema(Path(sys.argv[1]))
