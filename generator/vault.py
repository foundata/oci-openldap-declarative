"""Decrypt explicit Ansible Vault scalars using the supported CLI boundary."""

from __future__ import annotations

import getpass
import os
import re
import subprocess
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.directory_data import ConfigurationError, read_regular

VAULT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MAX_VAULT_VALUES = 256
MAX_VAULT_BYTES = 32768


@dataclass(frozen=True)
class VaultScalar:
    ciphertext: str = field(repr=False)


class DecryptedString(str):
    """Keep the encrypted-at-rest provenance until source validation finishes."""

    def __repr__(self) -> str:
        return "<decrypted>"


class Vault:
    def __init__(self, references: list[str]) -> None:
        self.sources: dict[str, str] = {}
        self.passwords: dict[str, bytes] = {}
        self.count = 0
        for reference in references:
            label, separator, source = reference.partition("@")
            if not separator or not VAULT_ID.fullmatch(label) or not source:
                raise ConfigurationError(
                    "--vault requires KEYID@prompt or KEYID@/absolute/password-file"
                )
            if label in self.sources:
                raise ConfigurationError("--vault must not repeat a key ID")
            if source != "prompt" and not Path(source).is_absolute():
                raise ConfigurationError("Vault password file paths must be absolute")
            self.sources[label] = source

    def password(self, label: str) -> bytes:
        if label not in self.sources:
            raise ConfigurationError(
                "no --vault source matches an encrypted value's key ID"
            )
        if label not in self.passwords:
            source = self.sources[label]
            if source == "prompt":
                try:
                    with Path("/dev/tty").open("w") as terminal:
                        if not terminal.isatty():
                            raise OSError
                        with warnings.catch_warnings():
                            warnings.simplefilter("error", getpass.GetPassWarning)
                            secret = getpass.getpass(
                                f"Vault password ({label}): ", stream=terminal
                            ).encode("utf-8")
                except (OSError, EOFError, getpass.GetPassWarning):
                    raise ConfigurationError(
                        "Vault prompting requires a terminal; use a password file in CI"
                    ) from None
            else:
                secret = read_regular(
                    Path(source),
                    maximum=4096,
                    context="Vault password file",
                    private=True,
                )
                secret = secret.removesuffix(b"\n").removesuffix(b"\r")
            if (
                not secret
                or secret != secret.strip()
                or any(char in secret for char in (b"\x00", b"\r", b"\n"))
            ):
                raise ConfigurationError(
                    "Vault passwords must be one non-empty line without surrounding whitespace"
                )
            self.passwords[label] = secret
        return self.passwords[label]

    def decrypt(self, scalar: VaultScalar) -> DecryptedString:
        self.count += 1
        if self.count > MAX_VAULT_VALUES:
            raise ConfigurationError("YAML exceeds the 256 encrypted-value limit")
        try:
            ciphertext = scalar.ciphertext.encode("ascii")
        except UnicodeError:
            raise ConfigurationError("Vault ciphertext must be ASCII") from None
        if len(ciphertext) > MAX_VAULT_BYTES:
            raise ConfigurationError("Vault scalar exceeds the 32768-byte limit")
        header, separator, _ = ciphertext.partition(b"\n")
        fields = header.decode("ascii").split(";")
        if (
            not separator
            or len(fields) != 4
            or fields[:3] != ["$ANSIBLE_VAULT", "1.2", "AES256"]
            or not VAULT_ID.fullmatch(fields[3])
        ):
            raise ConfigurationError(
                "Vault values require the labeled $ANSIBLE_VAULT;1.2;AES256;KEYID format"
            )
        label = fields[3]
        secret = self.password(label)
        with tempfile.TemporaryDirectory(prefix="openldap-vault-") as directory:
            home = Path(directory)
            config = home / "ansible.cfg"
            config.write_text("[defaults]\nvault_id_match = True\n", encoding="ascii")
            try:
                # Some Linux Python builds omit memfd_create. Both paths keep the
                # password anonymous and non-executable, disabling password scripts.
                with (
                    os.fdopen(
                        os.memfd_create("openldap-vault-password", os.MFD_CLOEXEC),
                        "w+b",
                    )
                    if hasattr(os, "memfd_create")
                    else tempfile.TemporaryFile(dir=home)
                ) as password_file:
                    descriptor = password_file.fileno()
                    os.fchmod(descriptor, 0o600)
                    password_file.write(secret + b"\n")
                    password_file.flush()
                    password_file.seek(0)
                    result = subprocess.run(
                        [
                            "/usr/bin/ansible-vault",
                            "decrypt",
                            "--output",
                            "-",
                            "--vault-id",
                            f"{label}@/proc/self/fd/{descriptor}",
                        ],
                        input=ciphertext,
                        capture_output=True,
                        check=False,
                        timeout=30,
                        pass_fds=(descriptor,),
                        cwd=home,
                        env={
                            "PATH": "/usr/bin:/bin",
                            "HOME": directory,
                            "TMPDIR": directory,
                            "LANG": "C.UTF-8",
                            "ANSIBLE_CONFIG": str(config),
                            "ANSIBLE_LOCAL_TEMP": str(home / "tmp"),
                            "ANSIBLE_NOCOLOR": "1",
                            "PYTHONDONTWRITEBYTECODE": "1",
                        },
                    )
            except (OSError, subprocess.TimeoutExpired):
                raise ConfigurationError(
                    "cannot run ansible-vault decryption (CLI required, 30-second timeout)"
                ) from None
        if result.returncode != 0:
            raise ConfigurationError(
                "Vault decryption failed; check the key and ciphertext"
            )
        if len(result.stdout) > MAX_VAULT_BYTES:
            raise ConfigurationError("decrypted Vault value exceeds the size limit")
        try:
            return DecryptedString(result.stdout.decode("utf-8"))
        except UnicodeError:
            raise ConfigurationError("decrypted Vault value must be UTF-8") from None

    def resolve(self, value: Any) -> Any:
        if isinstance(value, VaultScalar):
            return self.decrypt(value)
        if isinstance(value, dict):
            return {key: self.resolve(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.resolve(item) for item in value]
        return value
