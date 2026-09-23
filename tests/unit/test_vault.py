"""Keep source decryption strict, bounded, isolated and free of secret diagnostics."""

from __future__ import annotations

import io
import os
import pty
import select
import signal
import subprocess
import sys
import time
import warnings
from pathlib import Path
from typing import Any

import pytest

from generator.generate import load_yaml
from generator.vault import DecryptedString, Vault, VaultScalar
from scripts.directory_data import ConfigurationError


def secret(
    tmp_path: Path, name: str = "password", value: bytes = b"TEST-ONLY-key\n"
) -> Path:
    path = tmp_path / name
    path.write_bytes(value)
    path.chmod(0o600)
    return path


@pytest.mark.parametrize(
    "references",
    [["x"], ["@prompt"], ["x@relative"], ["x@prompt", "x@/a"], ["bad id@prompt"]],
)
def test_invalid_key_references(references: list[str]) -> None:
    with pytest.raises(ConfigurationError):
        Vault(references)


@pytest.mark.parametrize("without_memfd", [False, True])
def test_cli_boundary_uses_private_fd_and_an_isolated_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, without_memfd: bool
) -> None:
    if without_memfd:
        monkeypatch.delattr(os, "memfd_create", raising=False)
    source = secret(tmp_path)
    source.chmod(0o700)  # This must be read, never executed as a password script.
    monkeypatch.setenv("ANSIBLE_CONFIG", "/TOP-SECRET/host.cfg")
    monkeypatch.setenv("ANSIBLE_VAULT_PASSWORD_FILE", "/TOP-SECRET/script")
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        fd = kwargs["pass_fds"][0]
        assert os.fstat(fd).st_mode & 0o777 == 0o600
        assert os.read(fd, 4096) == b"TEST-ONLY-key\n"
        assert "TEST-ONLY-key" not in str(command) + str(kwargs["env"])
        assert "ANSIBLE_VAULT_PASSWORD_FILE" not in kwargs["env"]
        assert kwargs["env"]["ANSIBLE_CONFIG"] != "/TOP-SECRET/host.cfg"
        assert (
            "vault_id_match = True" in Path(kwargs["env"]["ANSIBLE_CONFIG"]).read_text()
        )
        return subprocess.CompletedProcess(command, 0, b"001: literal\n", b"")

    monkeypatch.setattr(subprocess, "run", run)
    vault = Vault([f"directory@{source}"])
    result = vault.decrypt(VaultScalar("$ANSIBLE_VAULT;1.2;AES256;directory\n00\n"))
    assert result == "001: literal\n" and isinstance(result, DecryptedString)
    assert "literal" not in repr(result)
    assert len(calls) == 1


def test_exact_label_selection_never_tries_unrelated_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = Vault([f"right@{secret(tmp_path)}"])

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("must not launch CLI without a matching key ID")

    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(ConfigurationError, match="key ID"):
        vault.decrypt(VaultScalar("$ANSIBLE_VAULT;1.2;AES256;wrong\n00\n"))


@pytest.mark.parametrize(
    "value", [b"\n", b" key\n", b"key \n", b"one\ntwo\n", b"a\x00b", b"x" * 4097]
)
def test_password_file_contract(tmp_path: Path, value: bytes) -> None:
    vault = Vault([f"key@{secret(tmp_path, value=value)}"])
    with pytest.raises(ConfigurationError):
        vault.password("key")


def test_prompt_is_read_once_for_each_id(monkeypatch: pytest.MonkeyPatch) -> None:
    class Terminal(io.StringIO):
        def isatty(self) -> bool:
            return True

    prompts: list[str] = []

    def prompt(message: str, **kwargs: Any) -> str:
        prompts.append(message)
        return "TEST-ONLY-prompt-key"

    def open_terminal(path: Path, mode: str) -> Terminal:
        assert str(path) == "/dev/tty" and mode == "w"
        return Terminal()

    monkeypatch.setattr(Path, "open", open_terminal)
    monkeypatch.setattr("getpass.getpass", prompt)
    vault = Vault(["one@prompt", "two@prompt"])
    assert vault.password("one") == vault.password("one")
    vault.password("two")
    assert len(prompts) == 2


def test_prompt_rejects_visible_input_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    import getpass

    class Terminal(io.StringIO):
        def isatty(self) -> bool:
            return True

    def unsafe_prompt(*args: Any, **kwargs: Any) -> str:
        warnings.warn("cannot disable echo", getpass.GetPassWarning, stacklevel=2)
        pytest.fail("must not fall back to visible input")

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: Terminal())
    monkeypatch.setattr(getpass, "getpass", unsafe_prompt)
    with pytest.raises(ConfigurationError, match="requires a terminal"):
        Vault(["key@prompt"]).password("key")


def test_real_terminal_prompt_does_not_echo_password() -> None:
    script = (
        "from generator.vault import Vault; "
        "v=Vault(['key@prompt']); "
        "assert v.password('key') == b'TEST-ONLY-terminal-key'; "
        "assert v.password('key') == b'TEST-ONLY-terminal-key'; "
        "print('PROMPT_OK')"
    )
    child, terminal = pty.fork()
    if child == 0:
        os.chdir(Path(__file__).resolve().parents[2])
        os.execl(sys.executable, sys.executable, "-c", script)
    output = b""
    sent = False
    reaped = False
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and b"PROMPT_OK" not in output:
            if not select.select([terminal], [], [], 0.1)[0]:
                continue
            try:
                data = os.read(terminal, 4096)
            except OSError:
                break
            if not data:
                break
            output += data
            if b"Vault password (key): " in output and not sent:
                os.write(terminal, b"TEST-ONLY-terminal-key\n")
                sent = True
        assert b"PROMPT_OK" in output, output
        assert b"TEST-ONLY-terminal-key" not in output
        assert output.count(b"Vault password (key): ") == 1
        _, status = os.waitpid(child, 0)
        reaped = True
        assert os.waitstatus_to_exitcode(status) == 0
    finally:
        os.close(terminal)
        if not reaped:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)


@pytest.mark.parametrize(
    "content",
    [
        "foo: !vault [value]\n",
        "!vault encrypted: value\n",
        "foo: !unknown value\n",
        "foo: !vault |\n  $VAULT;1.2;AES256;id\n  00\n",
        "foo: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  00\n",
    ],
)
def test_yaml_tags_are_narrowly_scoped(tmp_path: Path, content: str) -> None:
    source = tmp_path / "source.yaml"
    source.write_text(content)
    with pytest.raises(ConfigurationError):
        load_yaml(source, context="source")


def test_decryption_failures_are_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args, 1, b"TOP-SECRET", b"TOP-SECRET"
        ),
    )
    with pytest.raises(ConfigurationError) as raised:
        Vault([f"id@{secret(tmp_path)}"]).decrypt(
            VaultScalar("$ANSIBLE_VAULT;1.2;AES256;id\n00\n")
        )
    assert "TOP-SECRET" not in str(raised.value)


def test_decrypted_strings_are_not_reparsed_as_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Vault, "decrypt", lambda *args: DecryptedString("false"))
    source = tmp_path / "source.yaml"
    source.write_text("foo: !vault encrypted\n")
    assert load_yaml(source, context="source") == {"foo": "false"}


def test_repeated_values_decrypt_once_without_bypassing_the_count_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []

    def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, b"false", b"")

    monkeypatch.setattr(subprocess, "run", run)
    vault = Vault([f"id@{secret(tmp_path)}"])
    value = VaultScalar("$ANSIBLE_VAULT;1.2;AES256;id\n00\n")
    resolved = vault.resolve({"items": [value] * 256})
    assert resolved == {"items": ["false"] * 256}
    assert all(isinstance(item, DecryptedString) for item in resolved["items"])
    assert len(calls) == 1
    with pytest.raises(ConfigurationError, match="256 encrypted-value limit"):
        vault.decrypt(value)
    assert len(calls) == 1


def test_cache_is_exact_and_local_to_the_vault_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []

    def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, b"secret", b"")

    monkeypatch.setattr(subprocess, "run", run)
    references = [f"first@{secret(tmp_path)}", f"second@{secret(tmp_path, 'second')}"]
    vault = Vault(references)
    for label, payload in (("first", "00"), ("first", "01"), ("second", "00")):
        value = VaultScalar(f"$ANSIBLE_VAULT;1.2;AES256;{label}\n{payload}\n")
        vault.decrypt(value)
        vault.decrypt(value)
    assert len(calls) == 3
    Vault(references).decrypt(value)
    assert len(calls) == 4


def test_failed_decryption_is_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []

    def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, b"PRIVATE", b"PRIVATE")

    monkeypatch.setattr(subprocess, "run", run)
    vault = Vault([f"id@{secret(tmp_path)}"])
    for _ in range(2):
        with pytest.raises(ConfigurationError, match="Vault decryption failed"):
            vault.decrypt(VaultScalar("$ANSIBLE_VAULT;1.2;AES256;id\n00\n"))
    assert len(calls) == 2 and not vault.decrypted
