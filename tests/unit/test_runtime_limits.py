"""Check descriptor ceilings without changing the test runner's process limits."""

from __future__ import annotations

import resource
from unittest.mock import Mock, call

import pytest

from scripts import runtime_limits


@pytest.mark.parametrize("value", [None, "1", "4096", "8192", "2147483647"])
def test_open_files_cap(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    monkeypatch.delenv("LDAP_MAX_OPEN_FILES", raising=False)
    if value is not None:
        monkeypatch.setenv("LDAP_MAX_OPEN_FILES", value)
    assert runtime_limits.open_files_cap() == (4096 if value is None else int(value))


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0",
        "-1",
        "+1",
        "01",
        "1.5",
        " 1",
        "1\n",
        "unlimited",
        "2147483648",
        "9" * 100,
    ],
)
def test_invalid_cap_fails_before_changing_limits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    monkeypatch.setenv("LDAP_MAX_OPEN_FILES", value)
    prlimit = Mock()
    monkeypatch.setattr(resource, "prlimit", prlimit)
    assert runtime_limits.main(["123"]) == 64
    prlimit.assert_not_called()
    assert "LDAP_MAX_OPEN_FILES must be an integer" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("inherited", "expected"),
    [
        ((524288, 524288), (4096, 4096)),
        ((1024, 524288), (1024, 4096)),
        ((512, 1024), (512, 1024)),
        ((4096, 4096), (4096, 4096)),
        ((resource.RLIM_INFINITY, resource.RLIM_INFINITY), (4096, 4096)),
        ((1024, resource.RLIM_INFINITY), (1024, 4096)),
    ],
)
def test_clamp_never_raises_limits(
    monkeypatch: pytest.MonkeyPatch,
    inherited: tuple[int, int],
    expected: tuple[int, int],
) -> None:
    prlimit = Mock(return_value=inherited)
    monkeypatch.setattr(resource, "prlimit", prlimit)
    runtime_limits.clamp_open_files(123, 4096)
    calls = [call(123, resource.RLIMIT_NOFILE)]
    if inherited != expected:
        calls.append(call(123, resource.RLIMIT_NOFILE, expected))
    assert prlimit.call_args_list == calls


def test_custom_cap_is_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LDAP_MAX_OPEN_FILES", "8192")
    prlimit = Mock(return_value=(524288, 524288))
    monkeypatch.setattr(resource, "prlimit", prlimit)
    assert runtime_limits.main(["123"]) == 0
    assert prlimit.call_args_list == [
        call(123, resource.RLIMIT_NOFILE),
        call(123, resource.RLIMIT_NOFILE, (8192, 8192)),
    ]


@pytest.mark.parametrize("operation", ["read", "write"])
def test_limit_failure_stops_startup(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], operation: str
) -> None:
    monkeypatch.delenv("LDAP_MAX_OPEN_FILES", raising=False)
    error = PermissionError("denied")
    prlimit = Mock(
        side_effect=error if operation == "read" else [(524288, 524288), error]
    )
    monkeypatch.setattr(resource, "prlimit", prlimit)
    assert runtime_limits.main(["123"]) == 70
    assert "Cannot bound open-file limits" in capsys.readouterr().err


@pytest.mark.parametrize("pid", ["0", "-1", "not-a-pid"])
def test_invalid_pid_is_rejected(monkeypatch: pytest.MonkeyPatch, pid: str) -> None:
    prlimit = Mock()
    monkeypatch.setattr(resource, "prlimit", prlimit)
    with pytest.raises(SystemExit, match="2"):
        runtime_limits.main([pid])
    prlimit.assert_not_called()
