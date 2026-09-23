"""Check application image trust and HTML parsing without external services."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest

from tests.integration.application import FIXTURES, Page, application_image
from tests.integration.harness import Podman


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
@pytest.mark.parametrize("cached", [False, True])
def test_application_image_uses_exact_platform_pin(
    tmp_path: Path, architecture: str, cached: bool
) -> None:
    pins = json.loads((FIXTURES / "image.json").read_text())
    digest = pins["digests"][architecture]
    (tmp_path / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    podman = Mock(spec=Podman)
    podman.store = Mock()
    podman.output.return_value = "image-id\n"
    podman.inspect_image.side_effect = [digest, architecture]
    assert (
        application_image(
            cast(Podman, podman), architecture, tmp_path if cached else None
        )
        == "image-id"
    )
    source = f"oci:{tmp_path}:dokuwiki" if cached else f"{pins['repository']}@{digest}"
    podman.output.assert_called_once_with(
        "pull", "--quiet", "--platform", f"linux/{architecture}", source, timeout=600
    )


@pytest.mark.parametrize("actual", [("sha256:wrong", "amd64"), (None, "arm64")])
def test_application_image_rejects_mismatch(actual: tuple[str | None, str]) -> None:
    pin = json.loads((FIXTURES / "image.json").read_text())["digests"]["amd64"]
    podman = Mock(spec=Podman)
    podman.store = Mock()
    podman.output.return_value = "image-id"
    podman.inspect_image.side_effect = [actual[0] or pin, actual[1]]
    with pytest.raises(pytest.fail.Exception, match="pinned platform digest"):
        application_image(cast(Podman, podman), "amd64", None)


def test_invalid_cache_and_unsupported_platform_do_not_pull(tmp_path: Path) -> None:
    podman = Mock(spec=Podman)
    with pytest.raises(pytest.fail.Exception, match="existing OCI layout"):
        application_image(cast(Podman, podman), "amd64", tmp_path)
    with pytest.raises(pytest.fail.Exception, match="no approved pin"):
        application_image(cast(Podman, podman), "s390x", None)
    podman.output.assert_not_called()


def test_page_reads_only_login_form_hidden_fields() -> None:
    page = Page(
        '<form><input type="hidden" name="do" value="search"></form>'
        '<form id="dw__login"><input type="hidden" name="do" value="login">'
        '<input name="sectok" type="hidden" value="csrf&amp;token">'
        '<input name="u"><input name="p" type="password"></form>'
    )
    assert page.login_fields == {"do": "login", "sectok": "csrf&token"}
    assert not page.logged_in


def test_page_recognizes_logout_action_not_visible_wording() -> None:
    assert not Page("Log Out").logged_in
    assert not Page('<a href="/?do=login">Log In</a>').logged_in
    assert Page('<a href="/doku.php?id=start&amp;do=logout">Exit</a>').logged_in
