"""Pinned application image input and a cookie-aware HTTP form client."""

from __future__ import annotations

import json
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, ProxyHandler, build_opener

import pytest

from tests.integration.harness import Podman

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/dokuwiki"


def application_image(podman: Podman, architecture: str, layout: Path | None) -> str:
    pins = json.loads((FIXTURES / "image.json").read_text(encoding="utf-8"))
    digest = pins["digests"].get(architecture)
    if digest is None:
        pytest.fail(f"DokuWiki has no approved pin for architecture {architecture}")
    if layout is not None:
        if not layout.is_dir() or not (layout / "oci-layout").is_file():
            pytest.fail("--dokuwiki-image-layout must be an existing OCI layout")
        source = f"oci:{layout.resolve()}:dokuwiki"
    else:
        source = f"{pins['repository']}@{digest}"
    podman.store.record("application-image-source", source)
    pulled = podman.output(
        "pull", "--quiet", "--platform", f"linux/{architecture}", source, timeout=600
    )
    image = pulled.splitlines()[-1]
    actual_digest = podman.inspect_image(image, "{{.Digest}}")
    actual_architecture = podman.inspect_image(image, "{{.Architecture}}")
    if actual_digest != digest or actual_architecture != architecture:
        pytest.fail("DokuWiki image does not match the pinned platform digest")
    podman.store.record("application-image", f"{image}@{digest}")
    return image


class Page(HTMLParser):
    """Read login inputs and authentication state without scraping visible wording."""

    def __init__(self, body: str, status: int = 200) -> None:
        super().__init__(convert_charrefs=True)
        self.body = body
        self.status = status
        self.login_fields: dict[str, str] = {}
        self.logged_in = False
        self.in_login_form = False
        self.feed(body)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "form":
            self.in_login_form = attributes.get("id") == "dw__login"
        if tag == "input" and self.in_login_form:
            name = attributes.get("name")
            if name and attributes.get("type") == "hidden":
                self.login_fields[name] = attributes.get("value") or ""
        if tag == "a":
            query = parse_qs(urlsplit(attributes.get("href") or "").query)
            if query.get("do") == ["logout"]:
                self.logged_in = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.in_login_form = False


class Browser:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.http = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))

    def page(self, query: str, data: dict[str, str] | None = None) -> Page:
        encoded = urlencode(data).encode() if data is not None else None
        try:
            response = self.http.open(
                f"{self.base_url}/doku.php?{query}", encoded, timeout=5
            )
        except HTTPError as error:
            if error.code != 403:
                raise
            response = error
        with response:
            return Page(response.read().decode("utf-8"), response.status)

    def login(self, username: str, password: str) -> Page:
        form = self.page("id=start&do=login")
        assert form.status == 200 and form.login_fields.get("do") == "login"
        fields = {**form.login_fields, "u": username, "p": password}
        return self.page("id=start", fields)
