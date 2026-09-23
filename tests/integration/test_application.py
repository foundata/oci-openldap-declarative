"""Exercise generated users and memberships through DokuWiki's HTTP login."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from urllib.error import URLError

import pytest
import yaml

from tests.integration.application import FIXTURES, Browser, application_image
from tests.integration.conftest import Images
from tests.integration.harness import Podman, Store
from tests.integration.test_generator import (
    PASSWORDS,
    RuntimeService,
    prepare_generator,
)

pytestmark = [pytest.mark.integration, pytest.mark.application]
PUBLIC_MARKER = "public-7fbf6a89"
SECRET_MARKER = "staff-639e67c2"


def test_dokuwiki_login_groups_rename_and_offboarding(
    request: pytest.FixtureRequest, podman: Podman, store: Store, images: Images
) -> None:
    runtime_image = images.require_runtime()
    generator_image = images.require_generator()
    cache = request.config.getoption("--dokuwiki-image-layout")
    image = application_image(
        podman,
        podman.inspect_image(runtime_image, "{{.Architecture}}"),
        Path(cache) if cache is not None else None,
    )
    generator = prepare_generator(
        podman, generator_image, store.workspace / "application-generator"
    )
    service = RuntimeService(podman, runtime_image, generator, f"{store.prefix}-wiki")
    storage = store.workspace / "wiki-storage"
    (storage / "conf").mkdir(parents=True)
    (storage / "data/pages/staff").mkdir(parents=True)
    for name in ("local.php", "acl.auth.php"):
        shutil.copyfile(FIXTURES / name, storage / "conf" / name)
    shutil.copyfile(FIXTURES / "start.txt", storage / "data/pages/start.txt")
    shutil.copyfile(FIXTURES / "secret.txt", storage / "data/pages/staff/secret.txt")
    wiki = f"{store.prefix}-dokuwiki"
    podman.plan_container(wiki)
    podman.run(
        "create",
        "--name",
        wiki,
        "--pull=never",
        "--userns=keep-id:uid=1001,gid=1001",
        "--user=1001:1001",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--memory=256m",
        "--cpus=1",
        "--pids-limit=128",
        "--ulimit=nofile=1024:1024",
        "--publish",
        "127.0.0.1::8080",
        "--volume",
        f"{storage}:/storage:Z",
        image,
    )
    try:
        podman.run("start", wiki)
        port = podman.inspect(
            wiki, '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}'
        )
        base_url = f"http://127.0.0.1:{port}"
        store.record("application-http", base_url)
        deadline = time.monotonic() + 30
        while True:
            try:
                page = Browser(base_url).page("id=start")
                if page.status == 200 and PUBLIC_MARKER in page.body:
                    break
            except (OSError, URLError):
                pass
            if time.monotonic() >= deadline:
                pytest.fail("DokuWiki did not serve the public page within 30 seconds")
            time.sleep(0.1)

        document = yaml.safe_load((generator.inputs / "directory.yaml").read_text())

        def deploy(revision: int) -> None:
            document["revision"] = revision
            name = f"wiki-{revision}"
            result = generator.variant(name, document)
            assert result.returncode == 0, result.stderr
            service.start(generator.output / name, network=f"container:{wiki}")
            assert service.accepted_revision() == str(revision)

        def session(username: str, password: str, authenticated: bool) -> Browser:
            browser = Browser(base_url)
            page = browser.login(username, password)
            assert page.status == (200 if authenticated else 403)
            assert page.logged_in == authenticated
            if not authenticated:
                assert page.login_fields.get("do") == "login"
            assert PUBLIC_MARKER in browser.page("id=start").body
            return browser

        def protected(browser: Browser, allowed: bool) -> None:
            page = browser.page("id=staff:secret")
            assert (SECRET_MARKER in page.body) == allowed
            assert page.status in (200, 403)
            if allowed:
                assert page.status == 200
            else:
                assert "Permission Denied" in page.body

        password = PASSWORDS["person-0001-example-app"]
        deploy(1)
        protected(Browser(base_url), False)
        protected(session("alice", password, True), True)
        protected(session("alice", "TEST-ONLY-wrong", False), False)
        protected(session("bob", PASSWORDS["person-0003"], True), False)

        document["users"][0]["username"] = "alice.renamed"
        deploy(2)
        protected(session("alice.renamed", password, True), True)
        session("alice", password, False)

        document["groups"][0]["members"] = ["bob"]
        deploy(3)
        protected(session("alice.renamed", password, True), False)
        protected(session("bob", PASSWORDS["person-0003"], True), True)

        document["users"][0]["active"] = False
        deploy(4)
        session("alice.renamed", password, False)
        protected(session("bob", PASSWORDS["person-0003"], True), True)
        assert podman.inspect(wiki, "{{.State.OOMKilled}}") == "false"
        (store.base / "application-result.json").write_text(
            json.dumps({"image": image, "revisions": 4, "result": "passed"}) + "\n"
        )
    finally:
        for name in (service.name, wiki):
            if podman.container_exists(name):
                (store.base / f"{name}.log").write_text(podman.logs(name))
                podman.stop(name)
