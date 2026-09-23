"""Documentation extraction must fail rather than silently select another example."""

from pathlib import Path

import pytest

from tests.readme_examples import bash_example


def test_readme_admin_examples_are_present() -> None:
    document = (Path(__file__).resolve().parents[2] / "README.md").read_text()
    for anchor in (
        "usage-prepare",
        "usage-prepare-yaml",
        "usage-snapshot-keys",
        "usage-snapshot-generate",
    ):
        assert "podman" in bash_example(document, anchor)


@pytest.mark.parametrize(
    "document",
    [
        "# Missing\n```bash\ntrue\n```\n",
        '# Title<a id="example"></a>\n## Next\n```bash\ntrue\n```\n',
        '# Title<a id="example"></a>\n```bash\ntrue\n',
        '# Title<a id="example"></a>\n```bash\ntrue\n```\n```bash\nfalse\n```\n',
    ],
)
def test_missing_or_ambiguous_snippets_fail(document: str) -> None:
    with pytest.raises(ValueError):
        bash_example(document, "example")
