"""The generated matrix rejects broken mappings without claiming semantic coverage."""

from pathlib import Path

import pytest

from hack.implementation import ROOT, render


def tree(root: Path) -> None:
    (root / "ARCHITECTURE.md").write_text('<a id="IP0001"></a><!-- Test contract -->\n')
    for name in ("generator", "scripts", "tests"):
        (root / name).mkdir()
    (root / "generator/feature.py").write_text(
        "# Implements: IP0001\ndef feature():\n    pass\n"
    )
    (root / "tests/test_feature.py").write_text(
        "# Verifies: IP0001\ndef test_feature():\n    pass\n"
    )


def test_checked_in_implementation_matrix_is_current() -> None:
    assert (ROOT / "docs/implementation.md").read_text() == render(ROOT)


def test_matrix_links_functions_and_ignores_strings(tmp_path: Path) -> None:
    tree(tmp_path)
    (tmp_path / "scripts/noise.py").write_text(
        'text = """\n# Implements: IP9999\n"""\n'
    )
    document = render(tmp_path)
    assert "../ARCHITECTURE.md#IP0001" in document
    assert "[feature](../generator/feature.py#L2)" in document
    assert "[test_feature](../tests/test_feature.py#L2)" in document


@pytest.mark.parametrize(
    ("path", "content", "error"),
    [
        ("generator/feature.py", "def feature():\n    pass\n", "needs production"),
        (
            "tests/test_feature.py",
            "def test_feature():\n    pass\n",
            "needs production",
        ),
        (
            "generator/feature.py",
            "# Implements: IP9999\ndef feature():\n    pass\n",
            "unknown promise",
        ),
        (
            "generator/feature.py",
            "# Implements: IP0001, IP0001\ndef feature():\n    pass\n",
            "repeated promise",
        ),
        (
            "generator/feature.py",
            "# Implements: IP1\ndef feature():\n    pass\n",
            "invalid promise",
        ),
        (
            "generator/feature.py",
            "# Implements: IP0001\nvalue = 1\n",
            "precede a function",
        ),
        (
            "tests/test_feature.py",
            "# Verifies: IP0001\ndef helper():\n    pass\n",
            "invalid Verifies",
        ),
        (
            "generator/feature.py",
            "# Verifies: IP0001\ndef feature():\n    pass\n",
            "invalid Verifies",
        ),
        (
            "ARCHITECTURE.md",
            '<a id="IP0001"></a><!-- First -->\n<a id="IP0001"></a><!-- Second -->\n',
            "duplicate architecture",
        ),
    ],
)
def test_matrix_rejects_broken_references(
    tmp_path: Path, path: str, content: str, error: str
) -> None:
    tree(tmp_path)
    (tmp_path / path).write_text(content)
    with pytest.raises(ValueError, match=error):
        render(tmp_path)
