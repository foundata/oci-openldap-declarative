"""Keep emulation wait overrides explicit and bounded."""

import argparse

import pytest

from tests.conftest import positive_timeout


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "oops"])
def test_readiness_timeout_rejects_invalid_values(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        positive_timeout(value)


def test_readiness_timeout_accepts_positive_seconds() -> None:
    assert positive_timeout("120") == 120.0
    assert positive_timeout("0.5") == 0.5
