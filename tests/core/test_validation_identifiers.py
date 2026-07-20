from __future__ import annotations

import pytest

from forge.utils.validation_identifiers import looks_compound_placeholder_identifier


@pytest.mark.parametrize(
    "value",
    [
        "testuser",
        "testuser123",
        "user-test-001",
        "usr_testuser123",
        "tok_sampleproject42",
        "placeholder-service-01",
        "fakeaccount9",
    ],
)
def test_compound_placeholder_identifier_rejects_numeric_suffixes(value: str) -> None:
    assert looks_compound_placeholder_identifier(value)


@pytest.mark.parametrize(
    "value",
    [
        "acmebot",
        "usr_abcdefghijklmnop",
        "netlify-user-123",
        "delta-ops",
        "team-test-lab",
    ],
)
def test_compound_placeholder_identifier_preserves_stable_names(value: str) -> None:
    assert not looks_compound_placeholder_identifier(value)
