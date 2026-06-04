"""Regression tests for the Sigma → MITRE technique-id validator.

``is_valid_technique_id`` gates whether a Sigma rule tag is emitted as
an ``AttackPattern`` SDO. The validator must accept both the canonical
upper-case (``T1059``, ``T1059.001``) and the lower-case forms
(``t1059``, ``t1059.001``) that ship in the wild, while rejecting
mis-shaped values so the converter does not emit malformed
``AttackPattern`` ids.
"""

import pytest
from connector.utils import is_valid_technique_id


@pytest.mark.parametrize(
    "value",
    [
        "T1059",
        "t1059",
        "T1059.001",
        "t1059.001",
        "T0001",
        "T1059.999",
    ],
)
def test_valid_technique_ids_accepted(value):
    assert is_valid_technique_id(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        "X1059",
        "T105",
        "T10590",
        "T1059.1",
        "T1059.001.002",
        "T1059 ",
        " T1059",
        "indicates",
    ],
)
def test_invalid_technique_ids_rejected(value):
    assert is_valid_technique_id(value) is False
