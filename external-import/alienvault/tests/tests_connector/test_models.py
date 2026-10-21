"""Tests for the OTX pulse models."""

from typing import Any, Callable, Dict, List

import pytest
from alienvault.models import Pulse
from pydantic.v1 import ValidationError


@pytest.mark.parametrize(
    "adversary, expected",
    [
        pytest.param("APT28", ["APT28"], id="single"),
        pytest.param(
            "Linen Typhoon, Storm-2603, Violet Typhoon",
            ["Linen Typhoon", "Storm-2603", "Violet Typhoon"],
            id="comma-separated",
        ),
        pytest.param(
            " Linen Typhoon ,, Storm-2603 ,Linen Typhoon, ,linen typhoon",
            ["Linen Typhoon", "Storm-2603"],
            id="whitespace-empty-and-duplicates",
        ),
        pytest.param(None, [], id="none"),
        pytest.param("", [], id="empty-string"),
        pytest.param(" , ", [], id="only-separators"),
        pytest.param([], [], id="empty-list"),
        pytest.param(
            ["Linen Typhoon", "Storm-2603"],
            ["Linen Typhoon", "Storm-2603"],
            id="list",
        ),
        pytest.param(
            [" Linen Typhoon ", "", "linen typhoon", "Storm-2603"],
            ["Linen Typhoon", "Storm-2603"],
            id="list-with-blanks-and-duplicates",
        ),
        pytest.param(
            ("Linen Typhoon", "Storm-2603"),
            ["Linen Typhoon", "Storm-2603"],
            id="tuple",
        ),
        pytest.param(42, ["42"], id="int"),
        pytest.param(1.5, ["1.5"], id="float"),
        pytest.param(["APT28", 28], ["APT28", "28"], id="list-with-number"),
    ],
)
def test_pulse_adversary_is_parsed_into_names(
    make_pulse: Callable[..., Pulse], adversary: Any, expected: List[str]
):
    """#5005: the adversary becomes a clean, de-duplicated list of names."""
    pulse = make_pulse(adversary=adversary)

    assert pulse.adversary == expected


def test_pulse_without_adversary_key_has_no_adversary(pulse_data: Dict[str, Any]):
    """#5005: a pulse that lacks the adversary key still validates."""
    pulse = Pulse(**pulse_data)

    assert pulse.adversary == []


@pytest.mark.parametrize("adversary", [{"name": "APT28"}, [None], [["APT28"]]])
def test_pulse_adversary_rejects_unsupported_types(
    make_pulse: Callable[..., Pulse], adversary: Any
):
    """#5005: a value that is not a string, a number or a list of them is invalid."""
    with pytest.raises(ValidationError):
        make_pulse(adversary=adversary)
