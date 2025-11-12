from types import SimpleNamespace

import pytest
from connectors_sdk.core.pydantic import pycti_list_serializer


def test_pycti_list_serializer_pycti_mode() -> None:
    info = SimpleNamespace(context={"mode": "pycti"})
    assert pycti_list_serializer(["e1", "e2"], info) == "e1,e2"


@pytest.mark.parametrize("context", [None, {}, {"mode": "other"}])
def test_pycti_list_serializer_non_pycti_modes(context: dict[str, str] | None) -> None:
    info = SimpleNamespace(context=context)
    value = ["e1", "e2"]
    assert pycti_list_serializer(value, info) == value
