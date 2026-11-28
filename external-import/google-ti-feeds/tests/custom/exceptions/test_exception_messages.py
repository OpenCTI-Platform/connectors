"""The connector's exceptions put the original message in their own message.

The error strings had lost their f prefix, so every exception read like
"API error at endpoint: {message}" and the cause only showed in the chained
traceback.
"""

import inspect
from itertools import combinations
from typing import Any

import connector.src.custom.exceptions as exceptions_module
import pytest
from connector.src.custom.exceptions import GTIApiError

EXCEPTION_CLASSES = [
    cls
    for _, cls in inspect.getmembers(exceptions_module, inspect.isclass)
    if issubclass(cls, Exception)
]

_INT_PARAMS = {"page", "page_size", "batch_number", "reports_count"}
_DICT_PARAMS = {"details", "data_sample"}


def _sample(name: str) -> Any:
    if name in _INT_PARAMS:
        return 2
    if name in _DICT_PARAMS:
        return {"key": "value"}
    return f"sample-{name}"


def _optional_kwarg_sets(cls: type[Exception]) -> list[dict[str, Any]]:
    """Every combination of the constructor's optional arguments, so each branch is taken."""
    params = [
        p
        for p in inspect.signature(cls.__init__).parameters.values()
        if p.name not in ("self", "message")
        and p.default is not inspect.Parameter.empty
    ]
    return [
        {p.name: _sample(p.name) for p in combo}
        for size in range(len(params) + 1)
        for combo in combinations(params, size)
    ]


@pytest.mark.parametrize("cls", EXCEPTION_CLASSES, ids=lambda cls: cls.__name__)
def test_exception_message_contains_the_original_message(cls: type[Exception]) -> None:
    for kwargs in _optional_kwarg_sets(cls):
        text = str(cls("HTTP 403 Forbidden", **kwargs))
        assert "HTTP 403 Forbidden" in text, (cls.__name__, kwargs, text)
        assert "{message}" not in text, (cls.__name__, kwargs, text)


def test_gti_api_error_names_the_endpoint_and_status_code() -> None:
    assert (
        str(GTIApiError("Forbidden", status_code="403", endpoint="/collections"))
        == "API error at /collections (status 403): Forbidden"
    )
    assert (
        str(GTIApiError("Forbidden", endpoint="/collections"))
        == "API error at /collections: Forbidden"
    )
    assert (
        str(GTIApiError("Forbidden", status_code="403"))
        == "API error (status 403): Forbidden"
    )
    assert str(GTIApiError("Forbidden")) == "Forbidden"
