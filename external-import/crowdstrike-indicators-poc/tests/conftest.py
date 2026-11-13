"""Pytest configuration for the CrowdStrike indicators proof of concept."""

import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

# ``src`` goes first on the path so that ``import shared`` resolves to this
# proof of concept's ``src/shared`` package, not to the repository root
# ``shared`` package (CI tooling).
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

_MARKER_FILTER = re.compile(r"^_marker:>='(?P<cursor>[^']*)'$")


def load_fixture(name: str) -> dict[str, Any]:
    """Load a JSON fixture from ``tests/fixtures``."""
    return json.loads((FIXTURES_DIR / name).read_text())


def ok(body: dict[str, Any]) -> dict[str, Any]:
    """Wrap a body in a FalconPy success response."""
    return {"status_code": 200, "headers": {}, "body": body}


def make_indicator(
    index: int, *, second: int | None = None, **fields: Any
) -> dict[str, Any]:
    """Build a raw API indicator.

    ``second`` is the Unix second of its marker, ``1700000000 + index`` by
    default. The marker suffix keeps markers unique and in index order.
    """
    second = 1_700_000_000 + index if second is None else second
    return {
        "id": f"ioc-{index}",
        "indicator": f"host-{index}.example",
        "type": "domain",
        "_marker": f"{second}x{index:06d}",
        "last_updated": second,
        **fields,
    }


class FakeIndicatorsAPI:
    """Simulates ``query_indicator_entities`` over a dataset.

    Applies the same rules as CrowdStrike for the parameters the extractor
    uses: ``filter=_marker:>='<cursor>'`` (inclusive, compared as strings),
    ``sort=_marker.asc`` and ``limit``. Records the arguments of every call.
    """

    def __init__(self, indicators: list[dict[str, Any]]) -> None:
        self.indicators = sorted(indicators, key=lambda raw: raw["_marker"])
        self.calls: list[dict[str, Any]] = []

    def query_indicator_entities(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        assert kwargs["sort"] == "_marker.asc"
        match = _MARKER_FILTER.match(kwargs["filter"])
        assert match, kwargs["filter"]
        cursor = match["cursor"]
        matching = [raw for raw in self.indicators if raw["_marker"] >= cursor]
        page = matching[: kwargs["limit"]]
        return ok(
            {
                "meta": {"pagination": {"total": len(matching)}},
                "errors": [],
                "resources": copy.deepcopy(page),
            }
        )


class ScriptedClient:
    """Returns the given FalconPy responses in order, one per call."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def query_indicator_entities(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if not self.responses:
            return ok({"resources": []})
        return self.responses.pop(0)


@pytest.fixture
def indicators_page() -> dict[str, Any]:
    return load_fixture("indicators_page.json")


@pytest.fixture
def error_403() -> dict[str, Any]:
    return load_fixture("error_403.json")
