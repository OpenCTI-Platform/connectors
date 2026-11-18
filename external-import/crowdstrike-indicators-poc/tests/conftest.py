"""Pytest configuration for the CrowdStrike indicators proof of concept."""

import copy
import json
import re
import sys
import zlib
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
_NAME_FILTER = re.compile(r"^name:'(?P<token>(?:[^'\\]|\\.)*)'$")


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


def make_actor(name: str, actor_id: int | None = None, **fields: Any) -> dict[str, Any]:
    """Build a raw API actor named ``name`` (``SALTY SPIDER``), with its slug."""
    return {
        "id": zlib.crc32(name.encode()) if actor_id is None else actor_id,
        "name": name,
        "slug": name.lower().replace(" ", "-"),
        **fields,
    }


def filter_token(fql: str) -> str:
    """Return the token of a ``name:'<token>'`` filter, unescaped."""
    match = _NAME_FILTER.match(fql)
    assert match, fql
    return re.sub(r"\\(.)", r"\1", match["token"])


class FakeActorsAPI:
    """Simulates ``query_actor_entities`` over a dataset of actors.

    A ``name:'<token>'`` filter returns the actors whose name or slug,
    uppercased without spaces and hyphens, equals the token: the behavior
    the enricher assumes of the real API. ``failures`` maps a token to the
    responses to return, in order, before answering from the dataset.
    Records the arguments of every call.
    """

    def __init__(
        self,
        actors: list[dict[str, Any]] | None = None,
        failures: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self.actors = list(actors or [])
        self.failures = {token: list(rs) for token, rs in (failures or {}).items()}
        self.actor_calls: list[dict[str, Any]] = []

    @property
    def tokens(self) -> list[str]:
        """The token of every actors request, in order."""
        return [filter_token(call["filter"]) for call in self.actor_calls]

    def query_actor_entities(self, **kwargs: Any) -> dict[str, Any]:
        self.actor_calls.append(kwargs)
        token = filter_token(kwargs["filter"])
        if self.failures.get(token):
            return self.failures[token].pop(0)

        def key(value: str | None) -> str:
            return (value or "").upper().replace(" ", "").replace("-", "")

        wanted = key(token)
        matching = [
            actor
            for actor in self.actors
            if wanted in (key(actor.get("name")), key(actor.get("slug")))
        ]
        return ok({"errors": [], "resources": copy.deepcopy(matching)})


class ScriptedActorsClient:
    """Returns the given FalconPy actors responses in order, one per call."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.actor_calls: list[dict[str, Any]] = []

    def query_actor_entities(self, **kwargs: Any) -> dict[str, Any]:
        self.actor_calls.append(kwargs)
        if not self.responses:
            return ok({"resources": []})
        return self.responses.pop(0)


class FakeIndicatorsAPI(FakeActorsAPI):
    """Simulates ``query_indicator_entities`` over a dataset.

    Applies the same rules as CrowdStrike for the parameters the extractor
    uses: ``filter=_marker:>='<cursor>'`` (inclusive, compared as strings),
    ``sort=_marker.asc`` and ``limit``. Records the arguments of every call.
    Answers the actors API too, from ``actors`` (none by default): see
    :class:`FakeActorsAPI`.
    """

    def __init__(
        self,
        indicators: list[dict[str, Any]],
        actors: list[dict[str, Any]] | None = None,
        actor_failures: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        super().__init__(actors, actor_failures)
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


class ScriptedClient(FakeActorsAPI):
    """Returns the given FalconPy responses in order, one per call.

    Answers the actors API too, from ``actors`` (none by default).
    """

    def __init__(
        self,
        responses: list[dict[str, Any]],
        actors: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(actors)
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def query_indicator_entities(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if not self.responses:
            return ok({"resources": []})
        return self.responses.pop(0)


def build_extractor(client: Any, **kwargs: Any) -> Any:
    """Build a ``CrowdStrikeIndicatorExtractor`` whose actor enricher uses
    the same client, as the CLI does."""
    from crowdstrike_indicators.extract.actors import CrowdStrikeActorEnricher
    from crowdstrike_indicators.extract.extractor import CrowdStrikeIndicatorExtractor

    return CrowdStrikeIndicatorExtractor(
        client, CrowdStrikeActorEnricher(client), **kwargs
    )


@pytest.fixture
def indicators_page() -> dict[str, Any]:
    return load_fixture("indicators_page.json")


@pytest.fixture
def error_403() -> dict[str, Any]:
    return load_fixture("error_403.json")
