# pragma: no cover # Do not compute coverage on test files
"""Offer tests for CrowdStrikeActorDateRangeProvider."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest
from connectors_sdk.converters.crowdstrike import CrowdStrikeActorConverter
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from connectors_sdk.providers import AbstractDateRangeProvider
from connectors_sdk.providers.crowdstrike import CrowdStrikeActorDateRangeProvider
from falconpy import Intel

FIXTURE = (
    Path(__file__).parents[2]
    / "test_converters"
    / "crowdstrike"
    / "fixtures"
    / "actor_full.json"
)
T0800 = datetime(2026, 10, 20, 8, 0, tzinfo=timezone.utc)
T0930 = datetime(2026, 10, 20, 9, 30, tzinfo=timezone.utc)


def actor(id: int, modified: datetime | None, **fields: Any) -> dict[str, Any]:
    """Return a raw CrowdStrike actor."""
    raw: dict[str, Any] = {"id": id, "name": f"ACTOR {id}", **fields}
    if modified is not None:
        raw["last_modified_date"] = int(modified.timestamp())
    return raw


def ok(resources: list[Any] | None) -> dict[str, Any]:
    """Return a falconpy-like 200 response."""
    return {"status_code": 200, "headers": {}, "body": {"resources": resources}}


def error(status_code: int) -> dict[str, Any]:
    """Return a falconpy-like error response."""
    return {
        "status_code": status_code,
        "headers": {},
        "body": {"errors": [{"message": "x"}], "resources": None},
    }


class FakeIntel:
    """Fake falconpy Intel client recording calls."""

    def __init__(
        self,
        actors: Any,
        mitre: dict[str, Any] | None = None,
    ) -> None:
        """Store the actor response and the MITRE response of each actor id."""
        self.actors = actors
        self.mitre = mitre or {}
        self.actor_calls: list[dict[str, Any]] = []
        self.mitre_calls: list[str] = []

    def query_actor_entities(self, parameters: dict[str, Any]) -> Any:
        """Return or raise the actor response."""
        self.actor_calls.append(parameters)
        if isinstance(self.actors, Exception):
            raise self.actors
        return self.actors

    def query_mitre_attacks(self, id: str) -> Any:
        """Return the MITRE response of an actor, empty by default."""
        self.mitre_calls.append(id)
        return self.mitre.get(id, ok([]))


def provider(client: FakeIntel) -> CrowdStrikeActorDateRangeProvider:
    """Build a provider on a fake client."""
    return CrowdStrikeActorDateRangeProvider(client=cast(Intel, client))


def test_provider_type() -> None:
    """Test that the provider is a date range provider."""
    assert issubclass(CrowdStrikeActorDateRangeProvider, AbstractDateRangeProvider)


def test_actors_grouped_by_modification_date() -> None:
    """Test that actors modified in the same second share one date key."""
    client = FakeIntel(ok([actor(1, T0800), actor(2, T0800), actor(3, T0930)]))

    result = provider(client).get_data(since=T0800, limit=50)

    assert list(result) == [T0800, T0930]
    assert [item.actor.id for item in result[T0800]] == [1, 2]
    assert max(result) == T0930


def test_request_sent() -> None:
    """Test the one actor query: inclusive filter, ascending sort, limit, fields."""
    client = FakeIntel(ok([]))

    provider(client).get_data(since=T0800, limit=50)

    assert client.actor_calls == [
        {
            "limit": 50,
            "sort": "last_modified_date|asc",
            "filter": f"last_modified_date:>={int(T0800.timestamp())}",
            "fields": "__full__",
        }
    ]


def test_mitre_attack_ids_attached() -> None:
    """Test that each actor carries its MITRE ATT&CK ids, empty when none."""
    client = FakeIntel(
        ok([actor(1, T0800), actor(2, T0800)]),
        mitre={"1": ok(["actor_TA0002_T1059.001"])},
    )

    items = provider(client).get_data(since=T0800, limit=50)[T0800]

    assert client.mitre_calls == ["1", "2"]
    assert items[0].mitre_attack_ids == ["actor_TA0002_T1059.001"]
    assert items[1].mitre_attack_ids == []


def test_nothing_new() -> None:
    """Test that no actor (resources empty or absent) gives an empty result."""
    assert provider(FakeIntel(ok([]))).get_data(since=T0800, limit=50) == {}
    assert provider(FakeIntel(ok(None))).get_data(since=T0800, limit=50) == {}


@pytest.mark.parametrize(
    "invalid",
    [
        actor(2, None),
        {**actor(2, None), "last_modified_date": "not a date"},
        {"id": 2, "last_modified_date": int(T0800.timestamp())},  # no name
        "not an actor",
    ],
)
def test_invalid_actor_is_skipped(invalid: Any) -> None:
    """Test that an invalid actor is skipped and the others are kept."""
    client = FakeIntel(ok([actor(1, T0800), invalid]))

    result = provider(client).get_data(since=T0800, limit=50)

    assert [item.actor.id for item in result[T0800]] == [1]


@pytest.mark.parametrize("status_code", [401, 403, 429, 500])
def test_actor_query_error_raises(status_code: int) -> None:
    """Test that an error status on the actor query raises with the status."""
    with pytest.raises(DataRetrievalError, match=f"status {status_code}"):
        provider(FakeIntel(error(status_code))).get_data(since=T0800, limit=50)


def test_mitre_query_error_raises() -> None:
    """Test that an error status on a MITRE query raises."""
    client = FakeIntel(ok([actor(1, T0800)]), mitre={"1": error(403)})

    with pytest.raises(DataRetrievalError, match="MITRE ATT&CK of actor 1"):
        provider(client).get_data(since=T0800, limit=50)


def test_client_exception_wrapped() -> None:
    """Test that a falconpy exception is wrapped with its cause."""
    cause = ConnectionError("network down")

    with pytest.raises(DataRetrievalError) as raised:
        provider(FakeIntel(cause)).get_data(since=T0800, limit=50)

    assert raised.value.__cause__ is cause


@pytest.mark.parametrize(
    "response", ["not a dict", {"status_code": 200, "body": {"resources": "x"}}]
)
def test_unexpected_response_raises(response: Any) -> None:
    """Test that a response of an unexpected shape raises."""
    with pytest.raises(DataRetrievalError, match="Unexpected"):
        provider(FakeIntel(response)).get_data(since=T0800, limit=50)


def test_naive_since_rejected() -> None:
    """Test that a naive `since` is rejected."""
    with pytest.raises(ValueError, match="timezone-aware"):
        provider(FakeIntel(ok([]))).get_data(since=datetime(2026, 10, 20), limit=50)


def test_more_actors_than_limit_on_one_date_keep_the_checkpoint() -> None:
    """Document that more than `limit` actors in one second stall the checkpoint.

    The API returns the first `limit` actors of that second on every call, so
    `max(result)` stays at `since` and the next call asks for the same actors.
    """
    same_second = [actor(i, T0800) for i in range(60)]

    class LimitedIntel(FakeIntel):
        def query_actor_entities(self, parameters: dict[str, Any]) -> Any:
            self.actor_calls.append(parameters)
            return ok(same_second[: parameters["limit"]])

    client = LimitedIntel(None)
    since = T0800
    for _ in range(3):
        result = provider(client).get_data(since=since, limit=50)
        since = max(result)

    assert since == T0800
    assert len(result[T0800]) == 50


def test_items_chain_with_converter() -> None:
    """Test that the provider items are accepted as is by the converter."""
    fixture = json.loads(FIXTURE.read_text())
    raw = {**fixture["actor"], "last_modified_date": int(T0800.timestamp())}
    client = FakeIntel(
        ok([raw]), mitre={str(raw["id"]): ok(fixture["mitre_attack_ids"])}
    )
    converter = CrowdStrikeActorConverter(
        author=OrganizationAuthor(name="CrowdStrike"),
        markings=[TLPMarking(level="amber")],
    )

    result = provider(client).get_data(since=T0800, limit=50)
    objects = [obj for item in result[T0800] for obj in converter.transform(item)]

    assert result[T0800][0].mitre_attack_ids == fixture["mitre_attack_ids"]
    assert objects
