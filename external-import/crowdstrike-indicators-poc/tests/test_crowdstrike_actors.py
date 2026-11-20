"""Tests for the CrowdStrike actor enricher."""

import logging

import pytest
from conftest import (
    FakeActorsAPI,
    ScriptedActorsClient,
    filter_token,
    make_actor,
    ok,
)
from crowdstrike_indicators.entities.models import CrowdStrikeActor
from crowdstrike_indicators.extract.actors import (
    ACTOR_FIELDS,
    CrowdStrikeActorEnricher,
    name_filter,
    normalize,
)
from crowdstrike_indicators.extract.api import NO_ERROR_MESSAGE

from shared.errors import SourceAPIError


def _scripted(*resources_lists: list[dict]) -> ScriptedActorsClient:
    return ScriptedActorsClient(
        [ok({"errors": [], "resources": resources}) for resources in resources_lists]
    )


# --- The request -------------------------------------------------------------


def test_one_request_per_lookup_with_a_name_filter():
    client = _scripted([make_actor("SALTY SPIDER")])

    CrowdStrikeActorEnricher(client).extract("SALTYSPIDER")

    assert len(client.actor_calls) == 1
    assert client.actor_calls[0]["filter"] == "name:'SALTYSPIDER'"


def test_quote_in_the_token_is_escaped():
    client = _scripted([])

    CrowdStrikeActorEnricher(client).extract("O'BEAR")

    assert client.actor_calls[0]["filter"] == "name:'O\\'BEAR'"


@pytest.mark.parametrize("token", ["O'BEAR", "BACK\\SLASH", "A\\'B"])
def test_escaped_filter_round_trips(token):
    assert filter_token(name_filter(token)) == token


def test_requests_exactly_the_twelve_fields():
    client = _scripted([])

    CrowdStrikeActorEnricher(client).extract("SALTYSPIDER")

    fields = client.actor_calls[0]["fields"]
    assert sorted(fields) == sorted(
        [
            "id",
            "name",
            "slug",
            "url",
            "known_as",
            "description",
            "short_description",
            "first_activity_date",
            "last_activity_date",
            "motivations",
            "objectives",
            "actor_type",
        ]
    )
    assert list(fields) == list(ACTOR_FIELDS)
    assert "__basic__" not in fields and "__full__" not in fields


# --- Matching ----------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("SALTY SPIDER", "SALTYSPIDER"),
        ("salty-spider", "SALTYSPIDER"),
        ("Salty Spider", "SALTYSPIDER"),
        ("SALTYSPIDER", "SALTYSPIDER"),
    ],
)
def test_normalize(value, expected):
    assert normalize(value) == expected


def test_name_with_a_space_matches():
    actor = make_actor("SALTY SPIDER", actor_id=1, slug=None)

    result = CrowdStrikeActorEnricher(_scripted([actor])).extract("SALTYSPIDER")

    assert result == CrowdStrikeActor.model_validate(actor)


def test_slug_with_a_hyphen_matches_when_the_name_does_not():
    actor = make_actor("Wizard Spider Group", actor_id=2, slug="wizard-spider")

    result = CrowdStrikeActorEnricher(_scripted([actor])).extract("WIZARDSPIDER")

    assert result is not None and result.id == 2


def test_first_match_in_response_order_wins():
    first = make_actor("SALTY SPIDER", actor_id=1)
    second = make_actor("SALTY SPIDER", actor_id=2)

    result = CrowdStrikeActorEnricher(_scripted([first, second])).extract("SALTYSPIDER")

    assert result is not None and result.id == 1


def test_only_non_matching_results_give_none():
    other = make_actor("SALTY PANDA")

    assert CrowdStrikeActorEnricher(_scripted([other])).extract("SALTYSPIDER") is None


def test_empty_response_gives_none():
    assert CrowdStrikeActorEnricher(_scripted([])).extract("SALTYSPIDER") is None


def test_response_without_resources_gives_none():
    client = ScriptedActorsClient([ok({"errors": []})])

    assert CrowdStrikeActorEnricher(client).extract("SALTYSPIDER") is None


def test_undeclared_fields_are_kept():
    actor = make_actor("SALTY SPIDER", known_as="Salty", motivations=[{"id": 1}])

    result = CrowdStrikeActorEnricher(_scripted([actor])).extract("SALTYSPIDER")

    assert result is not None
    assert result.model_extra == {"known_as": "Salty", "motivations": [{"id": 1}]}


# --- Invalid actors ----------------------------------------------------------


def test_invalid_actor_before_a_valid_match_is_skipped(caplog):
    invalid = {"id": 9, "slug": "salty-spider"}
    valid = make_actor("SALTY SPIDER", actor_id=1)

    with caplog.at_level(
        logging.WARNING, logger="crowdstrike_indicators.extract.actors"
    ):
        result = CrowdStrikeActorEnricher(_scripted([invalid, valid])).extract(
            "SALTYSPIDER"
        )

    assert result is not None and result.id == 1
    assert "invalid actor" in caplog.text
    assert "name" in caplog.text


def test_only_invalid_actors_give_none():
    invalid = [{"id": 9, "slug": "salty-spider"}, {"name": "SALTY SPIDER"}]

    assert CrowdStrikeActorEnricher(_scripted(invalid)).extract("SALTYSPIDER") is None


# --- Errors and cache --------------------------------------------------------


def test_403_raises_with_its_message_and_nothing_is_cached():
    forbidden = {
        "status_code": 403,
        "headers": {},
        "body": {"errors": [{"code": 403, "message": "access denied"}]},
    }
    client = ScriptedActorsClient([forbidden, ok({"resources": []})])
    enricher = CrowdStrikeActorEnricher(client)

    with pytest.raises(SourceAPIError) as caught:
        enricher.extract("SALTYSPIDER")
    assert caught.value.status_code == 403
    assert caught.value.message == "access denied"

    enricher.extract("SALTYSPIDER")
    assert len(client.actor_calls) == 2


def test_error_without_a_message_gets_a_placeholder():
    client = ScriptedActorsClient([{"status_code": 500, "headers": {}, "body": {}}])

    with pytest.raises(SourceAPIError) as caught:
        CrowdStrikeActorEnricher(client).extract("SALTYSPIDER")

    assert caught.value.status_code == 500
    assert caught.value.message == NO_ERROR_MESSAGE


def test_status_that_is_not_an_integer_gives_status_zero():
    client = ScriptedActorsClient([{"headers": {}, "body": {"resources": []}}])

    with pytest.raises(SourceAPIError) as caught:
        CrowdStrikeActorEnricher(client).extract("SALTYSPIDER")

    assert caught.value.status_code == 0


def test_miss_and_hit_are_cached():
    api = FakeActorsAPI([make_actor("SALTY SPIDER")])
    enricher = CrowdStrikeActorEnricher(api)

    for _ in range(3):
        enricher.extract("SALTYSPIDER")
        enricher.extract("NOSUCHACTOR")

    assert api.tokens == ["SALTYSPIDER", "NOSUCHACTOR"]
