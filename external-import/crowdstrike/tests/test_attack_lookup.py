"""Tests for AttackTechniqueLookup dataset retrieval."""

import json
from unittest.mock import patch

import pytest
import requests
from crowdstrike_feeds_services.utils.attack_lookup import (
    DEFAULT_ATTACK_URL,
    AttackTechniqueLookup,
    AttackTechniqueLookupError,
    CustomAttackTechniqueLookup,
    GithubAttackTechniqueLookup,
    StixBundleEnvelope,
)
from pydantic import ValidationError

VERSION = "17.1"
VERSIONED_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/"
    f"enterprise-attack/enterprise-attack-{VERSION}.json"
)
CUSTOM_URL = "https://example.com/enterprise-attack.json"

BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Command and Scripting Interpreter",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059"}
            ],
        }
    ],
}


def make_response(status_code: int, content: bytes) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response._content = content
    return response


def ok() -> requests.Response:
    return make_response(200, json.dumps(BUNDLE).encode())


def not_found() -> requests.Response:
    return make_response(404, b"404: Not Found")


@pytest.fixture
def mock_get():
    with patch(
        "crowdstrike_feeds_services.utils.json_retriever.requests.get"
    ) as mock_get:
        yield mock_get


def requested_urls(mock_get) -> list[str]:
    return [call.args[0] for call in mock_get.call_args_list]


def test_lookup_tries_the_given_urls_in_order(mock_get):
    mock_get.side_effect = [not_found(), ok()]

    lookup = AttackTechniqueLookup(retrieval_urls=[CUSTOM_URL, DEFAULT_ATTACK_URL])

    assert [r.url for r in lookup.retrievers] == [CUSTOM_URL, DEFAULT_ATTACK_URL]
    assert requested_urls(mock_get) == [CUSTOM_URL, DEFAULT_ATTACK_URL]
    assert lookup.enterprise_attack_url == DEFAULT_ATTACK_URL


def test_github_lookup_tries_versioned_then_generic_dataset(mock_get):
    mock_get.return_value = ok()

    lookup = GithubAttackTechniqueLookup(attack_version=VERSION)

    assert [r.url for r in lookup.retrievers] == [VERSIONED_URL, DEFAULT_ATTACK_URL]


def test_custom_lookup_tries_only_the_custom_url(mock_get):
    mock_get.return_value = ok()

    lookup = CustomAttackTechniqueLookup(enterprise_attack_url=CUSTOM_URL)

    assert [r.url for r in lookup.retrievers] == [CUSTOM_URL]
    assert lookup.enterprise_attack_url == CUSTOM_URL


def test_versioned_dataset_is_used_when_available(mock_get):
    mock_get.return_value = ok()

    lookup = GithubAttackTechniqueLookup(attack_version=VERSION)

    assert requested_urls(mock_get) == [VERSIONED_URL]
    assert lookup.enterprise_attack_url == VERSIONED_URL
    assert lookup.lookup_mitre_id("Command and Scripting Interpreter") == "T1059"
    assert lookup.retrieval_errors == []


def test_missing_versioned_dataset_falls_back_to_generic_dataset(mock_get):
    mock_get.side_effect = [not_found(), ok()]

    lookup = GithubAttackTechniqueLookup(attack_version=VERSION)

    assert requested_urls(mock_get) == [VERSIONED_URL, DEFAULT_ATTACK_URL]
    assert lookup.enterprise_attack_url == DEFAULT_ATTACK_URL
    assert lookup.lookup_mitre_id("Command and Scripting Interpreter") == "T1059"
    assert len(lookup.retrieval_errors) == 1
    assert VERSIONED_URL in lookup.retrieval_errors[0]
    assert "HTTP 404" in lookup.retrieval_errors[0]


def test_invalid_versioned_payload_falls_back_to_generic_dataset(mock_get):
    mock_get.side_effect = [make_response(200, b"<html></html>"), ok()]

    lookup = GithubAttackTechniqueLookup(attack_version=VERSION)

    assert lookup.enterprise_attack_url == DEFAULT_ATTACK_URL


def test_failed_fallback_raises_lookup_error(mock_get):
    mock_get.side_effect = [not_found(), requests.ConnectionError("unreachable")]

    with pytest.raises(AttackTechniqueLookupError) as exc_info:
        GithubAttackTechniqueLookup(attack_version=VERSION)

    assert "HTTP 404" in str(exc_info.value)
    assert "unreachable" in str(exc_info.value)


def test_failed_custom_url_raises_lookup_error_without_fallback(mock_get):
    mock_get.side_effect = requests.ConnectionError("unreachable")

    with pytest.raises(AttackTechniqueLookupError, match="unreachable"):
        CustomAttackTechniqueLookup(enterprise_attack_url=CUSTOM_URL)

    assert requested_urls(mock_get) == [CUSTOM_URL]


def test_bundle_envelope_allows_extra_fields():
    bundle = StixBundleEnvelope.model_validate(
        {
            "type": "bundle",
            "id": "bundle--1",
            "objects": [{"type": "attack-pattern", "name": "Phishing"}],
        }
    )

    assert bundle.model_extra == {"id": "bundle--1"}
    assert bundle.objects[0].type == "attack-pattern"
    assert bundle.objects[0].model_extra == {"name": "Phishing"}


def test_bundle_envelope_accepts_empty_objects():
    bundle = StixBundleEnvelope.model_validate({"type": "bundle", "objects": []})

    assert bundle.objects == []


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"objects": []},
        {"type": "report", "objects": []},
        {"type": "bundle"},
        {"type": "bundle", "objects": {}},
        {"type": "bundle", "objects": ["attack-pattern"]},
        {"type": "bundle", "objects": [{"name": "Phishing"}]},
        {"type": "bundle", "objects": [{"type": 1}]},
    ],
)
def test_bundle_envelope_rejects_invalid_envelope(payload):
    with pytest.raises(ValidationError):
        StixBundleEnvelope.model_validate(payload)


def test_payload_that_is_not_a_bundle_falls_back_to_next_url(mock_get):
    mock_get.side_effect = [make_response(200, b"[]"), ok()]

    lookup = GithubAttackTechniqueLookup(attack_version=VERSION)

    assert lookup.enterprise_attack_url == DEFAULT_ATTACK_URL
    assert lookup.lookup_mitre_id("Command and Scripting Interpreter") == "T1059"
    assert len(lookup.retrieval_errors) == 1
    assert f"Payload from {VERSIONED_URL} is not a STIX bundle" in (
        lookup.retrieval_errors[0]
    )


def test_payload_that_is_not_a_bundle_raises_lookup_error(mock_get):
    mock_get.return_value = make_response(
        200, json.dumps({"type": "report", "objects": []}).encode()
    )

    with pytest.raises(AttackTechniqueLookupError) as exc_info:
        CustomAttackTechniqueLookup(enterprise_attack_url=CUSTOM_URL)

    message = str(exc_info.value)
    assert "is not a STIX bundle" in message
    assert "type:" in message
    assert "\n" not in message


def test_bundle_without_attack_patterns_gives_empty_lookup(mock_get):
    mock_get.return_value = make_response(
        200, json.dumps({"type": "bundle", "objects": [{"type": "x"}]}).encode()
    )

    lookup = AttackTechniqueLookup(retrieval_urls=[CUSTOM_URL])

    assert lookup.attack_techniques == {}
