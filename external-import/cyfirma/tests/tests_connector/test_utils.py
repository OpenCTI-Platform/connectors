"""Unit tests for connector.utils."""

import uuid

import pytest
from connector.utils import (
    _IOC_GENERIC_PATH,
    _IOC_TAILORED_PATH,
    _TA_SEARCH_PATH,
    _VUL_GENERIC_PATH,
    _VUL_PATH,
    _VUL_TAILORED_PATH,
    CYFIRMA_EXTENSION_DEFINITION_ID,
    CYFIRMA_INDICATOR_EXTENSION_DEFINITION_ID,
    OPENCTI_EXTENSION_DEFINITION_ID,
    get_request_headers,
    get_request_params,
)

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #


def test_api_paths():
    base = "/api/ex/v3/da/stix/2.1"

    assert _IOC_TAILORED_PATH == f"{base}/indicators/tailored"
    assert _IOC_GENERIC_PATH == f"{base}/indicators/all"
    assert _VUL_PATH == f"{base}/vulnerabilities"
    assert _VUL_TAILORED_PATH == f"{base}/vulnerabilities/tailored"
    assert _VUL_GENERIC_PATH == f"{base}/vulnerabilities/all"
    assert _TA_SEARCH_PATH == f"{base}/threat-actors/search"


def test_extension_definition_ids_are_distinct_and_well_formed():
    ids = [
        OPENCTI_EXTENSION_DEFINITION_ID,
        CYFIRMA_EXTENSION_DEFINITION_ID,
        CYFIRMA_INDICATOR_EXTENSION_DEFINITION_ID,
    ]

    assert len(set(ids)) == 3
    for ext_id in ids:
        prefix, _, raw_uuid = ext_id.partition("--")
        assert prefix == "extension-definition"
        assert str(uuid.UUID(raw_uuid)) == raw_uuid


# --------------------------------------------------------------------------- #
# get_request_headers
# --------------------------------------------------------------------------- #


def test_get_request_headers():
    headers = get_request_headers("my-key")

    assert headers["X-Api-Key"] == "my-key"
    assert headers["X-App-Name"] == "OPEN_CTI_CONNECTOR_V1"
    assert str(uuid.UUID(headers["X-Request-Id"])) == headers["X-Request-Id"]
    assert set(headers) == {"X-Api-Key", "X-App-Name", "X-Request-Id"}


def test_get_request_headers_generates_new_request_id_each_call():
    first = get_request_headers("k")["X-Request-Id"]
    second = get_request_headers("k")["X-Request-Id"]

    assert first != second


# --------------------------------------------------------------------------- #
# get_request_params
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("last_run", ["", None])
def test_get_request_params_first_run_uses_look_back(last_run):
    params = get_request_params(look_back_days=7, last_run=last_run)

    assert params == {
        "withRelationships": "true",
        "page": 0,
        "lookBackDays": 7,
        "delta": "false",
    }


def test_get_request_params_subsequent_run_uses_delta():
    params = get_request_params(look_back_days=7, last_run="2026-01-01 00:00:00")

    assert params == {
        "withRelationships": "true",
        "page": 0,
        "delta": "true",
    }
    assert "lookBackDays" not in params


def test_get_request_params_returns_independent_dicts():
    # _fetch_all_pages mutates params["page"], so each call must return a new dict
    first = get_request_params(3, "")
    second = get_request_params(3, "")

    first["page"] = 5

    assert second["page"] == 0
