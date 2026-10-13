"""
Regression tests for issue #6344: duplicate indicators caused by
``version_conflict_engine_exception`` (HTTP 409) during indicator deletion.

The fix makes ``create_indicator`` idempotent (deduplicate before insert) and
runs every ``_delete_by_query`` with ``conflicts=proceed`` so a version conflict
can no longer abort the deletion and leave stale duplicates behind.
"""

import pytest
import requests_mock as rm_module
from elastic_security_intel_connector.api_handler import ElasticApiHandler

ELASTIC_URL = "http://elastic.test:9200"
INDEX_NAME = "logs-ti_custom_opencti.indicator"
DELETE_URL = f"{ELASTIC_URL}/{INDEX_NAME}/_delete_by_query"
DOC_URL = f"{ELASTIC_URL}/{INDEX_NAME}/_doc"


class _Logger:
    def info(self, *args, **kwargs):
        pass

    debug = warning = error = info


class _Helper:
    connector_logger = _Logger()


class _Config:
    load = {}
    elastic_url = ELASTIC_URL
    elastic_api_key = "dummy"
    elastic_client_cert = None
    elastic_client_key = None
    elastic_ca_cert = None
    elastic_verify_ssl = False
    elastic_index_name = INDEX_NAME
    elastic_kibana_url = None
    elastic_opencti_external_url = "http://opencti.test"


@pytest.fixture
def handler():
    return ElasticApiHandler(_Helper(), _Config())


@pytest.fixture
def observable():
    opencti_id = "indicator--11111111-1111-4111-8111-111111111111"
    return {
        "id": opencti_id,
        "type": "indicator",
        "name": "evil.example.com",
        "pattern_type": "stix",
        "pattern": "[ipv4-addr:value = '198.51.100.42']",
        "confidence": 80,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "extensions": {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                "id": opencti_id
            }
        },
    }


@pytest.fixture
def requests_mock():
    with rm_module.Mocker() as m:
        yield m


def _delete_by_query_requests(mock):
    return [r for r in mock.request_history if r.path.endswith("/_delete_by_query")]


def _doc_requests(mock):
    return [r for r in mock.request_history if r.path.endswith("/_doc")]


def test_create_indicator_deduplicates_before_insert(
    handler, observable, requests_mock
):
    """A create must first delete any existing doc, so a replayed create event
    cannot accumulate duplicates."""
    requests_mock.post(DELETE_URL, json={"deleted": 1})
    requests_mock.post(
        DOC_URL, json={"_id": "abc", "result": "created"}, status_code=201
    )

    handler.create_indicator(observable)

    deletes = _delete_by_query_requests(requests_mock)
    docs = _doc_requests(requests_mock)
    assert len(deletes) == 1, "create_indicator must deduplicate before inserting"
    assert len(docs) == 1
    # deletion must happen before the insertion
    assert requests_mock.request_history.index(
        deletes[0]
    ) < requests_mock.request_history.index(docs[0])


def test_create_indicator_uses_conflicts_proceed(handler, observable, requests_mock):
    requests_mock.post(DELETE_URL, json={"deleted": 0})
    requests_mock.post(
        DOC_URL, json={"_id": "abc", "result": "created"}, status_code=201
    )

    handler.create_indicator(observable)

    delete = _delete_by_query_requests(requests_mock)[0]
    assert delete.qs.get("conflicts") == ["proceed"]


def test_update_indicator_deletes_then_recreates_with_proceed(
    handler, observable, requests_mock
):
    requests_mock.post(DELETE_URL, json={"deleted": 1})
    requests_mock.post(
        DOC_URL, json={"_id": "def", "result": "created"}, status_code=201
    )

    handler.update_indicator(observable)

    deletes = _delete_by_query_requests(requests_mock)
    docs = _doc_requests(requests_mock)
    assert len(deletes) == 1
    assert len(docs) == 1
    assert deletes[0].qs.get("conflicts") == ["proceed"]


def test_delete_indicator_uses_conflicts_proceed(handler, observable, requests_mock):
    requests_mock.post(DELETE_URL, json={"deleted": 1})

    assert handler.delete_indicator(observable) is True

    delete = _delete_by_query_requests(requests_mock)[0]
    assert delete.qs.get("conflicts") == ["proceed"]
    assert _doc_requests(requests_mock) == []


def test_delete_docs_by_opencti_id_query_targets_doc_id(handler, requests_mock):
    requests_mock.post(DELETE_URL, json={"deleted": 3})

    deleted = handler._delete_docs_by_opencti_id("some-doc-id")

    assert deleted == 3
    delete = _delete_by_query_requests(requests_mock)[0]
    body = delete.json()
    assert body["query"]["term"]["opencti_doc_id"] == "some-doc-id"
    assert delete.qs.get("conflicts") == ["proceed"]
