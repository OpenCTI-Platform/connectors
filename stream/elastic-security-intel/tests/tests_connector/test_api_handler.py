"""
Regression tests for issue #6344: duplicate indicators caused by
``version_conflict_engine_exception`` (HTTP 409) during indicator deletion.

The fix makes ``create_indicator`` idempotent (the other copies are deleted once
the new document is stored, so a failed write keeps the previous one) and runs
every ``_delete_by_query`` with ``conflicts=proceed`` so a version conflict can no
longer abort the deletion and leave stale duplicates behind.
"""

from urllib.parse import parse_qs, urlparse

import pytest
import requests_mock as rm_module
from elastic_security_intel_connector.api_handler import (
    ElasticApiHandler,
    ElasticApiHandlerError,
)

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


@pytest.mark.parametrize("write", ["create_indicator", "update_indicator"])
def test_a_write_stores_the_document_then_deletes_the_other_copies(
    handler, observable, requests_mock, write
):
    """A replayed create cannot accumulate duplicates, and the previous document
    stays until the new one is stored."""
    requests_mock.post(DELETE_URL, json={"deleted": 1})
    requests_mock.post(
        DOC_URL, json={"_id": "abc", "result": "created"}, status_code=201
    )

    assert getattr(handler, write)(observable)["id"] == "abc"

    (delete,) = _delete_by_query_requests(requests_mock)
    (doc,) = _doc_requests(requests_mock)
    history = requests_mock.request_history
    assert history.index(doc) < history.index(delete)
    assert delete.json()["query"]["bool"] == {
        "filter": [{"term": {"opencti_doc_id": doc.json()["opencti_doc_id"]}}],
        "must_not": [{"ids": {"values": ["abc"]}}],
    }


@pytest.mark.parametrize("write", ["create_indicator", "update_indicator"])
def test_a_failed_write_keeps_the_previous_document(
    handler, observable, requests_mock, write
):
    requests_mock.post(DELETE_URL, json={"deleted": 1})
    requests_mock.post(DOC_URL, status_code=500, text="boom")

    with pytest.raises(ElasticApiHandlerError):
        getattr(handler, write)(observable)
    assert _delete_by_query_requests(requests_mock) == []


def test_a_failed_cleanup_after_a_stored_write_is_not_a_failed_write(
    handler, observable, requests_mock
):
    """The object is written; the remaining copies are deleted by its next write."""
    requests_mock.post(DELETE_URL, status_code=500, text="busy")
    requests_mock.post(
        DOC_URL, json={"_id": "abc", "result": "created"}, status_code=201
    )

    assert handler.update_indicator(observable)["id"] == "abc"


def test_create_indicator_uses_conflicts_proceed(handler, observable, requests_mock):
    requests_mock.post(DELETE_URL, json={"deleted": 0})
    requests_mock.post(
        DOC_URL, json={"_id": "abc", "result": "created"}, status_code=201
    )

    handler.create_indicator(observable)

    delete = _delete_by_query_requests(requests_mock)[0]
    assert delete.qs.get("conflicts") == ["proceed"]


def test_update_indicator_recreates_then_deletes_with_proceed(
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


KIBANA_URL = "http://kibana.test:5601"
RULES_URL = f"{KIBANA_URL}/api/detection_engine/rules"
FIND_RULES_URL = f"{RULES_URL}/_find"


class _KibanaConfig(_Config):
    elastic_kibana_url = KIBANA_URL


@pytest.fixture
def kibana_handler():
    return ElasticApiHandler(_Helper(), _KibanaConfig())


@pytest.fixture
def native_indicator(observable):
    return {**observable, "pattern_type": "kql", "pattern": "dns.question.name : x"}


def test_delete_removes_the_siem_rule_found_on_kibana(
    kibana_handler, native_indicator, requests_mock
):
    requests_mock.get(FIND_RULES_URL, json={"data": [{"id": "rule-1"}]})
    requests_mock.delete(RULES_URL, json={"id": "rule-1"})
    requests_mock.post(DELETE_URL, json={"deleted": 1})

    assert kibana_handler.process_indicator(native_indicator, "delete") is True

    deletion = next(r for r in requests_mock.request_history if r.method == "DELETE")
    assert deletion.qs.get("id") == ["rule-1"]


def test_delete_without_siem_rule_succeeds(
    kibana_handler, native_indicator, requests_mock
):
    requests_mock.get(FIND_RULES_URL, json={"data": []})
    requests_mock.post(DELETE_URL, json={"deleted": 1})

    assert kibana_handler.process_indicator(native_indicator, "delete") is True
    assert not [r for r in requests_mock.request_history if r.method == "DELETE"]


def test_delete_fails_when_the_siem_rule_remains(
    kibana_handler, native_indicator, requests_mock
):
    """A rule that could not be deleted keeps detecting: the deletion failed and
    the threat intel document stays, so the next removal retries the rule."""
    requests_mock.get(FIND_RULES_URL, json={"data": [{"id": "rule-1"}]})
    requests_mock.delete(RULES_URL, status_code=500, text="boom")
    requests_mock.post(DELETE_URL, json={"deleted": 1})

    assert kibana_handler.process_indicator(native_indicator, "delete") is False
    assert _delete_by_query_requests(requests_mock) == []

    requests_mock.delete(RULES_URL, json={"id": "rule-1"})

    assert kibana_handler.process_indicator(native_indicator, "delete") is True
    assert len(_delete_by_query_requests(requests_mock)) == 1


def test_delete_fails_when_the_siem_rule_lookup_fails(
    kibana_handler, native_indicator, requests_mock
):
    requests_mock.get(FIND_RULES_URL, status_code=503, text="unavailable")
    requests_mock.post(DELETE_URL, json={"deleted": 1})

    assert kibana_handler.process_indicator(native_indicator, "delete") is False
    assert _delete_by_query_requests(requests_mock) == []


def _query(request):
    return parse_qs(urlparse(request.url).query)


def _rule_requests(mock, method):
    return [
        r
        for r in mock.request_history
        if r.method == method and r.path.endswith("/api/detection_engine/rules")
    ]


def test_siem_rule_lookup_matches_the_rule_parameters_and_reads_every_page(
    kibana_handler, native_indicator, requests_mock
):
    """Rule parameters live under alert.attributes.params: the lookup matches the
    reference written at creation, or the meta.opencti_id, on every page."""
    requests_mock.get(
        FIND_RULES_URL,
        [
            {"json": {"data": [{"id": "rule-1"}], "total": 2}},
            {"json": {"data": [{"id": "rule-2"}], "total": 2}},
        ],
    )
    opencti_id = native_indicator["id"]

    assert kibana_handler._find_siem_rule_ids(opencti_id) == ["rule-1", "rule-2"]

    first, second = requests_mock.request_history
    assert _query(first)["filter"] == [
        "alert.attributes.params.references:"
        f'"http://opencti.test/dashboard/id/{opencti_id}"'
        f' or alert.attributes.params.meta.opencti_id:"{opencti_id}"'
    ]
    assert _query(first)["page"] == ["1"]
    assert _query(second)["page"] == ["2"]


def test_siem_rule_lookup_raises_on_errors(kibana_handler, requests_mock):
    requests_mock.get(FIND_RULES_URL, status_code=503, text="unavailable")

    with pytest.raises(Exception):
        kibana_handler._find_siem_rule_ids("indicator--x")


def test_delete_removes_every_siem_rule_of_the_indicator(
    kibana_handler, native_indicator, requests_mock
):
    requests_mock.get(FIND_RULES_URL, json={"data": [{"id": "a"}, {"id": "b"}]})
    requests_mock.delete(RULES_URL, json={})
    requests_mock.post(DELETE_URL, json={"deleted": 1})

    assert kibana_handler.process_indicator(native_indicator, "delete") is True
    assert [_query(r)["id"] for r in _rule_requests(requests_mock, "DELETE")] == [
        ["a"],
        ["b"],
    ]


@pytest.mark.parametrize(
    "pattern_type, rule_type, language, has_index",
    [
        ("kql", "query", "kuery", True),
        ("lucene", "query", "lucene", True),
        ("eql", "eql", "eql", True),
        ("esql", "esql", "esql", False),
    ],
)
def test_create_writes_the_siem_rule_then_the_threat_intel_document(
    kibana_handler,
    native_indicator,
    requests_mock,
    pattern_type,
    rule_type,
    language,
    has_index,
):
    requests_mock.get(FIND_RULES_URL, json={"data": [], "total": 0})
    requests_mock.post(RULES_URL, json={"id": "rule-1"})
    requests_mock.post(DELETE_URL, json={"deleted": 0})
    requests_mock.post(DOC_URL, json={"_id": "abc", "result": "created"})
    indicator = {**native_indicator, "pattern_type": pattern_type}

    assert kibana_handler.process_indicator(indicator, "create") is True

    rule = _rule_requests(requests_mock, "POST")[0].json()
    assert (rule["type"], rule["language"]) == (rule_type, language)
    assert ("index" in rule) is has_index
    assert rule["references"] == [f"http://opencti.test/dashboard/id/{indicator['id']}"]
    assert len(_doc_requests(requests_mock)) == 1


@pytest.mark.parametrize(
    "find, create",
    [
        ({"status_code": 503, "text": "unavailable"}, None),
        ({"json": {"data": [], "total": 0}}, {"status_code": 400, "text": "bad"}),
    ],
    ids=["lookup failed", "creation refused"],
)
def test_create_fails_without_a_threat_intel_document_when_the_rule_is_not_written(
    kibana_handler, native_indicator, requests_mock, find, create
):
    """A threat intel document without its rule would be read back as active."""
    requests_mock.get(FIND_RULES_URL, **find)
    if create is not None:
        requests_mock.post(RULES_URL, **create)

    assert kibana_handler.process_indicator(native_indicator, "create") is False
    assert _doc_requests(requests_mock) == []
    assert _delete_by_query_requests(requests_mock) == []


@pytest.mark.parametrize("operation", ["create", "update"])
def test_existing_siem_rules_are_updated_instead_of_created_again(
    kibana_handler, native_indicator, requests_mock, operation
):
    """A replayed or pushed again indicator updates its rules (partial update)."""
    requests_mock.get(FIND_RULES_URL, json={"data": [{"id": "rule-1"}], "total": 1})
    requests_mock.patch(RULES_URL, json={"id": "rule-1"})
    requests_mock.post(DELETE_URL, json={"deleted": 1})
    requests_mock.post(DOC_URL, json={"_id": "abc", "result": "created"})

    assert kibana_handler.process_indicator(native_indicator, operation) is True

    assert _rule_requests(requests_mock, "POST") == []
    patch = _rule_requests(requests_mock, "PATCH")[0].json()
    assert patch["id"] == "rule-1"
    assert patch["query"] == native_indicator["pattern"]
    assert len(_doc_requests(requests_mock)) == 1


def test_update_leaves_the_threat_intel_document_when_the_rule_update_fails(
    kibana_handler, native_indicator, requests_mock
):
    requests_mock.get(FIND_RULES_URL, json={"data": [{"id": "rule-1"}], "total": 1})
    requests_mock.patch(RULES_URL, status_code=500, text="boom")

    assert kibana_handler.process_indicator(native_indicator, "update") is False
    assert _doc_requests(requests_mock) == []
    assert _delete_by_query_requests(requests_mock) == []


@pytest.mark.parametrize("rollback_status", [200, 500])
def test_a_rule_created_for_a_document_not_written_is_deleted_again(
    kibana_handler, native_indicator, requests_mock, rollback_status
):
    """A rule without its threat intel entry would detect unseen by the read-back."""
    requests_mock.get(FIND_RULES_URL, json={"data": [], "total": 0})
    requests_mock.post(RULES_URL, json={"id": "rule-1"})
    requests_mock.delete(RULES_URL, status_code=rollback_status, json={})
    requests_mock.post(DOC_URL, status_code=500, text="boom")

    assert kibana_handler.process_indicator(native_indicator, "create") is False

    (rollback,) = _rule_requests(requests_mock, "DELETE")
    assert _query(rollback)["id"] == ["rule-1"]


PREVIOUS_RULE = {
    "id": "rule-1",
    "name": "OpenCTI: previous name",
    "description": "Previous description",
    "risk_score": 21,
    "severity": "low",
    "query": "dns.question.name : previous",
    "language": "kuery",
    "enabled": True,
}
PREVIOUS_RULE_2 = {**PREVIOUS_RULE, "id": "rule-2", "query": "dns.question.name : two"}


def _restorable(rule):
    return {key: value for key, value in rule.items() if key != "enabled"}


def test_updated_rules_get_their_previous_definition_when_the_document_fails(
    kibana_handler, native_indicator, requests_mock
):
    """Existing rules are not deleted: they get back the definition matching the
    previous document, kept, so the read-back never sees a half-applied update."""
    requests_mock.get(FIND_RULES_URL, json={"data": [PREVIOUS_RULE], "total": 1})
    requests_mock.patch(RULES_URL, json={"id": "rule-1"})
    requests_mock.post(DOC_URL, status_code=500, text="boom")

    assert kibana_handler.process_indicator(native_indicator, "update") is False
    assert _rule_requests(requests_mock, "DELETE") == []
    assert _delete_by_query_requests(requests_mock) == []
    update, restore = _rule_requests(requests_mock, "PATCH")
    assert update.json()["query"] == native_indicator["pattern"]
    assert restore.json() == _restorable(PREVIOUS_RULE)


def test_a_failed_rule_update_restores_the_rules_already_updated(
    kibana_handler, native_indicator, requests_mock
):
    """All or nothing: the second rule refuses the update, the first one gets its
    previous definition back and no threat intel document is written."""
    requests_mock.get(
        FIND_RULES_URL, json={"data": [PREVIOUS_RULE, PREVIOUS_RULE_2], "total": 2}
    )
    requests_mock.patch(
        RULES_URL,
        [
            {"json": {"id": "rule-1"}},
            {"status_code": 500, "text": "boom"},
            {"json": {"id": "rule-1"}},
        ],
    )

    assert kibana_handler.process_indicator(native_indicator, "update") is False
    first, second, restore = _rule_requests(requests_mock, "PATCH")
    assert (first.json()["id"], second.json()["id"]) == ("rule-1", "rule-2")
    assert restore.json() == _restorable(PREVIOUS_RULE)
    assert _doc_requests(requests_mock) == []


def test_a_failed_rule_restore_is_logged(
    kibana_handler, native_indicator, requests_mock
):
    requests_mock.get(FIND_RULES_URL, json={"data": [PREVIOUS_RULE], "total": 1})
    requests_mock.patch(
        RULES_URL,
        [{"json": {"id": "rule-1"}}, {"status_code": 503, "text": "unavailable"}],
    )
    requests_mock.post(DOC_URL, status_code=500, text="boom")

    assert kibana_handler.process_indicator(native_indicator, "update") is False
    assert len(_rule_requests(requests_mock, "PATCH")) == 2


def test_delete_docs_by_opencti_id_query_targets_doc_id(handler, requests_mock):
    requests_mock.post(DELETE_URL, json={"deleted": 3})

    deleted = handler._delete_docs_by_opencti_id("some-doc-id")

    assert deleted == 3
    delete = _delete_by_query_requests(requests_mock)[0]
    body = delete.json()
    assert body["query"]["term"]["opencti_doc_id"] == "some-doc-id"
    assert delete.qs.get("conflicts") == ["proceed"]
