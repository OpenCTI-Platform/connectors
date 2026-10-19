"""
Regression tests for issue #8001: the OpenCTI live stream only carries the score
inside the STIX extensions, so it must be read from there and forwarded to
Elastic, both in the threat intel document and in the SIEM rule body.
"""

import pytest
import requests_mock as rm_module
from elastic_security_intel_connector.api_handler import ElasticApiHandler

ELASTIC_URL = "http://elastic.test:9200"
INDEX_NAME = "logs-ti_custom_opencti.indicator"
DELETE_URL = f"{ELASTIC_URL}/{INDEX_NAME}/_delete_by_query"
DOC_URL = f"{ELASTIC_URL}/{INDEX_NAME}/_doc"
RULES_URL = f"{ELASTIC_URL}/api/detection_engine/rules"
FIND_RULES_URL = f"{RULES_URL}/_find"
TEMPLATE_URL = f"{ELASTIC_URL}/_index_template/logs-ti_custom_opencti"

INDICATOR_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
OBSERVABLE_EXTENSION = "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"


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


def make_indicator(score=None, pattern_type="stix", confidence=10):
    opencti_id = "indicator--11111111-1111-4111-8111-111111111111"
    extension = {"id": opencti_id}
    if score is not None:
        extension["score"] = score
    pattern = (
        "source.ip : 198.51.100.42"
        if pattern_type == "kql"
        else "[ipv4-addr:value = '198.51.100.42']"
    )
    return {
        "id": opencti_id,
        "type": "indicator",
        "name": "198.51.100.42",
        "pattern_type": pattern_type,
        "pattern": pattern,
        "confidence": confidence,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "extensions": {INDICATOR_EXTENSION: extension},
    }


def make_observable(score=None):
    opencti_id = "ipv4-addr--22222222-2222-4222-8222-222222222222"
    extension = {"id": opencti_id}
    if score is not None:
        extension["score"] = score
    return {
        "id": opencti_id,
        "type": "ipv4-addr",
        "value": "198.51.100.42",
        "extensions": {OBSERVABLE_EXTENSION: extension},
    }


@pytest.fixture
def handler():
    return ElasticApiHandler(_Helper(), _Config())


@pytest.fixture
def requests_mock():
    with rm_module.Mocker() as m:
        m.post(DELETE_URL, json={"deleted": 0})
        m.post(DOC_URL, json={"_id": "abc", "result": "created"}, status_code=201)
        yield m


def _sent_doc(mock):
    return [r for r in mock.request_history if r.path.endswith("/_doc")][-1].json()


def _sent_rule(mock):
    return [
        r
        for r in mock.request_history
        if r.path.endswith("/api/detection_engine/rules")
    ][-1].json()


def test_create_indicator_should_send_score_when_score_is_in_indicator_extension(
    handler, requests_mock
):
    indicator = make_indicator(score=85)

    handler.create_indicator(indicator)

    doc = _sent_doc(requests_mock)
    assert doc["opencti"]["indicator"]["score"] == 85
    assert "sightings" not in doc["threat"]["indicator"]


def test_create_indicator_should_send_score_when_score_is_in_observable_extension(
    handler, requests_mock
):
    observable = make_observable(score=72)

    handler.create_indicator(observable)

    assert _sent_doc(requests_mock)["opencti"]["indicator"]["score"] == 72


def test_update_indicator_should_send_score(handler, requests_mock):
    indicator = make_indicator(score=30)

    handler.update_indicator(indicator)

    assert _sent_doc(requests_mock)["opencti"]["indicator"]["score"] == 30


def test_create_indicator_should_omit_score_when_score_is_missing(
    handler, requests_mock
):
    indicator = make_indicator(score=None)

    handler.create_indicator(indicator)

    doc = _sent_doc(requests_mock)
    assert "opencti" not in doc
    assert "sightings" not in doc["threat"]["indicator"]


def test_create_siem_rule_should_derive_risk_and_severity_from_score(
    handler, requests_mock
):
    requests_mock.post(RULES_URL, json={"id": "rule-1"}, status_code=200)
    indicator = make_indicator(score=85, pattern_type="kql", confidence=10)

    handler._create_siem_rule(indicator)

    rule = _sent_rule(requests_mock)
    assert rule["risk_score"] == 85
    assert rule["severity"] == "critical"


def test_update_siem_rule_should_derive_risk_and_severity_from_score(
    handler, requests_mock
):
    requests_mock.put(RULES_URL, json={"id": "rule-1"}, status_code=200)
    indicator = make_indicator(score=45, pattern_type="kql", confidence=90)

    handler._update_siem_rule(indicator, "rule-1")

    rule = _sent_rule(requests_mock)
    assert rule["risk_score"] == 45
    assert rule["severity"] == "medium"


def test_create_siem_rule_should_use_default_score_when_score_is_missing(
    handler, requests_mock
):
    requests_mock.post(RULES_URL, json={"id": "rule-1"}, status_code=200)
    indicator = make_indicator(score=None, pattern_type="kql", confidence=90)

    handler._create_siem_rule(indicator)

    rule = _sent_rule(requests_mock)
    assert rule["risk_score"] == 50
    assert rule["severity"] == "medium"


def test_process_indicator_update_should_send_score_to_rule_and_document(
    handler, requests_mock
):
    requests_mock.get(FIND_RULES_URL, json={"data": [{"id": "rule-1"}]})
    requests_mock.put(RULES_URL, json={"id": "rule-1"}, status_code=200)
    indicator = make_indicator(score=65, pattern_type="kql")

    assert handler.process_indicator(indicator, "update") is True

    assert _sent_rule(requests_mock)["risk_score"] == 65
    assert _sent_rule(requests_mock)["severity"] == "high"
    assert _sent_doc(requests_mock)["opencti"]["indicator"]["score"] == 65


@pytest.mark.parametrize(
    "score, expected_risk, expected_severity",
    [(0, 0, "low"), (39, 39, "low"), (60, 60, "high"), (150, 100, "critical")],
)
def test_rule_score_should_be_clamped_and_mapped_to_severity(
    handler, score, expected_risk, expected_severity
):
    indicator = make_indicator(score=score)

    assert handler._calculate_risk_score(indicator) == expected_risk
    assert handler._get_severity(indicator) == expected_severity


@pytest.mark.parametrize("score", ["high", True, None])
def test_rule_score_should_use_default_when_score_is_not_a_number(handler, score):
    indicator = make_indicator()
    indicator["extensions"][INDICATOR_EXTENSION]["score"] = score

    assert handler._calculate_risk_score(indicator) == 50


def test_index_template_should_map_score_as_long(handler, requests_mock):
    requests_mock.get(TEMPLATE_URL, status_code=404)
    requests_mock.put(TEMPLATE_URL, json={"acknowledged": True})

    handler.setup_index_template()

    template = requests_mock.request_history[-1].json()
    properties = template["template"]["mappings"]["properties"]
    assert properties["opencti"]["properties"]["indicator"]["properties"]["score"] == {
        "type": "long"
    }
