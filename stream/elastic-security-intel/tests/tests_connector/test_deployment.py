"""Deployment write-back of the Elastic Security Intel connector (OpenCTI-Platform/opencti#18680)."""

from unittest.mock import MagicMock

import pytest
import requests
import requests_mock as rm_module
from connectors_sdk import DeploymentAssurance
from connectors_sdk.connectors.stream.deployment import OPENCTI_EXTENSION_ID
from elastic_security_intel_connector import api_handler as api_module
from elastic_security_intel_connector.api_handler import (
    ElasticApiHandler,
    ElasticApiHandlerError,
)
from elastic_security_intel_connector.connector import ElasticSecurityIntelConnector
from elastic_security_intel_connector.deployment import (
    PUSH_FAILED_MESSAGE,
    REMOVE_FAILED_MESSAGE,
    ElasticDeploymentAdapter,
    ElasticDeploymentError,
    build_deployment_assurance,
    describe_error,
)

ELASTIC_URL = "http://elastic.test:9200"
INDEX_NAME = "logs-ti_custom_opencti.indicator"
PIT_URL = f"{ELASTIC_URL}/{INDEX_NAME}/_pit"
SEARCH_URL = f"{ELASTIC_URL}/_search"
CLOSE_PIT_URL = f"{ELASTIC_URL}/_pit"
INDICATOR_ID = "indicator--11111111-1111-4111-8111-111111111111"


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


def stix_indicator(opencti_id: str = INDICATOR_ID, type_: str = "indicator") -> dict:
    return {
        "id": opencti_id,
        "type": type_,
        "pattern_type": "stix",
        "pattern": "[ipv4-addr:value = '198.51.100.42']",
        "extensions": {OPENCTI_EXTENSION_ID: {"id": opencti_id}},
    }


def document(stix: dict, valid_until: str | None = None) -> dict:
    source = {"opencti_doc_id": f"doc-{stix['id']}", "stix": stix}
    if valid_until is not None:
        source["threat"] = {"indicator": {"valid_until": valid_until}}
    return {"_source": source, "sort": [len(stix["id"])]}


@pytest.fixture
def handler():
    return ElasticApiHandler(_Helper(), _Config())


@pytest.fixture
def connector(handler):
    instance = ElasticSecurityIntelConnector.__new__(ElasticSecurityIntelConnector)
    instance.api = handler
    instance.helper = MagicMock()
    instance.config = MagicMock(load={})
    instance.assurance = MagicMock(spec=DeploymentAssurance)
    return instance


class TestReadBack:
    def test_no_data_stream_yet_lists_nothing(self, handler):
        with rm_module.Mocker() as m:
            m.post(PIT_URL, status_code=404)
            assert list(handler.iter_connector_documents()) == []

    def test_pages_through_a_point_in_time_and_closes_it(self, handler, monkeypatch):
        monkeypatch.setattr(api_module, "READ_BACK_PAGE_SIZE", 2)
        first = [
            document(stix_indicator("indicator--a")),
            document(stix_indicator("indicator--b")),
        ]
        second = [document(stix_indicator("indicator--c"))]
        with rm_module.Mocker() as m:
            m.post(PIT_URL, json={"id": "pit-1"})
            search = m.post(
                SEARCH_URL,
                [
                    {"json": {"pit_id": "pit-2", "hits": {"hits": first}}},
                    {"json": {"pit_id": "pit-3", "hits": {"hits": second}}},
                ],
            )
            close = m.delete(CLOSE_PIT_URL, json={"succeeded": True})
            ids = [d["stix"]["id"] for d in handler.iter_connector_documents()]
        assert ids == ["indicator--a", "indicator--b", "indicator--c"]
        assert search.call_count == 2
        assert search.request_history[0].json()["pit"]["id"] == "pit-1"
        assert "search_after" not in search.request_history[0].json()
        assert search.request_history[1].json()["pit"]["id"] == "pit-2"
        assert search.request_history[1].json()["search_after"] == first[-1]["sort"]
        assert close.call_count == 1
        assert close.request_history[0].json() == {"id": "pit-3"}

    def test_a_failed_page_raises_instead_of_a_partial_listing(self, handler):
        with rm_module.Mocker() as m:
            m.post(PIT_URL, json={"id": "pit-1"})
            m.post(SEARCH_URL, status_code=500, text="boom")
            close = m.delete(CLOSE_PIT_URL, json={})
            with pytest.raises(ElasticApiHandlerError):
                list(handler.iter_connector_documents())
            assert close.call_count == 1

    @pytest.mark.parametrize(
        "payload", [{}, {"hits": None}, {"hits": {}}, {"hits": {"hits": None}}, []]
    )
    def test_an_unexpected_search_payload_raises_instead_of_an_empty_page(
        self, handler, payload
    ):
        """Never read as an empty page: every deployment would be reported removed."""
        with rm_module.Mocker() as m:
            m.post(PIT_URL, json={"id": "pit-1"})
            m.post(SEARCH_URL, json=payload)
            close = m.delete(CLOSE_PIT_URL, json={})
            with pytest.raises(ElasticApiHandlerError, match="unexpected search"):
                list(handler.iter_connector_documents())
            assert close.call_count == 1

    def test_a_full_page_without_sort_cursor_raises_instead_of_looping(
        self, handler, monkeypatch
    ):
        monkeypatch.setattr(api_module, "READ_BACK_PAGE_SIZE", 2)
        page = [document(stix_indicator("indicator--a")), {"_source": {}}]
        with rm_module.Mocker() as m:
            m.post(PIT_URL, json={"id": "pit-1"})
            search = m.post(SEARCH_URL, json={"hits": {"hits": page}})
            close = m.delete(CLOSE_PIT_URL, json={})
            with pytest.raises(ElasticApiHandlerError, match="no sort cursor"):
                list(handler.iter_connector_documents())
            assert search.call_count == 1
            assert close.call_count == 1

    @pytest.mark.parametrize("malformed", [{"_id": "x"}, {"_source": None}, "hit"])
    def test_a_hit_without_its_document_raises_instead_of_being_skipped(
        self, handler, malformed
    ):
        page = [document(stix_indicator("indicator--a")), malformed]
        with rm_module.Mocker() as m:
            m.post(PIT_URL, json={"id": "pit-1"})
            m.post(SEARCH_URL, json={"hits": {"hits": page}})
            close = m.delete(CLOSE_PIT_URL, json={})
            with pytest.raises(ElasticApiHandlerError, match="carries no document"):
                list(handler.iter_connector_documents())
            assert close.call_count == 1

    def test_a_refused_point_in_time_raises(self, handler):
        with rm_module.Mocker() as m:
            m.post(PIT_URL, status_code=403, text="forbidden")
            with pytest.raises(ElasticApiHandlerError):
                list(handler.iter_connector_documents())

    def test_a_network_error_raises(self, handler):
        with rm_module.Mocker() as m:
            m.post(PIT_URL, exc=requests.exceptions.ConnectTimeout)
            with pytest.raises(ElasticApiHandlerError):
                list(handler.iter_connector_documents())

    def test_closing_the_point_in_time_is_best_effort(self, handler):
        with rm_module.Mocker() as m:
            m.post(PIT_URL, json={"id": "pit-1"})
            m.post(SEARCH_URL, json={"hits": {"hits": []}})
            m.delete(CLOSE_PIT_URL, exc=requests.exceptions.ConnectTimeout)
            assert list(handler.iter_connector_documents()) == []


class TestAdapter:
    def test_lists_the_indicators_with_their_opencti_id(self, connector):
        live = stix_indicator()
        connector.api = MagicMock()
        connector.api.iter_connector_documents.return_value = [
            document(live)["_source"],
            document(stix_indicator("indicator--expired"), "2000-01-01T00:00:00Z")[
                "_source"
            ],
            document(stix_indicator("ipv4-addr--x", type_="ipv4-addr"))["_source"],
            document(stix_indicator("indicator--future"), "2999-01-01T00:00:00Z")[
                "_source"
            ],
        ]
        listed = list(ElasticDeploymentAdapter(connector).list_vendor_indicators())
        assert [v.indicator_id for v in listed] == [
            INDICATOR_ID,
            None,
            "indicator--future",
        ]
        assert listed[0].external_id == f"doc-{INDICATOR_ID}"
        assert listed[0].raw == {"stix": live}

    def test_a_document_without_stix_object_raises(self, connector):
        """A skipped document would make its deployment look absent."""
        connector.api = MagicMock()
        connector.api.iter_connector_documents.return_value = [
            document(stix_indicator())["_source"],
            {"opencti_doc_id": "no-stix"},
        ]
        with pytest.raises(ElasticDeploymentError, match="no STIX object"):
            list(ElasticDeploymentAdapter(connector).list_vendor_indicators())

    def test_lists_expired_documents_by_document_id_only(self, connector):
        expired = stix_indicator("indicator--expired")
        connector.api = MagicMock()
        connector.api.iter_connector_documents.return_value = [
            document(expired, "2000-01-01T00:00:00Z")["_source"],
        ]
        [listed] = ElasticDeploymentAdapter(connector).list_vendor_indicators()
        # Still in the index: listed for removal, but never backfilled as active
        assert listed.indicator_id is None
        assert listed.external_id == "doc-indicator--expired"
        assert listed.raw == {"stix": expired}

    def test_listing_errors_are_readable(self, connector):
        connector.api = MagicMock()
        connector.api.iter_connector_documents.side_effect = ElasticApiHandlerError(
            "Failed to read the indicators back: 500"
        )
        with pytest.raises(ElasticDeploymentError, match="500"):
            list(ElasticDeploymentAdapter(connector).list_vendor_indicators())

    def test_removal_uses_the_stream_delete_path(self, connector):
        connector.api = MagicMock()
        connector.api.process_indicator.return_value = True
        vendor = MagicMock(raw={"stix": stix_indicator()})
        ElasticDeploymentAdapter(connector).remove_vendor_indicator(vendor, MagicMock())
        connector.api.process_indicator.assert_called_once_with(
            stix_indicator(), "delete"
        )

    def test_failed_removal_raises(self, connector):
        connector.api = MagicMock()
        connector.api.process_indicator.return_value = False
        vendor = MagicMock(raw={"stix": stix_indicator()})
        with pytest.raises(ElasticDeploymentError, match=REMOVE_FAILED_MESSAGE):
            ElasticDeploymentAdapter(connector).remove_vendor_indicator(
                vendor, MagicMock()
            )

    def test_push_returns_the_document_id(self, connector):
        connector.api = MagicMock()
        connector.api.process_indicator.return_value = True
        connector.api.document_id.return_value = "doc-1"
        assert ElasticDeploymentAdapter(connector).push_indicator(stix_indicator()) == (
            "doc-1"
        )
        connector.api.process_indicator.assert_called_once_with(
            stix_indicator(), "create"
        )

    def test_rejected_push_raises(self, connector):
        connector.api = MagicMock()
        connector.api.process_indicator.return_value = False
        with pytest.raises(ElasticDeploymentError, match=PUSH_FAILED_MESSAGE):
            ElasticDeploymentAdapter(connector).push_indicator(stix_indicator())

    def test_no_hit_is_read_back(self, connector):
        assert list(ElasticDeploymentAdapter(connector).collect_hits([], None)) == []

    def test_describe_error(self):
        assert describe_error(ElasticApiHandlerError("Failed: 500")) == "Failed: 500"
        assert describe_error(ValueError("bad")) == "bad"
        assert describe_error(ValueError()) == "ValueError"


class TestConnectorReporting:
    @pytest.mark.parametrize("event", ["create", "update"])
    def test_accepted_indicator_is_reported_deployed(self, connector, event):
        connector.api = MagicMock()
        connector.api.process_indicator.return_value = True
        connector.api.document_id.return_value = "doc-1"
        handle = getattr(connector, f"_handle_{event}_event")
        handle(stix_indicator())
        connector.assurance.report_pushed.assert_called_once_with(
            stix_indicator(), external_id="doc-1"
        )
        connector.assurance.report_push_failed.assert_not_called()

    def test_rejected_indicator_is_reported_failed(self, connector):
        connector.api = MagicMock()
        connector.api.process_indicator.return_value = False
        connector._handle_create_event(stix_indicator())
        connector.assurance.report_push_failed.assert_called_once_with(
            stix_indicator(), PUSH_FAILED_MESSAGE
        )
        connector.assurance.report_pushed.assert_not_called()

    def test_deleted_indicator_is_reported_removed(self, connector):
        connector.api = MagicMock()
        connector.api.process_indicator.return_value = True
        connector.api.document_id.return_value = "doc-1"
        connector._handle_delete_event(stix_indicator())
        connector.assurance.report_removed.assert_called_once_with(
            stix_indicator(), external_id="doc-1"
        )

    def test_failed_deletion_is_not_reported(self, connector):
        connector.api = MagicMock()
        connector.api.process_indicator.return_value = False
        connector._handle_delete_event(stix_indicator())
        connector.assurance.report_removed.assert_not_called()

    def test_without_write_back_nothing_is_reported(self, connector):
        connector.api = MagicMock()
        connector.api.process_indicator.return_value = True
        connector.assurance = None
        connector._handle_create_event(stix_indicator())
        connector._handle_delete_event(stix_indicator())

    def test_run_starts_the_write_back_before_the_stream(self, connector):
        calls = []
        connector.assurance.start.side_effect = lambda: calls.append("start")
        connector.helper.listen_stream.side_effect = lambda **_: calls.append("listen")
        connector.run()
        assert calls == ["start", "listen"]


class TestBuildDeploymentAssurance:
    def test_defaults(self, connector, monkeypatch):
        for name in (
            "SECURITY_PLATFORM_NAME",
            "SECURITY_PLATFORM_TYPE",
            "SECURITY_PLATFORM_ID",
            "DEPLOYMENT_REPORTING_ENABLED",
            "DEPLOYMENT_RECONCILIATION_INTERVAL",
            "HITS_REPORTING_ENABLED",
        ):
            monkeypatch.delenv(name, raising=False)
        assurance = build_deployment_assurance(connector)
        options = assurance.reporter.options
        assert options.security_platform_name == "Elastic Security"
        assert options.security_platform_type == "SIEM"
        assert options.reporting_enabled is True
        assert options.hits_reporting_enabled is False
        assert assurance.reconciler is not None

    def test_environment_and_config_file(self, connector, monkeypatch):
        monkeypatch.setenv("SECURITY_PLATFORM_NAME", "Elastic SOC")
        monkeypatch.delenv("DEPLOYMENT_REPORTING_ENABLED", raising=False)
        connector.config = MagicMock(load={"deployment": {"reporting_enabled": False}})
        options = build_deployment_assurance(connector).reporter.options
        assert options.security_platform_name == "Elastic SOC"
        assert options.reporting_enabled is False
