"""Deployment write-back of the Microsoft Sentinel Intel connector."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from connectors_sdk import (
    DeploymentAssurance,
    HitCollection,
    IndicatorDeployment,
    VendorIndicator,
)
from filigran_sseclient.sseclient import Event
from microsoft_sentinel_intel import Connector
from microsoft_sentinel_intel.client import ConnectorClient, IncidentListing
from microsoft_sentinel_intel.deployment import (
    MAX_HIT_INCIDENTS,
    IncidentCursor,
    MicrosoftSentinelIntelDeploymentAdapter,
    SentinelDeploymentError,
    build_deployment_assurance,
)
from microsoft_sentinel_intel.errors import ConnectorClientError
from microsoft_sentinel_intel.settings import ConnectorSettings
from microsoft_sentinel_intel.utils import describe_error
from pytest_mock import MockerFixture

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
INDICATOR_STIX_ID = "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9"
OTHER_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
OTHER_STIX_ID = "indicator--7e8f9a0b-1c2d-4e3f-8a4b-5c6d7e8f9a0b"
WORKSPACE_PATH = (
    "/subscriptions/ChangeMe/resourceGroups/default/providers/"
    "Microsoft.OperationalInsights/workspaces/ChangeMe/providers/"
    "Microsoft.SecurityInsights"
)
RESOURCE_ID = f"{WORKSPACE_PATH}/threatintelligence/abc---{INDICATOR_STIX_ID}"


def make_indicator(
    indicator_id=INDICATOR_ID,
    stix_id=INDICATOR_STIX_ID,
    pattern="[ipv4-addr:value = '198.51.100.7']",
    **extra,
):
    """Build the `data` of a stream event for an indicator."""
    return {
        "id": stix_id,
        "type": "indicator",
        "spec_version": "2.1",
        "name": "198.51.100.7",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "extensions": {
            OPENCTI_EXTENSION_ID: {
                "id": indicator_id,
                "type": "Indicator",
                "main_observable_type": "IPv4-Addr",
            }
        },
        **extra,
    }


def make_event(event_type, data):
    return Event(event=event_type, data=json.dumps({"data": data}))


def make_deployment(
    indicator_id=INDICATOR_ID,
    stix_id=INDICATOR_STIX_ID,
    status="deployed",
    pattern="[ipv4-addr:value = '198.51.100.7']",
    **extra,
):
    return IndicatorDeployment(
        relationship_id=f"relationship-{indicator_id}",
        status=status,
        indicator_id=indicator_id,
        indicator_standard_id=stix_id,
        pattern=pattern,
        pattern_type="stix",
        **extra,
    )


def ti_object(stix_id=INDICATOR_STIX_ID, resource_id=RESOURCE_ID, **data):
    """Build a TI object of the `threatIntelligence/main/query` API."""
    return {
        "id": resource_id,
        "name": resource_id.rsplit("/", 1)[-1],
        "kind": "Indicator",
        "properties": {
            "data": {
                "id": stix_id,
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '198.51.100.7']",
                **data,
            }
        },
    }


def response(body, status_code=200):
    """Build an Azure HTTP response mock returning a JSON body."""
    return Mock(status_code=status_code, body=Mock(return_value=json.dumps(body)))


class GraphQLRouter:
    """Fake `helper.api.query` dispatching on the GraphQL operation name."""

    def __init__(self, deployments=None):
        self.calls = []
        self.deployments = deployments or []

    def __call__(self, query, variables=None):
        self.calls.append((query, variables))
        if "DeploymentWriteBackFeatures" in query:
            fields = [
                {"name": "indicatorReportDeployment"},
                {"name": "indicatorReportDeployments"},
                {"name": "indicatorReportHits"},
            ]
            return {"data": {"__type": {"fields": fields}}}
        if "DeploymentSecurityPlatformAdd" in query:
            return {"data": {"securityPlatformAdd": {"id": PLATFORM_ID}}}
        if "IndicatorReportDeployments(" in query:
            reports = variables["reports"]
            return {
                "data": {
                    "indicatorReportDeployments": {
                        "processed": len(reports),
                        "created": 0,
                        "updated": len(reports),
                        "unchanged": 0,
                        "errors": [],
                    }
                }
            }
        if "IndicatorReportHits(" in query:
            return {"data": {"indicatorReportHits": {"id": "sighting-id"}}}
        if "IndicatorDeploymentsOfPlatform" in query:
            return {
                "data": {
                    "stixCoreRelationships": {
                        "edges": [{"node": node} for node in self.deployments],
                        "pageInfo": {"endCursor": None, "hasNextPage": False},
                    }
                }
            }
        raise AssertionError(f"Unexpected GraphQL document: {query}")

    def calls_of(self, marker):
        return [variables for query, variables in self.calls if marker in query]


def deployment_node(indicator_id, stix_id, status, last_hit_at=None, revoked=False):
    return {
        "id": f"relationship-{indicator_id}",
        "deployment_status": status,
        "external_id": None,
        "revoked": revoked,
        "last_sync_at": "2026-10-01T00:00:00.000Z",
        "last_hit_at": last_hit_at,
        "hit_count": 0,
        "from": {
            "id": indicator_id,
            "standard_id": stix_id,
            "name": "198.51.100.7",
            "pattern": "[ipv4-addr:value = '198.51.100.7']",
            "pattern_type": "stix",
            "revoked": False,
            "valid_until": None,
        },
    }


@pytest.fixture(name="no_atexit")
def fixture_no_atexit(monkeypatch):
    """Do not register the exit flush of the deployment reporter during tests."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.atexit.register",
        lambda _handler: None,
    )


@pytest.fixture(name="connector")
def fixture_connector(
    mocked_api_client: MagicMock, mock_microsoft_sentinel_intel_config
) -> Connector:
    config = ConnectorSettings()
    helper = MagicMock()
    client = ConnectorClient(helper=helper, config=config)
    return Connector(
        helper=helper,
        config=config,
        client=client,
        assurance=MagicMock(spec=DeploymentAssurance),
    )


@pytest.fixture(name="batch_connector")
def fixture_batch_connector(
    mocked_api_client: MagicMock, mock_microsoft_sentinel_intel_batch_config
) -> Connector:
    config = ConnectorSettings()
    helper = MagicMock()
    client = ConnectorClient(helper=helper, config=config)
    return Connector(
        helper=helper,
        config=config,
        client=client,
        assurance=MagicMock(spec=DeploymentAssurance),
    )


@pytest.fixture(name="adapter_connector")
def fixture_adapter_connector(mock_microsoft_sentinel_intel_config):
    """Connector stand-in of the adapter tests (mocked client)."""
    return SimpleNamespace(
        client=MagicMock(spec=ConnectorClient),
        config=ConnectorSettings(),
        helper=MagicMock(),
        push_indicator=MagicMock(),
    )


@pytest.fixture(name="adapter")
def fixture_adapter(adapter_connector):
    return MicrosoftSentinelIntelDeploymentAdapter(adapter_connector)


# Stream path


def test_create_reports_the_pushed_indicator(
    mocker: MockerFixture, connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )
    indicator = make_indicator()

    connector._handle_event(make_event("create", indicator))

    connector.assurance.report_pushed.assert_called_once_with(indicator)
    connector.assurance.report_push_failed.assert_not_called()


def test_upload_of_a_revoked_indicator_is_reported_removed(
    mocker: MockerFixture, connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )
    indicator = make_indicator(revoked=True)

    connector._handle_event(make_event("update", indicator))

    connector.assurance.report_removed.assert_called_once_with(indicator)
    connector.assurance.report_pushed.assert_not_called()


def test_rejected_upload_is_reported_failed(
    mocker: MockerFixture, connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=HttpResponseError(message="400 Invalid pattern"),
    )
    indicator = make_indicator()

    with pytest.raises(ConnectorClientError):
        connector._handle_event(make_event("create", indicator))

    connector.assurance.report_push_failed.assert_called_once()
    reported, message = connector.assurance.report_push_failed.call_args.args
    assert reported == indicator
    assert message.startswith("[API] An error occurred during request: ")
    assert "400 Invalid pattern" in message
    connector.assurance.report_pushed.assert_not_called()


def test_delete_reports_the_removed_indicator(
    mocker: MockerFixture, connector: Connector
) -> None:
    delete = mocker.patch.object(connector.client, "delete_indicator_by_id")
    indicator = make_indicator()

    connector._handle_event(make_event("delete", indicator))

    delete.assert_called_once_with(
        INDICATOR_STIX_ID, source_system="Opencti Stream Connector"
    )
    connector.assurance.report_removed.assert_called_once_with(indicator)


def test_failed_delete_is_not_reported_removed(
    mocker: MockerFixture, connector: Connector
) -> None:
    mocker.patch.object(
        connector.client,
        "delete_indicator_by_id",
        side_effect=ConnectorClientError("[API] Failed to delete 1/1 indicators"),
    )

    with pytest.raises(ConnectorClientError):
        connector._handle_event(make_event("delete", make_indicator()))

    connector.assurance.report_removed.assert_not_called()


def test_identities_are_never_reported(
    mocker: MockerFixture, connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    connector._report_uploaded([{"id": "identity--x", "type": "identity"}])
    connector._report_upload_failed(
        [{"id": "identity--x", "type": "identity"}], ValueError("boom")
    )

    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_batch_upload_reports_every_indicator(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )
    delete = mocker.patch.object(batch_connector.client, "delete_indicator_by_id")
    first = make_indicator()
    second = make_indicator(indicator_id=OTHER_ID, stix_id=OTHER_STIX_ID)
    deleted = make_indicator(
        indicator_id="2fad6a2a-8c65-4b33-af8e-3f4a7b8c9dae",
        stix_id="indicator--3abe7b3b-9d76-4c44-b09f-4a5b8c9daebf",
    )

    batch_connector.process_batch(
        {
            "events": [
                make_event("create", first),
                make_event("update", second),
                make_event("delete", deleted),
            ]
        }
    )

    assert [
        call.args[0] for call in batch_connector.assurance.report_pushed.call_args_list
    ] == [first, second]
    delete.assert_called_once()
    batch_connector.assurance.report_removed.assert_called_once_with(deleted)


def test_rejected_batch_upload_reports_every_indicator_failed(
    mocker: MockerFixture, batch_connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=HttpResponseError(message="429 Too Many Requests"),
    )
    first = make_indicator()
    second = make_indicator(indicator_id=OTHER_ID, stix_id=OTHER_STIX_ID)

    batch_connector.process_batch(
        {"events": [make_event("create", first), make_event("create", second)]}
    )

    failed = batch_connector.assurance.report_push_failed.call_args_list
    assert [call.args[0] for call in failed] == [first, second]
    assert all("429 Too Many Requests" in call.args[1] for call in failed)
    batch_connector.assurance.report_pushed.assert_not_called()


def test_connector_works_without_write_back(
    mocker: MockerFixture, connector: Connector
) -> None:
    send = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )
    connector.assurance = None

    connector._handle_event(make_event("create", make_indicator()))

    send.assert_called_once()


def test_run_starts_the_write_back(connector: Connector) -> None:
    connector.run()

    connector.assurance.start.assert_called_once_with()
    connector.helper.listen_stream.assert_called_once()


def test_describe_error_includes_the_api_error() -> None:
    error = ConnectorClientError("[API] Request failed", {"error": "403 Forbidden"})

    assert describe_error(error) == "[API] Request failed: 403 Forbidden"
    assert describe_error(ConnectorClientError("[API] Failed")) == "[API] Failed"
    assert describe_error(ValueError()) == "ValueError"


# Settings and factory


@pytest.mark.usefixtures("mock_microsoft_sentinel_intel_config")
def test_write_back_settings_defaults() -> None:
    settings = ConnectorSettings()

    assert settings.deployment.reporting_enabled is True
    assert settings.deployment.reconciliation_interval == 60
    assert settings.hits.reporting_enabled is True
    assert settings.security_platform.name == "Microsoft Sentinel"
    assert settings.security_platform.type == "SIEM"
    assert settings.security_platform.id is None


def test_build_deployment_assurance_wires_reconciliation_and_hits(
    adapter_connector,
) -> None:
    assurance = build_deployment_assurance(adapter_connector)

    assert assurance.enabled is True
    assert assurance.reporter.hits_enabled is True
    assert assurance.reporter.options.security_platform_name == "Microsoft Sentinel"
    assert assurance.reconciler is not None


def test_disabled_write_back_is_a_no_op(
    mocker: MockerFixture, adapter_connector
) -> None:
    mocker.patch.dict(
        "os.environ",
        {"DEPLOYMENT_REPORTING_ENABLED": "false", "HITS_REPORTING_ENABLED": "false"},
    )
    adapter_connector.config = ConnectorSettings()

    assurance = build_deployment_assurance(adapter_connector)

    assert assurance.enabled is False
    assert assurance.start() is False
    assert assurance.report_pushed(make_indicator()) is False
    assert assurance.reconciler.start() is False
    adapter_connector.helper.api.query.assert_not_called()


# Client


def test_iter_indicators_follows_next_links(
    mocker: MockerFixture, connector: Connector
) -> None:
    next_link = "https://management.azure.com/next?api-version=2025-07-01-preview"
    send = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[
            response({"value": [ti_object()], "nextLink": next_link}),
            response({"value": [ti_object(stix_id=OTHER_STIX_ID)]}),
        ],
    )

    items = list(
        connector.client.iter_indicators(
            source_system="Opencti Stream Connector", page_size=100, max_pages=5
        )
    )

    assert [item["properties"]["data"]["id"] for item in items] == [
        INDICATOR_STIX_ID,
        OTHER_STIX_ID,
    ]
    first, second = (call.kwargs["request"] for call in send.call_args_list)
    assert first.method == "POST"
    assert first.url.startswith(
        f"https://management.azure.com{WORKSPACE_PATH}/threatIntelligence/main/query"
    )
    body = json.loads(first.data)
    assert body["maxPageSize"] == 100
    assert body["condition"]["clauses"] == [
        {
            "field": "source",
            "operator": "Equals",
            "values": ["Opencti Stream Connector"],
        }
    ]
    assert second.method == "GET"
    assert second.url == next_link


def test_iter_indicators_never_returns_a_partial_listing(
    mocker: MockerFixture, connector: Connector
) -> None:
    next_link = "https://management.azure.com/next"
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[
            response({"value": [ti_object()], "nextLink": next_link}),
            response({"value": [], "nextLink": next_link}),
        ],
    )

    with pytest.raises(ConnectorClientError) as error:
        list(connector.client.iter_indicators("source", page_size=1, max_pages=5))

    assert error.value.message.startswith("[API] Listing aborted")


def test_iter_indicators_never_exceeds_the_page_limit(
    mocker: MockerFixture, connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[
            response({"value": [ti_object()], "nextLink": "https://next/1"}),
            response({"value": [ti_object()], "nextLink": "https://next/2"}),
        ],
    )

    with pytest.raises(ConnectorClientError) as error:
        list(connector.client.iter_indicators("source", page_size=1, max_pages=2))

    assert error.value.metadata == {"pages": 2, "max_pages": 2}


@pytest.mark.parametrize(
    "body",
    [{"unexpected": True}, ["not", "an", "object"], {"value": [{}, "not an object"]}],
)
def test_iter_indicators_rejects_unexpected_payloads(
    mocker: MockerFixture, connector: Connector, body
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=response(body),
    )

    with pytest.raises(ConnectorClientError) as error:
        list(connector.client.iter_indicators("source", page_size=1, max_pages=5))

    assert error.value.message.startswith("[API] Unexpected response format")


def test_iter_indicators_rejects_invalid_json(
    mocker: MockerFixture, connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(body=Mock(return_value="<html>")),
    )

    with pytest.raises(ConnectorClientError) as error:
        list(connector.client.iter_indicators("source", page_size=1, max_pages=5))

    assert error.value.message == "[API] Failed to decode response body"


def test_iter_incidents_stops_at_the_page_limit(
    mocker: MockerFixture, connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[
            response({"value": [{"id": "incident-1"}], "nextLink": "https://next/1"}),
            response({"value": [{"id": "incident-2"}], "nextLink": "https://next/2"}),
        ],
    )

    listing = connector.client.iter_incidents(
        modified_since=datetime.now(UTC), page_size=1, max_pages=2
    )

    assert list(listing) == [{"id": "incident-1"}, {"id": "incident-2"}]
    assert listing.truncated is True
    connector.helper.connector_logger.warning.assert_called_once()


def test_iter_incidents_marks_short_pages_left_at_the_page_limit_as_truncated(
    mocker: MockerFixture, connector: Connector
) -> None:
    """Pages can be shorter than `$top`: the `nextLink` left decides, not the count."""
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[
            response({"value": [{"id": "incident-1"}], "nextLink": "https://next/1"}),
            response({"value": [{"id": "incident-2"}], "nextLink": "https://next/2"}),
        ],
    )

    listing = connector.client.iter_incidents(
        modified_since=datetime.now(UTC), page_size=100, max_pages=2
    )

    assert len(list(listing)) == 2
    assert listing.truncated is True


def test_iter_incidents_read_to_the_end_is_not_truncated(
    mocker: MockerFixture, connector: Connector
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[
            response({"value": [{"id": "incident-1"}], "nextLink": "https://next/1"}),
            response({"value": [{"id": "incident-2"}]}),
        ],
    )

    listing = connector.client.iter_incidents(
        modified_since=datetime.now(UTC), page_size=1, max_pages=2
    )

    assert len(list(listing)) == 2
    assert listing.truncated is False


def test_iter_incidents_filters_on_the_modification_time(
    mocker: MockerFixture, connector: Connector
) -> None:
    send = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=response({"value": [{"id": "incident-1"}]}),
    )

    incidents = list(
        connector.client.iter_incidents(
            modified_since=datetime(2026, 10, 3, 10, 0, 0, 123, tzinfo=UTC),
            page_size=50,
            max_pages=2,
        )
    )

    assert incidents == [{"id": "incident-1"}]
    request = send.call_args.kwargs["request"]
    assert request.method == "GET"
    assert f"{WORKSPACE_PATH}/incidents?" in request.url
    assert "api-version=2025-03-01" in request.url
    assert (
        "$filter=properties/lastModifiedTimeUtc%20ge%202026-10-03T10:00:00Z"
        in request.url
    )
    assert "$orderby=properties/lastModifiedTimeUtc%20asc" in request.url
    assert "$top=50" in request.url


def test_list_incident_entities(mocker: MockerFixture, connector: Connector) -> None:
    send = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=response(
            {"entities": [{"kind": "Ip", "properties": {"address": "1.2.3.4"}}]}
        ),
    )

    entities = connector.client.list_incident_entities("incident-1")

    assert entities == [{"kind": "Ip", "properties": {"address": "1.2.3.4"}}]
    request = send.call_args.kwargs["request"]
    assert request.method == "POST"
    assert f"{WORKSPACE_PATH}/incidents/incident-1/entities" in request.url

    connector.client.list_incident_entities(f"{WORKSPACE_PATH}/incidents/incident-2")
    assert (
        f"{WORKSPACE_PATH}/incidents/incident-2/entities"
        in send.call_args.kwargs["request"].url
    )


@pytest.mark.parametrize(
    "body",
    [{}, {"entities": None}, {"entities": {"kind": "Ip"}}, {"entities": [{}, 3]}],
)
def test_list_incident_entities_rejects_a_malformed_response(
    mocker: MockerFixture, connector: Connector, body: dict
) -> None:
    """Never read as "no match": the hit window would move past the incident."""
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=response(body),
    )

    with pytest.raises(ConnectorClientError) as raised:
        connector.client.list_incident_entities("incident-1")
    assert "entities" in raised.value.message
    assert raised.value.metadata["incident_id"] == "incident-1"


def test_delete_ti_object(mocker: MockerFixture, connector: Connector) -> None:
    send = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        return_value=Mock(status_code=200),
    )

    connector.client.delete_ti_object(RESOURCE_ID)

    request = send.call_args.kwargs["request"]
    assert request.method == "DELETE"
    assert request.url.startswith(f"https://management.azure.com{RESOURCE_ID}?")


# Vendor adapter


def test_adapter_lists_an_indicator_at_its_valid_until_as_inactive() -> None:
    """`valid_until` ends the validity window: at that instant it is expired."""
    boundary = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    to_vendor_indicator = MicrosoftSentinelIntelDeploymentAdapter._to_vendor_indicator

    at_boundary = to_vendor_indicator(
        ti_object(valid_until=boundary.isoformat()), boundary
    )
    before = to_vendor_indicator(
        ti_object(valid_until=boundary.isoformat()), boundary - timedelta(seconds=1)
    )

    assert at_boundary.active is False
    assert before.active is True


def test_adapter_lists_live_indicators_of_the_source_system(
    adapter, adapter_connector
) -> None:
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    adapter_connector.client.iter_indicators.return_value = iter(
        [
            ti_object(valid_until=future),
            ti_object(stix_id=OTHER_STIX_ID, revoked=True),
            ti_object(stix_id="indicator--expired", valid_until=past),
            {"id": "x", "properties": {"data": {"type": "attack-pattern", "id": "a"}}},
        ]
    )

    vendor_indicators = list(adapter.list_vendor_indicators())

    resource_name = RESOURCE_ID.rsplit("/", 1)[-1]
    assert vendor_indicators == [
        VendorIndicator(
            indicator_id=INDICATOR_STIX_ID,
            external_id=resource_name,
            value="198.51.100.7",
        ),
        VendorIndicator(
            indicator_id=OTHER_STIX_ID,
            external_id=resource_name,
            value="198.51.100.7",
            active=False,
        ),
        VendorIndicator(
            indicator_id="indicator--expired",
            external_id=resource_name,
            value="198.51.100.7",
            active=False,
        ),
    ]
    assert vendor_indicators[0].raw == {
        "id": RESOURCE_ID,
        "name": RESOURCE_ID.rsplit("/", 1)[-1],
    }
    adapter_connector.client.iter_indicators.assert_called_once_with(
        source_system="Opencti Stream Connector", page_size=100, max_pages=5_000
    )


@pytest.mark.parametrize(
    "malformed",
    [
        {"id": "y", "properties": {"data": {"type": "indicator"}}},
        {"id": "z", "properties": {}},
    ],
)
def test_adapter_read_back_rejects_an_indicator_without_stix_id(
    adapter, adapter_connector, malformed
) -> None:
    """A skipped indicator would make its deployment look absent."""
    adapter_connector.client.iter_indicators.return_value = iter(
        [ti_object(), malformed]
    )

    with pytest.raises(SentinelDeploymentError, match="carries no STIX id"):
        list(adapter.list_vendor_indicators())


def test_adapter_removes_by_resource_id(adapter, adapter_connector) -> None:
    vendor_indicator = VendorIndicator(
        indicator_id=INDICATOR_STIX_ID, raw={"id": RESOURCE_ID}
    )

    adapter.remove_vendor_indicator(vendor_indicator, make_deployment())

    adapter_connector.client.delete_ti_object.assert_called_once_with(RESOURCE_ID)


def test_adapter_removal_of_an_already_deleted_indicator_succeeds(
    adapter, adapter_connector
) -> None:
    error = ConnectorClientError("[API] An error occurred during request")
    error.__cause__ = ResourceNotFoundError("Not found")
    adapter_connector.client.delete_ti_object.side_effect = error

    adapter.remove_vendor_indicator(
        VendorIndicator(indicator_id=INDICATOR_STIX_ID, raw={"id": RESOURCE_ID}),
        make_deployment(),
    )


def test_adapter_removal_errors_are_raised_with_their_message(
    adapter, adapter_connector
) -> None:
    error = ConnectorClientError(
        "[API] An error occurred during request", {"error": "403 Forbidden"}
    )
    error.__cause__ = HttpResponseError(message="403 Forbidden")
    adapter_connector.client.delete_ti_object.side_effect = error

    with pytest.raises(SentinelDeploymentError) as raised:
        adapter.remove_vendor_indicator(
            VendorIndicator(indicator_id=INDICATOR_STIX_ID, raw={"id": RESOURCE_ID}),
            make_deployment(),
        )

    assert str(raised.value) == "[API] An error occurred during request: 403 Forbidden"
    assert raised.value.__cause__ is error


def test_adapter_read_back_errors_are_raised_with_their_message(
    adapter, adapter_connector
) -> None:
    adapter_connector.client.iter_indicators.side_effect = ConnectorClientError(
        "[API] An error occurred during request", {"error": "401 Unauthorized"}
    )

    with pytest.raises(SentinelDeploymentError, match="401 Unauthorized"):
        list(adapter.list_vendor_indicators())


def test_adapter_rejected_push_is_raised_with_its_message(
    adapter, adapter_connector
) -> None:
    adapter_connector.push_indicator.side_effect = ConnectorClientError(
        "[API] An error occurred during request", {"error": "400 Invalid pattern"}
    )

    with pytest.raises(SentinelDeploymentError, match="400 Invalid pattern"):
        adapter.push_indicator(make_indicator())


def test_adapter_removal_without_resource_id_uses_the_stix_id(
    adapter, adapter_connector
) -> None:
    adapter.remove_vendor_indicator(
        VendorIndicator(indicator_id=INDICATOR_STIX_ID), make_deployment()
    )

    adapter_connector.client.delete_indicator_by_id.assert_called_once_with(
        INDICATOR_STIX_ID, source_system="Opencti Stream Connector"
    )


def test_adapter_push_uses_the_stream_upload_path(adapter, adapter_connector) -> None:
    indicator = make_indicator()

    assert adapter.push_indicator(indicator) is None

    adapter_connector.push_indicator.assert_called_once_with(indicator)


def test_adapter_collects_hits_from_incident_entities(
    adapter, adapter_connector
) -> None:
    since = datetime.now(UTC) - timedelta(hours=1)
    recent = (since + timedelta(minutes=30)).isoformat()
    old = (since - timedelta(minutes=30)).isoformat()
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        [
            {"id": "incident-old", "properties": {"lastActivityTimeUtc": old}},
            {"id": "incident-1", "properties": {"lastActivityTimeUtc": recent}},
            {"id": "incident-2", "properties": {"createdTimeUtc": recent}},
        ]
    )
    adapter_connector.client.list_incident_entities.side_effect = [
        [
            {"kind": "Ip", "properties": {"address": "198.51.100.7"}},
            {"kind": "Url", "properties": {"url": "https://unrelated.example"}},
            {"kind": "Account", "properties": {"address": "198.51.100.7"}},
        ],
        [{"kind": "Ip", "properties": {"address": "198.51.100.7"}}],
    ]

    hits = list(adapter.collect_hits([make_deployment()], since))

    assert [(hit.indicator_id, hit.count) for hit in hits] == [
        (INDICATOR_ID, 1),
        (INDICATOR_ID, 1),
    ]
    assert hits[0].timestamp.isoformat() == recent
    adapter_connector.client.iter_incidents.assert_called_once_with(
        modified_since=since, page_size=100, max_pages=20
    )
    assert adapter_connector.client.list_incident_entities.call_count == 2


def test_adapter_hit_read_rejects_an_incident_without_id(
    adapter, adapter_connector
) -> None:
    """A skipped incident would be lost: the hit window moves past its entities."""
    since = datetime.now(UTC) - timedelta(hours=1)
    recent = (since + timedelta(minutes=30)).isoformat()
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        [{"properties": {"lastActivityTimeUtc": recent}}]
    )

    with pytest.raises(SentinelDeploymentError, match="incident of the hit read"):
        list(adapter.collect_hits([make_deployment()], since))


@pytest.mark.parametrize(
    "properties",
    [
        {},
        {
            "lastActivityTimeUtc": "not a date",
            "createdTimeUtc": "",
            "lastModifiedTimeUtc": None,
        },
    ],
)
def test_adapter_hit_read_rejects_an_incident_without_activity_time(
    adapter, adapter_connector, properties
) -> None:
    """A skipped incident would be lost: the hit window moves past its entities."""
    since = datetime.now(UTC) - timedelta(hours=1)
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        [{"id": "incident-1", "properties": properties}]
    )

    with pytest.raises(SentinelDeploymentError, match="carries no activity time"):
        list(adapter.collect_hits([make_deployment()], since))
    adapter_connector.client.list_incident_entities.assert_not_called()


def test_adapter_hits_resume_at_an_incident_whose_entities_cannot_be_read(
    adapter, adapter_connector
) -> None:
    since = datetime.now(UTC) - timedelta(hours=1)
    first = since + timedelta(minutes=10)
    failing = since + timedelta(minutes=20)
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        [
            {
                "id": "incident-1",
                "properties": {"lastModifiedTimeUtc": first.isoformat()},
            },
            {
                "id": "incident-2",
                "properties": {"lastModifiedTimeUtc": failing.isoformat()},
            },
            {
                "id": "incident-3",
                "properties": {"lastModifiedTimeUtc": failing.isoformat()},
            },
        ]
    )
    adapter_connector.client.list_incident_entities.side_effect = [
        [{"kind": "Ip", "properties": {"address": "198.51.100.7"}}],
        ConnectorClientError("[API] Failed", {"error": "503"}),
    ]

    collection = adapter.collect_hits([make_deployment()], since)

    assert isinstance(collection, HitCollection)
    assert collection.complete_until == since
    assert collection.resume == IncidentCursor(
        modified_since=first, handled={"incident-1": first}
    )
    assert [hit.timestamp for hit in collection.hits] == [first]
    assert adapter_connector.client.list_incident_entities.call_count == 2


def test_adapter_hits_resume_after_the_last_listed_page(
    adapter, adapter_connector
) -> None:
    since = datetime.now(UTC) - timedelta(hours=1)
    last = since + timedelta(minutes=5)
    listing = IncidentListing(
        [
            {
                "id": "incident-1",
                "properties": {
                    "lastModifiedTimeUtc": "invalid",
                    "lastActivityTimeUtc": (since - timedelta(minutes=10)).isoformat(),
                },
            },
            {
                "id": "incident-2",
                "properties": {"lastModifiedTimeUtc": last.isoformat()},
            },
        ]
    )
    listing.mark_truncated()
    adapter_connector.client.iter_incidents.return_value = listing
    adapter_connector.client.list_incident_entities.return_value = []

    collection = adapter.collect_hits([make_deployment()], since)

    assert collection == HitCollection(
        hits=[],
        complete_until=since,
        resume=IncidentCursor(
            modified_since=last,
            handled={
                "incident-1": since - timedelta(minutes=10),
                "incident-2": last,
            },
        ),
    )


def test_adapter_hits_of_a_complete_listing_are_complete(
    adapter, adapter_connector
) -> None:
    since = datetime.now(UTC) - timedelta(hours=1)
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        {
            "id": f"incident-{index}",
            "properties": {
                "lastModifiedTimeUtc": (since + timedelta(minutes=index)).isoformat()
            },
        }
        for index in range(3)
    )
    adapter_connector.client.list_incident_entities.return_value = []

    assert adapter.collect_hits([make_deployment()], since) == []


def test_adapter_hits_count_once_per_indicator_and_credit_shared_values(
    adapter, adapter_connector
) -> None:
    """Two values of one indicator in an incident make one hit; a value shared by
    two indicators makes one hit for each of them."""
    since = datetime.now(UTC) - timedelta(hours=1)
    recent = since + timedelta(minutes=5)
    multi_value = make_deployment(
        pattern="[ipv4-addr:value = '198.51.100.7'] OR [domain-name:value = 'bad.example']"
    )
    sharing = make_deployment(
        indicator_id="other-indicator",
        stix_id="indicator--0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
        pattern="[domain-name:value = 'bad.example']",
    )
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        [
            {
                "id": "incident-1",
                "properties": {"lastActivityTimeUtc": recent.isoformat()},
            }
        ]
    )
    adapter_connector.client.list_incident_entities.return_value = [
        {"kind": "Ip", "properties": {"address": "198.51.100.7"}},
        {"kind": "DnsResolution", "properties": {"domainName": "bad.example"}},
    ]

    hits = list(adapter.collect_hits([multi_value, sharing], since))

    assert sorted((hit.indicator_id, hit.count) for hit in hits) == [
        (INDICATOR_ID, 1),
        ("other-indicator", 1),
    ]


def test_adapter_hits_without_values_read_no_incident(
    adapter, adapter_connector
) -> None:
    deployment = make_deployment(pattern=None)

    assert adapter.collect_hits([deployment], datetime.now(UTC)) == []
    adapter_connector.client.iter_incidents.assert_not_called()


def test_adapter_hits_inspect_a_bounded_number_of_incidents(
    adapter, adapter_connector
) -> None:
    since = datetime.now(UTC) - timedelta(hours=1)
    recent = since + timedelta(minutes=1)
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        {
            "id": f"incident-{index}",
            "properties": {
                "lastActivityTimeUtc": recent.isoformat(),
                "lastModifiedTimeUtc": (recent + timedelta(seconds=index)).isoformat(),
            },
        }
        for index in range(MAX_HIT_INCIDENTS + 5)
    )
    adapter_connector.client.list_incident_entities.return_value = []

    collection = adapter.collect_hits([make_deployment()], since)

    assert collection == HitCollection(
        hits=[],
        complete_until=since,
        resume=IncidentCursor(
            modified_since=recent + timedelta(seconds=MAX_HIT_INCIDENTS - 1),
            handled={f"incident-{index}": recent for index in range(MAX_HIT_INCIDENTS)},
        ),
    )
    assert (
        adapter_connector.client.list_incident_entities.call_count == MAX_HIT_INCIDENTS
    )


def test_adapter_hits_capped_at_their_start_continue_after_the_incidents_inspected(
    adapter, adapter_connector, monkeypatch
) -> None:
    """More incidents share the start time than the limit: the next read skips the
    incidents already inspected there instead of moving past that time."""
    monkeypatch.setattr("microsoft_sentinel_intel.deployment.MAX_HIT_INCIDENTS", 2)
    since = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        {
            "id": f"incident-{index}",
            "properties": {
                "lastActivityTimeUtc": since.isoformat(),
                "lastModifiedTimeUtc": since.isoformat(),
            },
        }
        for index in range(5)
    )
    adapter_connector.client.list_incident_entities.return_value = [
        {"kind": "Ip", "properties": {"address": "198.51.100.7"}}
    ]

    collection = adapter.collect_hits(
        [make_deployment()],
        since,
        resume=IncidentCursor(modified_since=since, handled={"incident-0": since}),
    )

    assert isinstance(collection, HitCollection)
    assert collection.complete_until == since
    assert collection.resume == IncidentCursor(
        modified_since=since,
        handled={"incident-0": since, "incident-1": since, "incident-2": since},
    )
    assert len(collection.hits) == 2
    assert [
        call.args[0]
        for call in adapter_connector.client.list_incident_entities.call_args_list
    ] == ["incident-1", "incident-2"]


def test_adapter_hits_continued_later_keep_the_activity_lower_bound(
    adapter, adapter_connector
) -> None:
    """The listing continues at a modification time, the activity filter stays at
    `since`: an unread incident modified later but active earlier is counted."""
    since = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    cursor = since + timedelta(minutes=20)
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        [
            {
                "id": "incident-1",
                "properties": {"lastModifiedTimeUtc": cursor.isoformat()},
            },
            {
                "id": "incident-2",
                "properties": {
                    "lastActivityTimeUtc": (since + timedelta(minutes=5)).isoformat(),
                    "lastModifiedTimeUtc": (since + timedelta(minutes=25)).isoformat(),
                },
            },
        ]
    )
    adapter_connector.client.list_incident_entities.return_value = [
        {"kind": "Ip", "properties": {"address": "198.51.100.7"}}
    ]

    hits = adapter.collect_hits(
        [make_deployment()],
        since,
        resume=IncidentCursor(modified_since=cursor, handled={"incident-1": cursor}),
    )

    assert [hit.timestamp for hit in hits] == [since + timedelta(minutes=5)]
    adapter_connector.client.iter_incidents.assert_called_once_with(
        modified_since=cursor, page_size=100, max_pages=20
    )
    adapter_connector.client.list_incident_entities.assert_called_once_with(
        "incident-2"
    )


def test_adapter_hits_continued_later_read_again_an_incident_active_again(
    adapter, adapter_connector
) -> None:
    """An incident handled by the read and active again since is read again (as the
    next window of an uncapped read would); one with the same activity is not."""
    since = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    handled_at = since + timedelta(minutes=5)
    active_again = since + timedelta(minutes=30)
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        [
            {
                "id": "incident-1",
                "properties": {
                    "lastActivityTimeUtc": active_again.isoformat(),
                    "lastModifiedTimeUtc": active_again.isoformat(),
                },
            },
            {
                "id": "incident-2",
                "properties": {
                    "lastActivityTimeUtc": handled_at.isoformat(),
                    "lastModifiedTimeUtc": active_again.isoformat(),
                },
            },
        ]
    )
    adapter_connector.client.list_incident_entities.return_value = [
        {"kind": "Ip", "properties": {"address": "198.51.100.7"}}
    ]

    hits = adapter.collect_hits(
        [make_deployment()],
        since,
        resume=IncidentCursor(
            modified_since=handled_at,
            handled={"incident-1": handled_at, "incident-2": handled_at},
        ),
    )

    assert [hit.timestamp for hit in hits] == [active_again]
    adapter_connector.client.list_incident_entities.assert_called_once_with(
        "incident-1"
    )


def test_adapter_hits_not_continued_beyond_the_handled_incident_limit(
    adapter, adapter_connector, monkeypatch
) -> None:
    monkeypatch.setattr("microsoft_sentinel_intel.deployment.MAX_HIT_INCIDENTS", 2)
    monkeypatch.setattr("microsoft_sentinel_intel.deployment.MAX_HANDLED_INCIDENTS", 1)
    since = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    adapter_connector.client.iter_incidents.return_value = IncidentListing(
        {
            "id": f"incident-{index}",
            "properties": {"lastActivityTimeUtc": since.isoformat()},
        }
        for index in range(3)
    )
    adapter_connector.client.list_incident_entities.return_value = []

    collection = adapter.collect_hits([make_deployment()], since)

    assert collection == HitCollection(hits=[], complete_until=since)


# End to end: stream processing and reconciliation through GraphQL


@pytest.fixture(name="router")
def fixture_router():
    return GraphQLRouter()


@pytest.fixture(name="e2e_connector")
def fixture_e2e_connector(
    no_atexit, router, mocked_api_client, mock_microsoft_sentinel_intel_config
):
    """Connector with a helper without the pycti deployment helpers (GraphQL path)."""
    helper = MagicMock(spec=["api", "connector_logger", "listen_stream"])
    helper.api.query.side_effect = router
    config = ConnectorSettings()
    client = ConnectorClient(helper=helper, config=config)
    connector = Connector(helper=helper, config=config, client=client)
    connector.assurance = DeploymentAssurance.from_settings(
        helper,
        config,
        adapter=MicrosoftSentinelIntelDeploymentAdapter(connector),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_stream_outcomes_are_reported_in_one_batch(
    mocker: MockerFixture, e2e_connector: Connector, router: GraphQLRouter
) -> None:
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[
            Mock(status_code=200),
            HttpResponseError(message="400 Invalid pattern"),
        ],
    )

    e2e_connector._handle_event(make_event("create", make_indicator()))
    with pytest.raises(ConnectorClientError):
        e2e_connector._handle_event(
            make_event(
                "create", make_indicator(indicator_id=OTHER_ID, stix_id=OTHER_STIX_ID)
            )
        )
    result = e2e_connector.assurance.flush()

    assert result.processed == 2
    assert router.calls_of("DeploymentSecurityPlatformAdd") == [
        {
            "input": {
                "name": "Microsoft Sentinel",
                "update": True,
                "security_platform_type": "SIEM",
            }
        }
    ]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    assert batch["platformId"] == PLATFORM_ID
    deployed, failed = batch["reports"]
    assert deployed == {"indicatorId": INDICATOR_ID, "status": "deployed"}
    assert failed["indicatorId"] == OTHER_ID
    assert failed["status"] == "failed"
    assert "400 Invalid pattern" in failed["metadata"]["error_message"]


def test_reconciliation_and_hits_are_reported(
    mocker: MockerFixture, e2e_connector: Connector, router: GraphQLRouter
) -> None:
    router.deployments = [
        deployment_node(INDICATOR_ID, INDICATOR_STIX_ID, "deployed"),
        deployment_node(OTHER_ID, OTHER_STIX_ID, "active"),
    ]
    activity = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[
            response({"value": [ti_object()]}),
            response(
                {
                    "value": [
                        {
                            "id": f"{WORKSPACE_PATH}/incidents/incident-1",
                            "properties": {"lastActivityTimeUtc": activity},
                        }
                    ]
                }
            ),
            response(
                {
                    "entities": [
                        {"kind": "Ip", "properties": {"address": "198.51.100.7"}}
                    ]
                }
            ),
        ],
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.vendor_indicators == 1
    assert summary.confirmed_active == 1
    assert summary.marked_removed == 1
    assert summary.hits_reported == 1
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report for report in batch["reports"]}
    assert reports[INDICATOR_ID]["status"] == "active"
    assert reports[INDICATOR_ID]["externalId"] == RESOURCE_ID.rsplit("/", 1)[-1]
    assert reports[OTHER_ID]["status"] == "removed"
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["indicatorId"] == INDICATOR_ID
    assert hits["count"] == 1


def test_withdrawal_deletes_a_resource_sentinel_retains_revoked(
    mocker: MockerFixture, e2e_connector: Connector, router: GraphQLRouter
) -> None:
    """A revoked TI object stays in Sentinel: the withdrawal still deletes it."""
    router.deployments = [
        deployment_node(INDICATOR_ID, INDICATOR_STIX_ID, "active", revoked=True)
    ]
    send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[response({"value": [ti_object(revoked=True)]}), response({})],
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert (summary.withdrawn, summary.discovered) == (1, 0)
    deleted = [
        call.kwargs["request"].url
        for call in send_request.call_args_list
        if call.kwargs["request"].method == "DELETE"
    ]
    assert len(deleted) == 1 and RESOURCE_ID in deleted[0]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    assert batch["reports"][0]["status"] == "removed"


def test_withdrawal_deletes_every_resource_of_the_stix_id(
    mocker: MockerFixture, e2e_connector: Connector, router: GraphQLRouter
) -> None:
    """Duplicate TI objects of one STIX id are all deleted before `removed`."""
    router.deployments = [
        deployment_node(INDICATOR_ID, INDICATOR_STIX_ID, "active", revoked=True)
    ]
    duplicate_id = f"{RESOURCE_ID}-duplicate"
    send_request = mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=[
            response({"value": [ti_object(), ti_object(resource_id=duplicate_id)]}),
            response({}),
            response({}),
        ],
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.withdrawn == 1
    assert summary.discovered == 0
    deleted = [
        call.kwargs["request"].url
        for call in send_request.call_args_list
        if call.kwargs["request"].method == "DELETE"
    ]
    assert len(deleted) == 2
    assert RESOURCE_ID in deleted[0] and duplicate_id in deleted[1]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    assert batch["reports"][0]["status"] == "removed"


def test_read_back_failure_skips_the_reconciliation(
    mocker: MockerFixture, e2e_connector: Connector, router: GraphQLRouter
) -> None:
    router.deployments = [deployment_node(INDICATOR_ID, INDICATOR_STIX_ID, "active")]
    mocker.patch(
        "microsoft_sentinel_intel.client.PipelineClient.send_request",
        side_effect=HttpResponseError(message="503 Service Unavailable"),
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is True
    assert router.calls_of("IndicatorReportDeployments(") == []
