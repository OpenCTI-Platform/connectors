import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.connector import Connector
from connector.models import CortexXdrIoc, OctiIndicator, OctiIndicatorObservable
from connectors_sdk import (
    ApiForbiddenError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
)
from cortex_xdr_client import CortexXdrApiError
from pydantic import ValidationError


def _make_msg(event: str, data: dict) -> SimpleNamespace:
    """Build a fake SSE stream event (attributes: `data`, `event`, `id`)."""
    return SimpleNamespace(event=event, data=json.dumps({"data": data}), id="1-0")


@pytest.fixture
def connector():
    client = MagicMock()
    # By default, no existing IOC is found on Cortex XDR (fresh insert case).
    client.get_iocs.return_value = {"objects": []}
    return Connector(helper=MagicMock(), settings=MagicMock(), client=client)


class TestProcessMessageEventGuardrail:
    def test_connector_skips_unsupported_event_without_parsing(
        self, connector, monkeypatch
    ):
        # Given: a stream event whose action is not one of create/update/delete
        build_indicator = MagicMock()
        monkeypatch.setattr(connector, "_build_octi_indicator", build_indicator)
        msg = _make_msg("invalid-event", {"type": "identity", "name": "Test Identity"})
        # When: processing the message
        connector._process_message(msg)
        # Then: no indicator parsing is attempted (the invalid JSON body is
        # never even parsed)
        build_indicator.assert_not_called()


class TestProcessMessageEntityGuardrail:
    def test_connector_skips_non_indicator_entity_without_parsing(
        self, connector, monkeypatch
    ):
        # Given: a stream event for a non-Indicator entity (e.g. an Identity)
        build_indicator = MagicMock()
        monkeypatch.setattr(connector, "_build_octi_indicator", build_indicator)
        msg = _make_msg("create", {"type": "identity", "name": "Test Identity"})
        # When: processing the message
        connector._process_message(msg)
        # Then: no indicator parsing is attempted
        build_indicator.assert_not_called()

    def test_connector_skips_event_missing_data_without_parsing(
        self, connector, monkeypatch
    ):
        # Given: a stream event payload without a top-level "data" key
        build_indicator = MagicMock()
        monkeypatch.setattr(connector, "_build_octi_indicator", build_indicator)
        msg = SimpleNamespace(event="create", data=json.dumps({}), id="1-0")
        # When: processing the message
        connector._process_message(msg)
        # Then: it is treated as a non-Indicator event, no indicator parsing
        # is attempted
        build_indicator.assert_not_called()


class TestBuildIndicator:
    def test_connector_extracts_supported_observable(self, connector):
        # Given: an Indicator whose `observable_values` extension attribute
        # contains a single MVP-supported (domain) observable
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        # When: building the indicator
        indicator = connector._build_octi_indicator({"type": "indicator"})
        # Then: the observable is extracted
        assert indicator.observables == [
            OctiIndicatorObservable(type="Domain-Name", value="evil.com")
        ]

    def test_connector_filters_out_unsupported_observable_type(self, connector):
        # Given: an Indicator whose `observable_values` only contains an
        # unsupported observable type (e.g. Mutex)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Mutex", "value": "some-mutex"}],
        }.get(key)
        # When: building the indicator
        indicator = connector._build_octi_indicator({"type": "indicator"})
        # Then: no observable is extracted
        assert indicator.observables == []

    def test_connector_filters_out_hostname_observable_type(self, connector):
        # Given: an Indicator whose `observable_values` only contains a
        # Hostname observable (support intentionally dropped, see #7187)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Hostname", "value": "evil.com"}],
        }.get(key)
        # When: building the indicator
        indicator = connector._build_octi_indicator({"type": "indicator"})
        # Then: no observable is extracted
        assert indicator.observables == []

    def test_connector_defaults_to_no_observables_when_extension_attribute_missing(
        self, connector
    ):
        # Given: an Indicator without an `observable_values` extension attribute
        # (e.g. older OpenCTI version, or non-STIX pattern indicator)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": None,
        }.get(key)
        # When: building the indicator
        indicator = connector._build_octi_indicator({"type": "indicator"})
        # Then: no observable is extracted, no crash
        assert indicator.observables == []


class TestProcessMessageUnsupportedObservableGuardrail:
    def test_connector_skips_indicator_without_any_supported_observable(
        self, connector
    ):
        # Given: an Indicator whose observables are all of an unsupported type
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Hostname", "value": "evil.com"}],
        }.get(key)
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        connector._process_message(msg)
        # Then: the indicator is skipped with a warning, before it is even
        # logged as successfully parsed
        connector.helper.connector_logger.warning.assert_called_once()
        connector.helper.connector_logger.info.assert_not_called()

    def test_connector_processes_indicator_with_at_least_one_supported_observable(
        self, connector
    ):
        # Given: an Indicator mixing an unsupported and a supported observable
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [
                {"type": "Hostname", "value": "evil.com"},
                {"type": "Domain-Name", "value": "evil.com"},
            ],
        }.get(key)
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        connector._process_message(msg)
        # Then: the indicator is parsed and logged, no warning is logged
        connector.helper.connector_logger.warning.assert_not_called()
        assert connector.helper.connector_logger.info.called


class TestProcessMessageErrorHandling:
    # Fatal errors: always kill the connector

    def test_connector_logs_error_and_reraises_on_invalid_json(self, connector):
        # Given: a stream event whose `data` is not valid JSON
        msg = SimpleNamespace(event="create", data="not-json", id="1-0")
        # When: processing the message
        # Then: the error is logged with context, and the exception is deliberately
        # re-raised to let `pycti` kill the connector process
        with pytest.raises(json.JSONDecodeError):
            connector._process_message(msg)
        connector.helper.connector_logger.error.assert_called_once()

    def test_connector_logs_error_and_reraises_when_indicator_id_missing(
        self, connector
    ):
        # Given: an Indicator stream event missing its "id" extension attribute
        # (required by `OctiIndicator`), causing `_build_octi_indicator` to raise
        # a `ValidationError`
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": None,
            "observable_values": None,
        }.get(key)
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        # Then: the error is logged with context, and the exception is deliberately
        # re-raised to let `pycti` kill the connector process
        with pytest.raises(ValidationError):
            connector._process_message(msg)
        connector.helper.connector_logger.error.assert_called_once()

    def test_connector_logs_error_and_reraises_on_unexpected_upsert_error(
        self, connector
    ):
        # Given: the Cortex XDR client unexpectedly raises a non-`CortexXdrApiError`
        # while upserting
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        connector.client.insert_iocs.side_effect = RuntimeError("boom")
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        # Then: the error is logged with context, and the exception is deliberately
        # re-raised to let `pycti` kill the connector process
        with pytest.raises(RuntimeError, match="boom"):
            connector._process_message(msg)
        connector.helper.connector_logger.error.assert_called_once()

    @pytest.mark.parametrize(
        "cause_cls",
        [
            ApiUnauthorizedError,
            ApiForbiddenError,
            ApiNotFoundError,
            ApiRateLimitError,
            ApiServerError,
        ],
    )
    def test_connector_logs_error_and_reraises_on_fatal_api_error_cause(
        self, connector, cause_cls
    ):
        # Given: the Cortex XDR client raises a `CortexXdrApiError` wrapping a
        # fatal cause (auth/permission/rate-limit/server errors)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        try:
            raise cause_cls("boom")
        except cause_cls as cause:
            api_error = CortexXdrApiError("Error while fetching Cortex XDR API")
            api_error.__cause__ = cause
        connector.client.insert_iocs.side_effect = api_error
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        # Then: the error is logged with context, and the exception is deliberately
        # re-raised to let `pycti` kill the connector process, avoiding exhausting
        # the stream with repeated global failures
        with pytest.raises(CortexXdrApiError):
            connector._process_message(msg)
        connector.helper.connector_logger.error.assert_called_once()

    # Non-fatal errors: skip the event, keep the stream alive

    def test_connector_logs_error_and_continues_on_non_fatal_api_error_cause(
        self, connector
    ):
        # Given: the Cortex XDR client raises a `CortexXdrApiError` whose cause
        # is not one of the fatal causes (e.g. a rejected IOC value, 400)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        api_error = CortexXdrApiError("Error while fetching Cortex XDR API")
        api_error.__cause__ = ValueError("rejected IOC value")
        connector.client.insert_iocs.side_effect = api_error
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        # Then: the error is logged, the event is skipped, and no exception
        # propagates so the stream keeps processing the next event
        connector._process_message(msg)
        connector.helper.connector_logger.error.assert_called_once()

    def test_connector_logs_error_and_continues_when_api_error_has_no_cause(
        self, connector
    ):
        # Given: the Cortex XDR client raises a `CortexXdrApiError` without any
        # chained cause at all (defensive edge case)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        connector.client.insert_iocs.side_effect = CortexXdrApiError("boom")
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        # Then: it is treated as non-fatal: logged, event skipped, no re-raise
        connector._process_message(msg)
        connector.helper.connector_logger.error.assert_called_once()

    def test_connector_logs_error_and_reraises_on_unexpected_delete_error(
        self, connector
    ):
        # Given: the Cortex XDR client unexpectedly raises while deleting
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        connector.client.delete_iocs.side_effect = RuntimeError("boom")
        msg = _make_msg("delete", {"type": "indicator"})
        # When: processing the message
        # Then: the error is logged with context, and the exception is deliberately
        # re-raised to let `pycti` kill the connector process
        with pytest.raises(RuntimeError, match="boom"):
            connector._process_message(msg)
        connector.helper.connector_logger.error.assert_called_once()


class TestProcessMessageUpsertRouting:
    def test_connector_calls_handle_upsert_on_create_event(
        self, connector, monkeypatch
    ):
        # Given: a "create" stream event for an Indicator with a supported observable
        handle_upsert = MagicMock()
        monkeypatch.setattr(connector, "_handle_upsert", handle_upsert)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        connector._process_message(msg)
        # Then: the upsert lifecycle is triggered
        handle_upsert.assert_called_once()

    def test_connector_calls_handle_upsert_on_update_event(
        self, connector, monkeypatch
    ):
        # Given: an "update" stream event for an Indicator with a supported observable
        handle_upsert = MagicMock()
        monkeypatch.setattr(connector, "_handle_upsert", handle_upsert)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        msg = _make_msg("update", {"type": "indicator"})
        # When: processing the message
        connector._process_message(msg)
        # Then: the upsert lifecycle is triggered
        handle_upsert.assert_called_once()

    def test_connector_does_not_call_handle_upsert_on_delete_event(
        self, connector, monkeypatch
    ):
        # Given: a "delete" stream event for an Indicator with a supported observable
        handle_upsert = MagicMock()
        monkeypatch.setattr(connector, "_handle_upsert", handle_upsert)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        msg = _make_msg("delete", {"type": "indicator"})
        # When: processing the message
        connector._process_message(msg)
        # Then: the upsert lifecycle is not triggered (delete events trigger
        # the delete lifecycle instead, see `TestProcessMessageDeleteRouting`)
        handle_upsert.assert_not_called()


class TestProcessMessageDeleteRouting:
    def test_connector_calls_handle_delete_on_delete_event(
        self, connector, monkeypatch
    ):
        # Given: a "delete" stream event for an Indicator with a supported observable
        handle_delete = MagicMock()
        monkeypatch.setattr(connector, "_handle_delete", handle_delete)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        msg = _make_msg("delete", {"type": "indicator"})
        # When: processing the message
        connector._process_message(msg)
        # Then: the delete lifecycle is triggered
        handle_delete.assert_called_once()

    def test_connector_does_not_call_handle_delete_on_create_event(
        self, connector, monkeypatch
    ):
        # Given: a "create" stream event for an Indicator with a supported observable
        handle_delete = MagicMock()
        monkeypatch.setattr(connector, "_handle_delete", handle_delete)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        connector._process_message(msg)
        # Then: the delete lifecycle is not triggered
        handle_delete.assert_not_called()

    def test_connector_does_not_call_handle_delete_on_update_event(
        self, connector, monkeypatch
    ):
        # Given: an "update" stream event for an Indicator with a supported observable
        handle_delete = MagicMock()
        monkeypatch.setattr(connector, "_handle_delete", handle_delete)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        msg = _make_msg("update", {"type": "indicator"})
        # When: processing the message
        connector._process_message(msg)
        # Then: the delete lifecycle is not triggered
        handle_delete.assert_not_called()


class TestExtractXdrIocs:
    def test_maps_domain_observable_to_domain_name_type(self, connector):
        # Given: an indicator with a supported Domain-Name observable
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "Domain-Name", "value": "evil.com"}],
        )
        # When: extracting Cortex XDR IOCs
        xdr_iocs = connector._extract_xdr_iocs(indicator)
        # Then: the observable is mapped to a bare DOMAIN_NAME IOC (optional
        # fields are only set later by `_map_indicator_fields_to_xdr_iocs`)
        assert xdr_iocs == [CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")]

    def test_maps_ip_observable_to_ip_type(self, connector):
        # Given: an indicator with a supported IPv4-Addr observable
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "IPv4-Addr", "value": "1.2.3.4"}],
        )
        # When: extracting Cortex XDR IOCs
        xdr_iocs = connector._extract_xdr_iocs(indicator)
        # Then: the observable is mapped to a bare IP IOC
        assert xdr_iocs == [CortexXdrIoc(indicator="1.2.3.4", type="IP")]

    def test_maps_stixfile_hash_observable_to_hash_type(self, connector):
        # Given: an indicator with a StixFile hash observable
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "StixFile", "hashes": {"SHA-256": "deadbeef"}}],
        )
        # When: extracting Cortex XDR IOCs
        xdr_iocs = connector._extract_xdr_iocs(indicator)
        # Then: the hash is mapped to a bare HASH IOC
        assert xdr_iocs == [CortexXdrIoc(indicator="deadbeef", type="HASH")]

    def test_skips_unsupported_observable_type(self, connector):
        # Given: an indicator with only a StixFile filename observable
        # (Cortex XDR's FILENAME IOC type is out of scope for now, see #7186)
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "StixFile", "name": "evil.exe"}],
        )
        # When: extracting Cortex XDR IOCs
        xdr_iocs = connector._extract_xdr_iocs(indicator)
        # Then: no IOC is built (silently skipped; only `_handle_upsert`/
        # `_handle_delete` log when the final list ends up empty)
        assert xdr_iocs == []

    def test_skips_hostname_observable_type(self, connector):
        # Given: an indicator with a Hostname observable (support
        # intentionally dropped, see #7187)
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "Hostname", "value": "evil.com"}],
        )
        # When: extracting Cortex XDR IOCs
        xdr_iocs = connector._extract_xdr_iocs(indicator)
        # Then: no IOC is built
        assert xdr_iocs == []

    def test_handles_indicator_without_any_observable(self, connector):
        # Given: an indicator with no observables at all
        indicator = OctiIndicator(id="indicator--id", observables=[])
        # When: extracting Cortex XDR IOCs
        xdr_iocs = connector._extract_xdr_iocs(indicator)
        # Then: no IOC is built, no crash
        assert xdr_iocs == []


class TestMapIndicatorFieldsToXdrIocs:
    def test_hardcodes_reputation_to_bad(self, connector):
        # Given: a bare Cortex XDR IOC and any indicator
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "Domain-Name", "value": "evil.com"}],
        )
        xdr_iocs = [CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")]
        # When: mapping the indicator's fields onto the IOC(s)
        result = connector._map_indicator_fields_to_xdr_iocs(indicator, xdr_iocs)
        # Then: the IOC's reputation is hardcoded to "BAD"
        assert result[0].reputation == "BAD"

    def test_includes_expiration_date_when_valid_until_present(self, connector):
        # Given: an indicator with a `valid_until` value
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "Domain-Name", "value": "evil.com"}],
            valid_until="2030-01-01T00:00:00Z",
        )
        xdr_iocs = [CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")]
        # When: mapping the indicator's fields onto the IOC(s)
        result = connector._map_indicator_fields_to_xdr_iocs(indicator, xdr_iocs)
        # Then: the IOC's expiration date is set as epoch milliseconds
        assert result[0].expiration_date == 1893456000000

    def test_omits_expiration_date_when_valid_until_absent(self, connector):
        # Given: an indicator without a `valid_until` value
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "Domain-Name", "value": "evil.com"}],
        )
        xdr_iocs = [CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")]
        # When: mapping the indicator's fields onto the IOC(s)
        result = connector._map_indicator_fields_to_xdr_iocs(indicator, xdr_iocs)
        # Then: no expiration date is set on the IOC
        assert result[0].expiration_date is None

    @pytest.mark.parametrize(
        "score,expected_severity",
        [
            (None, None),
            (10, None),
            (20, "SEV_010_INFO"),
            (40, "SEV_020_LOW"),
            (60, "SEV_030_MEDIUM"),
            (80, "SEV_040_HIGH"),
            (100, "SEV_040_HIGH"),
        ],
    )
    def test_maps_score_to_severity(self, connector, score, expected_severity):
        # Given: an indicator with a given `score`
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "Domain-Name", "value": "evil.com"}],
            score=score,
        )
        xdr_iocs = [CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")]
        # When: mapping the indicator's fields onto the IOC(s)
        result = connector._map_indicator_fields_to_xdr_iocs(indicator, xdr_iocs)
        # Then: the score is mapped to the expected Cortex XDR severity
        assert result[0].severity == expected_severity

    def test_handles_empty_xdr_iocs_list(self, connector):
        # Given: an indicator and an empty list of Cortex XDR IOCs
        indicator = OctiIndicator(id="indicator--id", observables=[])
        # When: mapping the indicator's fields onto the (empty) IOC list
        result = connector._map_indicator_fields_to_xdr_iocs(indicator, [])
        # Then: no IOC is built, no crash
        assert result == []


class TestResolveXdrIocsRuleIds:
    def test_calls_get_iocs_with_indicator_values_filter(self, connector):
        # Given: two extracted Cortex XDR IOCs
        xdr_iocs = [
            CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME"),
            CortexXdrIoc(indicator="1.2.3.4", type="IP"),
        ]
        # When: resolving their `rule_id`
        connector._resolve_xdr_iocs_rule_ids(xdr_iocs)
        # Then: the client is asked to look up both indicator values via an
        # "IN" filter on the "indicator" field
        connector.client.get_iocs.assert_called_once_with(
            [
                {
                    "field": "indicator",
                    "operator": "IN",
                    "value": ["evil.com", "1.2.3.4"],
                }
            ]
        )

    def test_attaches_rule_id_when_ioc_already_exists(self, connector):
        # Given: an IOC that already exists on Cortex XDR
        xdr_iocs = [CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")]
        connector.client.get_iocs.return_value = {
            "objects": [{"rule_id": 42, "indicator": "evil.com", "type": "DOMAIN_NAME"}]
        }
        # When: resolving `rule_id`
        resolved = connector._resolve_xdr_iocs_rule_ids(xdr_iocs)
        # Then: the existing `rule_id` is attached, so a subsequent insert
        # overwrites the existing IOC instead of failing
        assert resolved[0].rule_id == 42

    def test_does_not_attach_rule_id_when_ioc_does_not_exist(self, connector):
        # Given: an IOC that does not exist on Cortex XDR yet
        xdr_iocs = [CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")]
        connector.client.get_iocs.return_value = {"objects": []}
        # When: resolving `rule_id`
        resolved = connector._resolve_xdr_iocs_rule_ids(xdr_iocs)
        # Then: no `rule_id` is attached, so a subsequent insert creates a new IOC
        assert resolved[0].rule_id is None

    def test_does_not_attach_rule_id_when_type_differs(self, connector):
        # Given: a lookup match on the same indicator value but a different
        # type (e.g. a same-looking value registered as a different IOC type)
        xdr_iocs = [CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")]
        connector.client.get_iocs.return_value = {
            "objects": [{"rule_id": 42, "indicator": "evil.com", "type": "IP"}]
        }
        # When: resolving `rule_id`
        resolved = connector._resolve_xdr_iocs_rule_ids(xdr_iocs)
        # Then: no `rule_id` is attached, since the existing IOC is of a different type
        assert resolved[0].rule_id is None

    def test_returns_empty_list_without_calling_client_when_no_iocs(self, connector):
        # Given: no extracted Cortex XDR IOCs at all
        # When: resolving `rule_id`
        resolved = connector._resolve_xdr_iocs_rule_ids([])
        # Then: the client is never called, and an empty list is returned
        connector.client.get_iocs.assert_not_called()
        assert resolved == []


class TestHandleUpsert:
    def test_calls_client_insert_iocs_with_extracted_iocs(self, connector):
        # Given: an indicator with a supported observable
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "Domain-Name", "value": "evil.com"}],
        )
        # When: handling the upsert
        connector._handle_upsert(indicator)
        # Then: the client is called once with the extracted IOC(s)
        connector.client.insert_iocs.assert_called_once_with(
            [{"indicator": "evil.com", "type": "DOMAIN_NAME", "reputation": "BAD"}]
        )

    def test_includes_rule_id_when_ioc_already_exists(self, connector):
        # Given: an indicator whose IOC already exists on Cortex XDR
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "Domain-Name", "value": "evil.com"}],
        )
        connector.client.get_iocs.return_value = {
            "objects": [{"rule_id": 42, "indicator": "evil.com", "type": "DOMAIN_NAME"}]
        }
        # When: handling the upsert
        connector._handle_upsert(indicator)
        # Then: the existing `rule_id` is included in the payload sent to
        # Cortex XDR, so the request overwrites the existing IOC instead of
        # failing with a 400 "IOC indicator exists"
        connector.client.insert_iocs.assert_called_once_with(
            [
                {
                    "indicator": "evil.com",
                    "type": "DOMAIN_NAME",
                    "reputation": "BAD",
                    "rule_id": 42,
                }
            ]
        )

    def test_skips_client_call_when_no_supported_observable(self, connector):
        # Given: an indicator with only unsupported observable(s)
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "StixFile", "name": "evil.exe"}],
        )
        # When: handling the upsert
        connector._handle_upsert(indicator)
        # Then: the client is never called
        connector.client.insert_iocs.assert_not_called()

    def test_logs_error_when_no_supported_observable(self, connector):
        # Given: an indicator with only unsupported observable(s)
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "StixFile", "name": "evil.exe"}],
        )
        # When: handling the upsert
        connector._handle_upsert(indicator)
        # Then: the skip is logged as an error, not a mere info
        connector.helper.connector_logger.error.assert_called_once()


class TestHandleDelete:
    def test_calls_client_delete_iocs_with_built_filter(self, connector):
        # Given: an indicator with a supported observable
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "Domain-Name", "value": "evil.com"}],
        )
        # When: handling the delete
        connector._handle_delete(indicator)
        # Then: the client is called once with a single batched "IN" filter
        connector.client.delete_iocs.assert_called_once_with(
            [{"field": "indicator", "operator": "IN", "value": ["evil.com"]}]
        )

    def test_batches_multiple_iocs_into_a_single_filter(self, connector):
        # Given: an indicator with several supported observables, one of
        # which (StixFile) yields more than one Cortex XDR IOC
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[
                {"type": "Domain-Name", "value": "evil.com"},
                {
                    "type": "StixFile",
                    "hashes": {"SHA-256": "deadbeef", "MD5": "beefdead"},
                },
            ],
        )
        # When: handling the delete
        connector._handle_delete(indicator)
        # Then: all the extracted IOCs' indicator values are batched into a
        # single "IN" filter
        connector.client.delete_iocs.assert_called_once_with(
            [
                {
                    "field": "indicator",
                    "operator": "IN",
                    "value": ["evil.com", "deadbeef", "beefdead"],
                }
            ]
        )

    def test_skips_client_call_when_no_supported_observable(self, connector):
        # Given: an indicator with only unsupported observable(s)
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "StixFile", "name": "evil.exe"}],
        )
        # When: handling the delete
        connector._handle_delete(indicator)
        # Then: the client is never called
        connector.client.delete_iocs.assert_not_called()

    def test_logs_error_when_no_supported_observable(self, connector):
        # Given: an indicator with only unsupported observable(s)
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[{"type": "StixFile", "name": "evil.exe"}],
        )
        # When: handling the delete
        connector._handle_delete(indicator)
        # Then: the skip is logged as an error, not a mere info
        connector.helper.connector_logger.error.assert_called_once()
