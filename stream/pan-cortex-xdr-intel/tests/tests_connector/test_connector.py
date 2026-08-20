import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.connector import Connector
from connector.models import IndicatorObservable
from pydantic import ValidationError


def _make_msg(event: str, data: dict) -> SimpleNamespace:
    """Build a fake SSE stream event (attributes: `data`, `event`, `id`)."""
    return SimpleNamespace(event=event, data=json.dumps({"data": data}), id="1-0")


@pytest.fixture
def connector():
    return Connector(helper=MagicMock(), settings=MagicMock(), client=MagicMock())


class TestProcessMessageEventGuardrail:
    def test_connector_skips_unsupported_event_without_parsing(
        self, connector, monkeypatch
    ):
        # Given: a stream event whose action is not one of create/update/delete
        parse_indicator = MagicMock()
        monkeypatch.setattr(connector, "_parse_indicator", parse_indicator)
        msg = _make_msg("invalid-event", {"type": "identity", "name": "Test Identity"})
        # When: processing the message
        connector._process_message(msg)
        # Then: no indicator parsing is attempted (the invalid JSON body is
        # never even parsed)
        parse_indicator.assert_not_called()


class TestProcessMessageEntityGuardrail:
    def test_connector_skips_non_indicator_entity_without_parsing(
        self, connector, monkeypatch
    ):
        # Given: a stream event for a non-Indicator entity (e.g. an Identity)
        parse_indicator = MagicMock()
        monkeypatch.setattr(connector, "_parse_indicator", parse_indicator)
        msg = _make_msg("create", {"type": "identity", "name": "Test Identity"})
        # When: processing the message
        connector._process_message(msg)
        # Then: no indicator parsing is attempted
        parse_indicator.assert_not_called()

    def test_connector_skips_event_missing_data_without_parsing(
        self, connector, monkeypatch
    ):
        # Given: a stream event payload without a top-level "data" key
        parse_indicator = MagicMock()
        monkeypatch.setattr(connector, "_parse_indicator", parse_indicator)
        msg = SimpleNamespace(event="create", data=json.dumps({}), id="1-0")
        # When: processing the message
        connector._process_message(msg)
        # Then: it is treated as a non-Indicator event, no indicator parsing
        # is attempted
        parse_indicator.assert_not_called()


class TestParseIndicator:
    def test_connector_extracts_supported_observable(self, connector):
        # Given: an Indicator whose `observable_values` extension attribute
        # contains a single MVP-supported (domain) observable
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Domain-Name", "value": "evil.com"}],
        }.get(key)
        # When: parsing the indicator
        indicator = connector._parse_indicator({"type": "indicator"})
        # Then: the observable is extracted
        assert indicator.observables == [
            IndicatorObservable(type="Domain-Name", value="evil.com")
        ]

    def test_connector_filters_out_unsupported_observable_type(self, connector):
        # Given: an Indicator whose `observable_values` only contains an
        # unsupported observable type (e.g. Mutex)
        connector.helper.get_attribute_in_extension.side_effect = lambda key, data: {
            "id": "indicator--id",
            "observable_values": [{"type": "Mutex", "value": "some-mutex"}],
        }.get(key)
        # When: parsing the indicator
        indicator = connector._parse_indicator({"type": "indicator"})
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
        # When: parsing the indicator
        indicator = connector._parse_indicator({"type": "indicator"})
        # Then: no observable is extracted, no crash
        assert indicator.observables == []


class TestProcessMessageErrorHandling:
    # Fatal errors

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
        # (required by `EventIndicator`), causing `_parse_indicator` to raise
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

    @pytest.mark.xfail(
        reason=(
            "Upsert/delete client calls are not implemented yet (see #7186/#7187); "
            "the try/except around them currently only wraps `pass` placeholders, "
            "so this expected error-handling behavior cannot be exercised yet. "
            "Remove this xfail marker once real client calls land in that block."
        ),
        strict=True,
    )
    def test_connector_logs_error_and_reraises_on_unexpected_processing_error(
        self, connector
    ):
        # Given: the Cortex XDR client unexpectedly raises while upserting/deleting
        connector.client.upsert_indicator.side_effect = RuntimeError("boom")
        connector.client.delete_indicator.side_effect = RuntimeError("boom")
        msg = _make_msg("create", {"type": "indicator"})
        # When: processing the message
        # Then: the error is logged with context, and the exception is deliberately
        # re-raised to let `pycti` kill the connector process
        with pytest.raises(RuntimeError, match="boom"):
            connector._process_message(msg)
        connector.helper.connector_logger.error.assert_called_once()
