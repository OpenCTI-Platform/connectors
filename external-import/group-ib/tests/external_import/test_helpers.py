from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from connector.connector import ExternalImportConnector

# --- Helpers ------------------------------------------------------------------


def _bare_connector() -> ExternalImportConnector:
    """Bypass the heavy ``__init__`` (which talks to the OpenCTI platform)
    and return an instance with the attributes our tests touch.
    """
    inst = ExternalImportConnector.__new__(ExternalImportConnector)
    inst.helper = SimpleNamespace(
        connector_logger=MagicMock(),
        connect_name="Group-IB Connector",
        get_state=MagicMock(return_value=None),
        set_state=MagicMock(),
    )
    inst.cfg = SimpleNamespace(get_extra_settings_by_name=MagicMock(return_value=None))
    return inst


# --- _is_transient_network_error ---------------------------------------------


class _FakeConnectionError(Exception):
    pass


_FakeConnectionError.__name__ = "ConnectionError"


class _FakeReadTimeout(Exception):
    pass


_FakeReadTimeout.__name__ = "ReadTimeout"


class _FakeProtocolError(Exception):
    pass


_FakeProtocolError.__name__ = "ProtocolError"


class TestIsTransientNetworkError:
    def test_direct_connection_error(self):
        assert (
            ExternalImportConnector._is_transient_network_error(
                _FakeConnectionError("boom")
            )
            is True
        )

    def test_direct_read_timeout(self):
        assert (
            ExternalImportConnector._is_transient_network_error(
                _FakeReadTimeout("slow")
            )
            is True
        )

    def test_direct_protocol_error(self):
        assert (
            ExternalImportConnector._is_transient_network_error(
                _FakeProtocolError("reset")
            )
            is True
        )

    def test_remote_disconnected(self):
        class RemoteDisconnected(Exception):
            pass

        assert (
            ExternalImportConnector._is_transient_network_error(
                RemoteDisconnected("eof")
            )
            is True
        )

    def test_chained_cause_matches(self):
        # Wrapped/nested errors must still be classified as transient when
        # ANY link in the ``__cause__`` chain matches a known transient name.
        inner = _FakeConnectionError("network drop")
        outer = RuntimeError("wrapper")
        outer.__cause__ = inner
        assert ExternalImportConnector._is_transient_network_error(outer) is True

    def test_chained_context_matches(self):
        inner = _FakeReadTimeout("slow")
        outer = RuntimeError("wrapper")
        outer.__context__ = inner
        assert ExternalImportConnector._is_transient_network_error(outer) is True

    def test_unknown_error_is_not_transient(self):
        assert (
            ExternalImportConnector._is_transient_network_error(ValueError("bad data"))
            is False
        )

    def test_keyboard_interrupt_not_transient(self):
        # Match by type name only, so unrelated BaseException stays False.
        assert (
            ExternalImportConnector._is_transient_network_error(KeyboardInterrupt())
            is False
        )

    def test_self_referential_cause_does_not_loop(self):
        # Defensive: the walker must terminate even if the cause chain
        # points back to the same exception object (would otherwise loop
        # forever).
        exc = ValueError("loop")
        exc.__cause__ = exc
        # Doesn't hang; not transient.
        assert ExternalImportConnector._is_transient_network_error(exc) is False


# --- _event_hint --------------------------------------------------------------


class TestEventHint:
    def test_top_level_id(self):
        # The walker first inspects nested-dict values; only if none of them
        # carry an id does it return the top-level ``id`` (this matches the
        # current implementation order, which prefers the inner-payload id).
        evt = {"id": "TOP"}
        # No nested dict carries an id → top-level id wins.
        assert ExternalImportConnector._event_hint(evt) == "TOP"

    def test_inner_dict_id_preferred(self):
        # When a nested dict carries an ``id`` field it is returned in
        # preference to a top-level ``id`` on the event itself.
        evt = {"id": "TOP", "threat_report": {"id": "INNER"}}
        assert ExternalImportConnector._event_hint(evt) == "INNER"

    def test_first_inner_id_wins_over_others(self):
        evt = {
            "first": {"id": "A"},
            "second": {"id": "B"},
        }
        # Order of dict insertion in CPython 3.7+ is preserved.
        assert ExternalImportConnector._event_hint(evt) == "A"

    def test_no_id_anywhere_returns_unknown(self):
        assert ExternalImportConnector._event_hint({}) == "unknown"
        assert ExternalImportConnector._event_hint({"foo": "bar"}) == "unknown"

    def test_non_dict_event_returns_unknown(self):
        assert ExternalImportConnector._event_hint(None) == "unknown"
        assert ExternalImportConnector._event_hint("scalar") == "unknown"
        assert ExternalImportConnector._event_hint(42) == "unknown"
        assert ExternalImportConnector._event_hint([1, 2, 3]) == "unknown"

    def test_long_id_truncated_to_128(self):
        long_id = "x" * 500
        evt = {"id": long_id}
        out = ExternalImportConnector._event_hint(evt)
        assert len(out) == 128

    def test_int_id_coerced_to_str(self):
        evt = {"section": {"id": 9876543210}}
        assert ExternalImportConnector._event_hint(evt) == "9876543210"


# --- check_generator / check_enable ------------------------------------------


class TestCheckGenerator:
    def test_truthy_generator(self):
        c = _bare_connector()
        assert c.check_generator(iter([1]), "apt/threat") is True
        c.helper.connector_logger.warning.assert_not_called()

    def test_none_generator_warns_and_returns_false(self):
        c = _bare_connector()
        assert c.check_generator(None, "apt/threat") is False
        c.helper.connector_logger.warning.assert_called_once()
        # The warning text must mention the offending collection slug.
        call_args = str(c.helper.connector_logger.warning.call_args)
        assert "apt/threat" in call_args


class TestCheckEnable:
    def test_enabled_returns_true(self):
        c = _bare_connector()
        assert c.check_enable(True, "apt/threat") is True
        c.helper.connector_logger.warning.assert_not_called()

    def test_disabled_returns_false(self):
        c = _bare_connector()
        assert c.check_enable(False, "apt/threat") is False
        c.helper.connector_logger.warning.assert_called_once()
        call_args = str(c.helper.connector_logger.warning.call_args)
        assert "apt/threat" in call_args

    def test_none_treated_as_disabled(self):
        c = _bare_connector()
        assert c.check_enable(None, "apt/threat") is False
        c.helper.connector_logger.warning.assert_called_once()


# --- get_formatted_utcfromtimestamp ------------------------------------------


class TestGetFormattedUtcFromTimestamp:
    def test_default_format(self):
        c = _bare_connector()
        c.cfg.get_extra_settings_by_name = MagicMock(return_value=None)
        # Epoch 0 -> 1970-01-01 in UTC.
        out = c.get_formatted_utcfromtimestamp(0)
        assert out == "1970-01-01 00:00:00"

    def test_custom_format_from_config(self):
        c = _bare_connector()
        c.cfg.get_extra_settings_by_name = MagicMock(return_value="%Y-%m-%d")
        out = c.get_formatted_utcfromtimestamp(0)
        assert out == "1970-01-01"

    def test_invalid_format_passes_through_without_crash(self):
        # ``strftime("%Q")`` is platform-dependent — glibc raises on
        # unknown directives, BSD/macOS silently echoes them. We only
        # care that the wrapper doesn't blow up on a non-canonical
        # format string.
        c = _bare_connector()
        c.cfg.get_extra_settings_by_name = MagicMock(return_value="%Q")
        out = c.get_formatted_utcfromtimestamp(0)
        assert isinstance(out, str)
        assert len(out) > 0

    def test_non_int_timestamp_invalid_fallback(self):
        c = _bare_connector()
        c.cfg.get_extra_settings_by_name = MagicMock(return_value=None)
        # Float epoch is accepted by datetime.fromtimestamp.
        assert c.get_formatted_utcfromtimestamp(1.5) == "1970-01-01 00:00:01"


# --- set_or_update_state ------------------------------------------------------


class TestSetOrUpdateState:
    def test_no_state_no_args_noop(self):
        c = _bare_connector()
        c.helper.get_state = MagicMock(return_value=None)
        c.set_or_update_state()
        # Even with both args empty, we still write {} so the platform
        # gets a non-null state.
        c.helper.set_state.assert_called_once_with({})

    def test_timestamp_only(self):
        c = _bare_connector()
        c.helper.get_state = MagicMock(return_value=None)
        c.set_or_update_state(timestamp=1700000000)
        c.helper.set_state.assert_called_once_with({"last_run": 1700000000})

    def test_prepared_data_only(self):
        c = _bare_connector()
        c.helper.get_state = MagicMock(return_value=None)
        c.set_or_update_state(prepared_data={"apt/threat": {"sequpdate": "1"}})
        c.helper.set_state.assert_called_once_with({"apt/threat": {"sequpdate": "1"}})

    def test_merges_into_existing_state(self):
        c = _bare_connector()
        c.helper.get_state = MagicMock(
            return_value={
                "last_run": 1600000000,
                "apt/threat": {"sequpdate": "old"},
            }
        )
        c.set_or_update_state(
            timestamp=1700000000,
            prepared_data={"apt/threat": {"sequpdate": "new"}},
        )
        merged = c.helper.set_state.call_args[0][0]
        assert merged["last_run"] == 1700000000
        assert merged["apt/threat"] == {"sequpdate": "new"}

    def test_falsy_timestamp_zero_skipped(self):
        # The ``if timestamp:`` guard means 0/None don't overwrite an
        # existing last_run — important for the dry-run code path.
        c = _bare_connector()
        c.helper.get_state = MagicMock(return_value={"last_run": 42})
        c.set_or_update_state(timestamp=0)
        merged = c.helper.set_state.call_args[0][0]
        assert merged["last_run"] == 42

    def test_empty_prepared_data_dict_skipped(self):
        # ``if prepared_data:`` — empty dict is falsy, no merge.
        c = _bare_connector()
        c.helper.get_state = MagicMock(return_value={"x": 1})
        c.set_or_update_state(prepared_data={})
        merged = c.helper.set_state.call_args[0][0]
        assert merged == {"x": 1}


# --- get_last_run -------------------------------------------------------------


class TestGetLastRun:
    def test_returns_last_run_from_state(self):
        c = _bare_connector()
        out = c.get_last_run({"last_run": 1700000000})
        assert out == 1700000000

    def test_logs_human_readable_timestamp(self):
        c = _bare_connector()
        c.cfg.get_extra_settings_by_name = MagicMock(return_value=None)
        c.get_last_run({"last_run": 0})
        c.helper.connector_logger.info.assert_called_once()
        # Info log must include the formatted date so operators can grep it.
        call_args = str(c.helper.connector_logger.info.call_args)
        assert "1970-01-01" in call_args

    def test_returns_none_when_state_is_none(self):
        c = _bare_connector()
        out = c.get_last_run(None)
        assert out is None
        # "Has never run" message must be emitted for first-run telemetry.
        c.helper.connector_logger.info.assert_called_once()
        call_args = str(c.helper.connector_logger.info.call_args)
        assert "never run" in call_args.lower()

    def test_returns_none_when_state_lacks_last_run(self):
        c = _bare_connector()
        out = c.get_last_run({"some_other_key": 1})
        assert out is None
