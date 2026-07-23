from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from connector.connector import ExternalImportConnector


def _connector() -> ExternalImportConnector:
    """Bare connector skeleton with the attributes the orchestration touches."""
    inst = ExternalImportConnector.__new__(ExternalImportConnector)
    inst.helper = MagicMock()
    inst.helper.connect_name = "Group-IB Connector"
    inst.helper.connect_id = "connector--abc"
    inst.helper.api = MagicMock()
    inst.helper.api.work = MagicMock()
    inst.helper.api.work.initiate_work = MagicMock(return_value="work-1")
    inst.helper.metric = MagicMock()
    inst.cfg = MagicMock()
    inst.cfg.get_collection_settings = MagicMock(return_value=None)
    inst.cfg.get_extra_settings_by_name = MagicMock(return_value=None)
    inst.cfg.get_extra_settings_bool = MagicMock(return_value=False)
    inst.ti_adapter = MagicMock()
    inst.ttl = None
    inst.MITRE_MAPPER = {}
    inst.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR = False
    inst.IGNORE_NON_MALWARE_DDOS = False
    inst.IGNORE_NON_INDICATOR_THREAT_REPORTS = False
    inst.IGNORE_NON_INDICATOR_THREATS = False
    inst.update_existing_data = False
    inst.interval = "PT4H"
    return inst


# --- _process / _process catch-all ------------------------------------------


class TestProcess:
    def test_calls_run_once(self):
        c = _connector()
        c._run_once = MagicMock()
        c.set_or_update_state = MagicMock()
        c._process()
        c._run_once.assert_called_once()
        c.set_or_update_state.assert_called_once()
        # Metric ticks updated.
        c.helper.metric.inc.assert_any_call("run_count")
        c.helper.metric.state.assert_any_call("running")

    def test_run_once_exception_logged_not_raised(self):
        c = _connector()
        c._run_once = MagicMock(side_effect=RuntimeError("boom"))
        c.set_or_update_state = MagicMock()
        # _process catches the inner exception and logs the traceback.
        c._process()
        c.helper.connector_logger.error.assert_called()
        # State still updates so subsequent ticks see the timestamp.
        c.set_or_update_state.assert_called_once()

    def test_keyboard_interrupt_propagates(self):
        c = _connector()
        c._run_once = MagicMock(side_effect=KeyboardInterrupt)
        with pytest.raises(KeyboardInterrupt):
            c._process()

    def test_outer_exception_marks_stopped(self):
        c = _connector()
        # Simulating a fatal failure outside the inner try/except — e.g.
        # get_state raises BEFORE _run_once runs.
        c.helper.get_state = MagicMock(side_effect=RuntimeError("outer"))
        c._run_once = MagicMock()
        c._process()
        c.helper.metric.state.assert_any_call("stopped")


# --- _run_once --------------------------------------------------------------


class TestRunOnce:
    def test_iterates_create_generators_output(self):
        c = _connector()
        c.ti_adapter.create_generators.return_value = [
            ("apt/threat", iter(["portion-1"])),
            ("hi/threat", iter([])),
        ]
        c._process_collection = MagicMock()
        with patch("connector.connector.get_mitre_mapper", return_value={"T1": "x"}):
            c._run_once(current_state=None, timestamp=1700000000)
        # _process_collection invoked per data_item.
        assert c._process_collection.call_count == 2
        # MITRE mapper cached on the connector.
        assert c.MITRE_MAPPER == {"T1": "x"}

    def test_refreshes_sequpdate_state(self):
        c = _connector()
        c.ti_adapter.create_generators.return_value = []
        with patch("connector.connector.get_mitre_mapper", return_value={}):
            c._run_once(
                current_state={"apt/threat": {"sequpdate": "123"}},
                timestamp=1700000000,
            )
        # The TI adapter keeps state by reference — we replace it each run.
        assert c.ti_adapter._collections_last_sequence_updates == {
            "apt/threat": {"sequpdate": "123"}
        }

    def test_none_state_treated_as_empty(self):
        c = _connector()
        c.ti_adapter.create_generators.return_value = []
        with patch("connector.connector.get_mitre_mapper", return_value={}):
            c._run_once(current_state=None, timestamp=0)
        assert c.ti_adapter._collections_last_sequence_updates == {}


# --- _process_collection ----------------------------------------------------


class TestProcessCollection:
    def test_skipped_when_generator_none(self):
        c = _connector()
        c._process_portion = MagicMock()
        c._process_collection(
            data_item=(("apt/threat", None), {"apt/threat": {}}),
            timestamp=1700000000,
        )
        c._process_portion.assert_not_called()
        # No Work created (initiate_work never called).
        c.helper.api.work.initiate_work.assert_not_called()

    def test_skipped_when_collection_disabled(self):
        c = _connector()
        # enable=False → check_enable returns False → return before Work.
        c.cfg.get_collection_settings = MagicMock(return_value=False)
        c._process_portion = MagicMock()
        c._process_collection(
            data_item=(("apt/threat", iter([])), {"apt/threat": {}}),
            timestamp=1700000000,
        )
        c._process_portion.assert_not_called()
        c.helper.api.work.initiate_work.assert_not_called()

    def test_skipped_when_no_new_data(self):
        c = _connector()
        c.cfg.get_collection_settings = MagicMock(return_value=True)
        # Generator with no items → first next() raises StopIteration → skip.
        c._process_portion = MagicMock()
        c._process_collection(
            data_item=(("apt/threat", iter([])), {"apt/threat": {}}),
            timestamp=1700000000,
        )
        c._process_portion.assert_not_called()
        c.helper.api.work.initiate_work.assert_not_called()

    def test_skipped_when_pre_peek_raises(self):
        c = _connector()
        c.cfg.get_collection_settings = MagicMock(return_value=True)

        # Generator that throws on first next() → handled via warning.
        def boom():
            yield 1 / 0  # noqa - intentional

        c._process_portion = MagicMock()
        c._process_collection(
            data_item=(("apt/threat", boom()), {"apt/threat": {}}),
            timestamp=1700000000,
        )
        c._process_portion.assert_not_called()
        c.helper.connector_logger.warning.assert_called()

    def test_initiates_work_and_processes_portion(self, monkeypatch):
        c = _connector()
        c.cfg.get_collection_settings = MagicMock(
            side_effect=lambda _k, key: True if key == "enable" else 30
        )
        portion = SimpleNamespace(sequpdate="555")
        c._process_portion = MagicMock()
        # Avoid the 3-second sleep inside _process_collection.
        monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
        c._process_collection(
            data_item=(("apt/threat", iter([portion])), {"apt/threat": {}}),
            timestamp=1700000000,
        )
        c.helper.api.work.initiate_work.assert_called_once()
        c._process_portion.assert_called_once()
        c.helper.api.work.to_processed.assert_called_once()

    def test_invalid_ttl_falls_back_to_none(self, monkeypatch):
        c = _connector()
        c.cfg.get_collection_settings = MagicMock(
            side_effect=lambda _k, key: (
                True if key == "enable" else "not-a-number" if key == "ttl" else None
            )
        )
        c._process_portion = MagicMock()
        portion = SimpleNamespace(sequpdate="x")
        monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
        c._process_collection(
            data_item=(("apt/threat", iter([portion])), {"apt/threat": {}}),
            timestamp=1,
        )
        assert c.ttl is None

    def test_transient_error_during_portion_warns(self, monkeypatch):
        # _process_portion raises a TimeoutError → classified as transient,
        # Work closed as "interrupted" not "failed".
        c = _connector()
        c.cfg.get_collection_settings = MagicMock(
            side_effect=lambda _k, key: True if key == "enable" else 30
        )

        class Timeout(Exception):
            pass

        Timeout.__name__ = "Timeout"
        c._process_portion = MagicMock(side_effect=Timeout("read drop"))
        monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
        c._process_collection(
            data_item=(
                ("apt/threat", iter([SimpleNamespace(sequpdate="x")])),
                {"apt/threat": {}},
            ),
            timestamp=1,
        )
        c.helper.api.work.to_processed.assert_called_once()
        call = c.helper.api.work.to_processed.call_args
        # in_error=False for transient drops.
        assert (
            call.args[2] is False
            if len(call.args) >= 3
            else call.kwargs.get("in_error") is False
        )

    def test_real_error_marks_work_failed(self, monkeypatch):
        c = _connector()
        c.cfg.get_collection_settings = MagicMock(
            side_effect=lambda _k, key: True if key == "enable" else 30
        )
        c._process_portion = MagicMock(side_effect=RuntimeError("real bug"))
        monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
        c._process_collection(
            data_item=(
                ("apt/threat", iter([SimpleNamespace(sequpdate="x")])),
                {"apt/threat": {}},
            ),
            timestamp=1,
        )
        c.helper.api.work.to_processed.assert_called_once()
        # Final to_processed call must say in_error=True.
        call = c.helper.api.work.to_processed.call_args
        args, kwargs = call.args, call.kwargs
        assert (len(args) >= 3 and args[2] is True) or kwargs.get("in_error") is True


# --- _process_portion -------------------------------------------------------


class TestProcessPortion:
    def _portion(self, events, sequpdate="seq-1"):
        p = MagicMock()
        p.parse_portion = MagicMock(return_value=events)
        p.sequpdate = sequpdate
        return p

    def test_sends_bundle_for_each_event(self):
        c = _connector()
        c._collect_intelligence = MagicMock(
            return_value=[SimpleNamespace(id="x", type="malware")]
        )
        c.helper.send_stix2_bundle = MagicMock()
        c.set_or_update_state = MagicMock()
        events = [{"id": "evt-1"}, {"id": "evt-2"}]
        with patch(
            "connector.connector.OpenCTIConnectorHelper.stix2_create_bundle",
            return_value="bundle-json",
        ):
            c._process_portion(
                collection="apt/threat",
                prepared_data={"apt/threat": {}},
                portion=self._portion(events),
                work_id="w-1",
            )
        # Two events emit two send_stix2_bundle calls.
        assert c.helper.send_stix2_bundle.call_count == 2
        # State updated with the portion sequpdate.
        assert c.set_or_update_state.called

    def test_empty_bundle_counted_as_skip(self):
        c = _connector()
        c._collect_intelligence = MagicMock(return_value=[])
        c.helper.send_stix2_bundle = MagicMock()
        c.set_or_update_state = MagicMock()
        c._process_portion(
            collection="apt/threat",
            prepared_data={"apt/threat": {}},
            portion=self._portion([{"id": "evt-1"}]),
            work_id="w-1",
        )
        # No bundles sent (empty output → skip).
        c.helper.send_stix2_bundle.assert_not_called()

    def test_none_bundle_normalised_to_empty(self):
        c = _connector()
        c._collect_intelligence = MagicMock(return_value=None)
        c.helper.send_stix2_bundle = MagicMock()
        c._process_portion(
            collection="apt/threat",
            prepared_data={"apt/threat": {}},
            portion=self._portion([{"id": "evt-1"}]),
            work_id="w-1",
        )
        # None means "no objects" — silent skip, no bundle, no crash.
        c.helper.send_stix2_bundle.assert_not_called()

    def test_event_failure_increments_error_metric_but_continues(self):
        c = _connector()
        # First event throws non-transient error, second works.
        calls = [0]

        def maybe_fail(**kwargs):
            calls[0] += 1
            if calls[0] == 1:
                raise ValueError("bad")
            return [SimpleNamespace(id="x", type="malware")]

        c._collect_intelligence = MagicMock(side_effect=maybe_fail)
        c.helper.send_stix2_bundle = MagicMock()
        c.set_or_update_state = MagicMock()
        events = [{"id": "evt-1"}, {"id": "evt-2"}]
        with patch(
            "connector.connector.OpenCTIConnectorHelper.stix2_create_bundle",
            return_value="bundle",
        ):
            c._process_portion(
                collection="apt/threat",
                prepared_data={"apt/threat": {}},
                portion=self._portion(events),
                work_id="w-1",
            )
        c.helper.metric.inc.assert_any_call("error_count")
        # Second event still processed.
        assert c.helper.send_stix2_bundle.call_count == 1

    def test_transient_error_propagates(self):
        c = _connector()

        class ProtocolError(Exception):
            pass

        ProtocolError.__name__ = "ProtocolError"
        c._collect_intelligence = MagicMock(side_effect=ProtocolError("conn reset"))
        with pytest.raises(ProtocolError):
            c._process_portion(
                collection="apt/threat",
                prepared_data={"apt/threat": {}},
                portion=self._portion([{"id": "evt-1"}]),
                work_id="w-1",
            )


# --- _event_hint ------------------------------------------------------------


class TestEventHintEdgeCases:
    def test_inner_dict_id_int(self):
        assert (
            ExternalImportConnector._event_hint({"threat_report": {"id": 9999}})
            == "9999"
        )


# --- whitelist / authentication failures ------------------------------------
#
# Regression guard for OpenCTI-connectors/issues/4168: a Group-IB API rejection
# (IP not whitelisted, revoked token, wrong username) must surface in the
# connector logs. Silent swallowing of the exception is the failure mode.


class _FakeResponse:
    """Minimal stand-in for ``requests.Response`` used inside HTTPError."""

    def __init__(self, status_code: int, reason: str = "Forbidden") -> None:
        self.status_code = status_code
        self.reason = reason
        self.text = f"HTTP {status_code} {reason}"


class _FakeHTTPError(Exception):
    """Shaped like ``requests.exceptions.HTTPError`` — carries ``response``."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.response = _FakeResponse(status_code)


def _collect_log_text(mock_logger: MagicMock, level: str) -> str:
    """Concatenate every string that was passed to logger.<level>(...)."""
    method = getattr(mock_logger, level)
    parts: list[str] = []
    for call in method.call_args_list:
        for arg in call.args:
            if isinstance(arg, str):
                parts.append(arg)
    return "\n".join(parts)


class TestWhitelistAndAuthFailuresLogged:
    def test_create_generators_auth_error_logged_as_error(self):
        # ``create_generators`` is the first API touchpoint each cycle. If the
        # backing IP is not whitelisted, ciaops raises here. The inner
        # try/except inside ``_process`` must log the traceback via
        # ``connector_logger.error`` — never swallow silently.
        c = _connector()
        c.ti_adapter.create_generators = MagicMock(
            side_effect=_FakeHTTPError(401, "Unauthorized: IP not whitelisted")
        )
        c.set_or_update_state = MagicMock()
        with patch("connector.connector.get_mitre_mapper", return_value={}):
            c._process()

        c.helper.connector_logger.error.assert_called()
        joined = _collect_log_text(c.helper.connector_logger, "error")
        assert "_FakeHTTPError" in joined
        assert "Unauthorized" in joined
        # State still persisted so the next tick is not lost.
        c.set_or_update_state.assert_called_once()

    def test_pre_peek_auth_error_warns_with_traceback(self):
        # A 403 raised on the very first ``next(generator)`` must be captured
        # by the pre-peek ``except Exception`` and logged with the traceback;
        # no Work is created for the flapping collection.
        c = _connector()
        c.cfg.get_collection_settings = MagicMock(return_value=True)

        def blocked():
            raise _FakeHTTPError(403, "Forbidden: whitelisting required")
            yield  # pragma: no cover — unreachable, marks fn as a generator

        c._process_portion = MagicMock()
        c._process_collection(
            data_item=(("apt/threat", blocked()), {"apt/threat": {}}),
            timestamp=1700000000,
        )

        c._process_portion.assert_not_called()
        c.helper.api.work.initiate_work.assert_not_called()
        c.helper.connector_logger.warning.assert_called()
        joined = _collect_log_text(c.helper.connector_logger, "warning")
        assert "apt/threat" in joined
        assert "_FakeHTTPError" in joined
        assert "Forbidden" in joined

    def test_run_once_httperror_propagates_to_process_error_log(self):
        # Independent path: even if create_generators succeeds but a later
        # step inside _run_once (e.g. the MITRE mapper fetch) hits an auth
        # rejection, the outer ``_process`` handler still logs a full trace.
        c = _connector()
        c._run_once = MagicMock(side_effect=_FakeHTTPError(401, "auth token expired"))
        c.set_or_update_state = MagicMock()
        c._process()

        c.helper.connector_logger.error.assert_called()
        joined = _collect_log_text(c.helper.connector_logger, "error")
        assert "auth token expired" in joined
