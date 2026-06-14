"""Unit tests for the PortSpoofPro pydantic boundary + helpers.

The tests live directly against the production modules — we do not
construct a full ``StixSynchronizer`` (it would try to call OpenCTI and
RabbitMQ at import time), but we do exercise the real pydantic models
and the ``validation.validate_ip_address`` helper so the contracts the
connector advertises stay pinned by CI.
"""

from __future__ import annotations

import os
import sys

import pytest
from pydantic import ValidationError as PydanticValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from main import FullSessionState  # noqa: E402
from validation import ValidationError, validate_ip_address  # noqa: E402


class TestValidateIpAddress:
    """``validate_ip_address`` is the single boundary helper still used."""

    @pytest.mark.parametrize(
        "ip",
        [
            "192.0.2.1",
            "10.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
            "2001:db8::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "::ffff:192.0.2.1",
        ],
    )
    def test_accepts_valid_ip(self, ip: str) -> None:
        validate_ip_address(ip)

    @pytest.mark.parametrize(
        "ip",
        [
            "",
            "not-an-ip",
            ":::::::",
            "256.0.0.1",
            "1.2.3",
            "1.2.3.4.5",
            "fe80:::1",
        ],
    )
    def test_rejects_malformed(self, ip: str) -> None:
        with pytest.raises(ValidationError):
            validate_ip_address(ip)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValidationError):
            validate_ip_address(None)  # type: ignore[arg-type]
        with pytest.raises(ValidationError):
            validate_ip_address(12345)  # type: ignore[arg-type]


def _minimal_session(**overrides):
    base = {
        "session_id": "S-1",
        "source_ip": "192.0.2.10",
        "session_start_time": "2024-01-01T00:00:00Z",
        "last_activity_time": "2024-01-01T00:05:00Z",
        "last_event_type": "scanner_detected",
        "risk_score": 100.0,
        "alert_level": 1,
        "total_ports_seen": 10,
        "total_hosts_probed": 1,
    }
    base.update(overrides)
    return base


class TestFullSessionStateSourceIp:
    """``source_ip`` is validated through ``validate_ip_address``.

    Pins the contract that malformed addresses are rejected at the
    pydantic boundary so they cannot reach STIX indicator patterns or
    IPv4/IPv6 observable construction downstream.
    """

    def test_accepts_ipv4(self) -> None:
        state = FullSessionState(**_minimal_session(source_ip="192.0.2.10"))
        assert state.source_ip == "192.0.2.10"

    def test_accepts_ipv6(self) -> None:
        state = FullSessionState(**_minimal_session(source_ip="2001:db8::1"))
        assert state.source_ip == "2001:db8::1"

    @pytest.mark.parametrize("bad_ip", [":::::::", "256.0.0.1", "1.2.3", "abc"])
    def test_rejects_malformed_source_ip(self, bad_ip: str) -> None:
        with pytest.raises(PydanticValidationError):
            FullSessionState(**_minimal_session(source_ip=bad_ip))


class TestFullSessionStateTimestamps:
    """Empty / malformed ISO-8601 timestamps are rejected at the boundary.

    The earlier shape let an empty ``session_start_time`` flow through
    to ``parse_iso_datetime``, which silently fell back to
    ``datetime.now()`` and so STIX SDOs ended up with the wall-clock
    ingest time as ``first_observed`` / ``last_observed``. Now the
    pydantic validator rejects the bad payload so the upstream retry /
    DLQ logic can act on it.
    """

    def test_accepts_zulu_timestamp(self) -> None:
        state = FullSessionState(
            **_minimal_session(session_start_time="2024-01-01T00:00:00Z")
        )
        assert state.session_start_time == "2024-01-01T00:00:00Z"

    def test_accepts_offset_timestamp(self) -> None:
        state = FullSessionState(
            **_minimal_session(session_start_time="2024-01-01T00:00:00+02:00")
        )
        assert state.session_start_time == "2024-01-01T00:00:00+02:00"

    def test_accepts_negative_offset_timestamp(self) -> None:
        state = FullSessionState(
            **_minimal_session(last_activity_time="2024-01-01T00:00:00-04:00")
        )
        assert state.last_activity_time == "2024-01-01T00:00:00-04:00"

    def test_rejects_empty_session_start_time(self) -> None:
        with pytest.raises(PydanticValidationError):
            FullSessionState(**_minimal_session(session_start_time=""))

    def test_rejects_empty_last_activity_time(self) -> None:
        with pytest.raises(PydanticValidationError):
            FullSessionState(**_minimal_session(last_activity_time=""))

    def test_rejects_malformed_timestamp(self) -> None:
        with pytest.raises(PydanticValidationError):
            FullSessionState(**_minimal_session(session_start_time="not-a-date"))

    def test_accepts_optional_session_end_time_none(self) -> None:
        state = FullSessionState(**_minimal_session(session_end_time=None))
        assert state.session_end_time is None

    def test_rejects_empty_optional_session_end_time(self) -> None:
        """An *explicit* empty string is still a bad value even on optional fields."""
        with pytest.raises(PydanticValidationError):
            FullSessionState(**_minimal_session(session_end_time=""))


class TestFullSessionStateEventType:
    """``last_event_type`` must match the PortSpoofPro session-event contract.

    The sensor aggregator only ever emits three lifecycle events for a
    session — ``scanner_detected``, ``scanner_update``,
    ``scanner_session_ended``. Anything else (empty string, unknown
    value, wrong casing) must be rejected at the pydantic boundary so
    a malformed message hits the DLQ instead of producing a partial
    STIX bundle downstream.
    """

    @pytest.mark.parametrize(
        "ev",
        ["scanner_detected", "scanner_update", "scanner_session_ended"],
    )
    def test_accepts_known_events(self, ev: str) -> None:
        state = FullSessionState(**_minimal_session(last_event_type=ev))
        assert state.last_event_type == ev

    @pytest.mark.parametrize("ev", ["", "unknown", "scan", "SCANNER_DETECTED"])
    def test_rejects_unknown_events(self, ev: str) -> None:
        with pytest.raises(PydanticValidationError):
            FullSessionState(**_minimal_session(last_event_type=ev))


class TestFullSessionStateAlertLevel:
    """``alert_level`` is bounded to 0..3."""

    @pytest.mark.parametrize("level", [0, 1, 2, 3])
    def test_accepts_valid_levels(self, level: int) -> None:
        state = FullSessionState(**_minimal_session(alert_level=level))
        assert state.alert_level == level

    @pytest.mark.parametrize("level", [-1, 4, 100])
    def test_rejects_out_of_range(self, level: int) -> None:
        with pytest.raises(PydanticValidationError):
            FullSessionState(**_minimal_session(alert_level=level))


class TestClassifyError:
    """``classify_error`` drives the retry / DLQ decision tree."""

    def test_permanent_for_value_error(self) -> None:
        from main import ErrorType, classify_error

        assert classify_error(ValueError("bad")) is ErrorType.PERMANENT

    def test_permanent_for_key_error(self) -> None:
        from main import ErrorType, classify_error

        assert classify_error(KeyError("missing")) is ErrorType.PERMANENT

    def test_permanent_for_type_error(self) -> None:
        from main import ErrorType, classify_error

        assert classify_error(TypeError("nope")) is ErrorType.PERMANENT

    def test_transient_for_runtime_error(self) -> None:
        from main import ErrorType, classify_error

        assert classify_error(RuntimeError("ephemeral")) is ErrorType.TRANSIENT

    def test_transient_for_connection_error(self) -> None:
        from main import ErrorType, classify_error

        assert classify_error(ConnectionError("amqp down")) is ErrorType.TRANSIENT


class TestRedactRabbitmqUrl:
    """RabbitMQ credentials must never appear in logs."""

    def test_masks_userinfo(self) -> None:
        from main import _redact_rabbitmq_url

        out = _redact_rabbitmq_url(
            "amqp://opencti:hunter2@rabbitmq.internal:5672/portspoof"
        )
        assert "hunter2" not in out
        assert "opencti" not in out
        assert "rabbitmq.internal" in out
        assert "5672" in out
        assert "/portspoof" in out

    def test_passes_through_without_credentials(self) -> None:
        from main import _redact_rabbitmq_url

        out = _redact_rabbitmq_url("amqp://rabbitmq:5672/")
        assert "amqp" in out
        assert "rabbitmq" in out
        assert "***" not in out

    def test_handles_unparseable_input(self) -> None:
        from main import _redact_rabbitmq_url

        # Any non-URL still produces a sane (non-crashing) log line.
        result = _redact_rabbitmq_url("not a url at all")
        assert isinstance(result, str)


class TestParseIsoDatetimeNormalisesToUtc:
    """``parse_iso_datetime`` must return a UTC datetime regardless of input offset.

    Downstream STIX timestamps and deterministic ID seeds hash this
    value — silently honouring the source-system timezone (the
    pre-fix behaviour, which only normalised naive timestamps) would
    produce different STIX IDs depending on whether the publisher
    emitted ``+02:00`` vs ``Z`` for the same wall-clock moment, and
    would let UI tooling render the same event twice in different
    timezones. The boundary now asserts UTC end-to-end.
    """

    @staticmethod
    def _parse(value):
        from helpers import parse_iso_datetime

        return parse_iso_datetime(value)

    def test_zulu_returns_utc(self) -> None:
        from datetime import timezone

        dt = self._parse("2026-05-21T10:00:00Z")
        assert dt.tzinfo is not None
        assert dt.utcoffset() == timezone.utc.utcoffset(dt)
        assert dt.isoformat() == "2026-05-21T10:00:00+00:00"

    def test_positive_offset_normalised_to_utc(self) -> None:
        # ``12:00+02:00`` is ``10:00`` in UTC. The pre-fix code
        # returned a ``+02:00`` datetime, which then leaked into
        # ``created`` / ``modified`` on the STIX side; now it's UTC.
        dt = self._parse("2026-05-21T12:00:00+02:00")
        assert dt.utcoffset().total_seconds() == 0
        assert dt.isoformat() == "2026-05-21T10:00:00+00:00"

    def test_negative_offset_normalised_to_utc(self) -> None:
        # ``06:00-04:00`` is ``10:00`` in UTC.
        dt = self._parse("2026-05-21T06:00:00-04:00")
        assert dt.utcoffset().total_seconds() == 0
        assert dt.isoformat() == "2026-05-21T10:00:00+00:00"

    def test_naive_input_assumed_utc(self) -> None:
        # No tzinfo on the wire is treated as UTC (matches the docstring
        # contract and what the connector did before — pinned so a
        # later refactor cannot silently re-introduce drift).
        dt = self._parse("2026-05-21T10:00:00")
        assert dt.utcoffset().total_seconds() == 0
        assert dt.isoformat() == "2026-05-21T10:00:00+00:00"
