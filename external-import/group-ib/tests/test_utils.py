from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.utils import ExternalImportHelper


def _helper_stub() -> SimpleNamespace:
    return SimpleNamespace(connector_logger=MagicMock())


def _cfg(**attrs) -> SimpleNamespace:
    """Build a config stand-in carrying the attributes the validator reads."""
    return SimpleNamespace(**attrs)


class TestValidationInterval:
    def test_valid_iso8601_hours(self):
        helper = _helper_stub()
        cfg = _cfg(connector_duration_period="PT4H")
        assert ExternalImportHelper.validation_interval(cfg, helper) == "PT4H"
        helper.connector_logger.info.assert_called_once()
        helper.connector_logger.error.assert_not_called()

    def test_valid_iso8601_minutes(self):
        helper = _helper_stub()
        cfg = _cfg(connector_duration_period="PT3M")
        assert ExternalImportHelper.validation_interval(cfg, helper) == "PT3M"

    def test_valid_iso8601_seconds(self):
        helper = _helper_stub()
        cfg = _cfg(connector_duration_period="PT5S")
        assert ExternalImportHelper.validation_interval(cfg, helper) == "PT5S"

    def test_valid_iso8601_days(self):
        helper = _helper_stub()
        cfg = _cfg(connector_duration_period="P7D")
        assert ExternalImportHelper.validation_interval(cfg, helper) == "P7D"

    def test_valid_iso8601_compound(self):
        helper = _helper_stub()
        cfg = _cfg(connector_duration_period="P1DT2H30M")
        assert ExternalImportHelper.validation_interval(cfg, helper) == "P1DT2H30M"

    def test_invalid_string_raises(self):
        helper = _helper_stub()
        cfg = _cfg(connector_duration_period="not-a-duration")
        with pytest.raises(ValueError) as excinfo:
            ExternalImportHelper.validation_interval(cfg, helper)
        assert "CONNECTOR_DURATION_PERIOD" in str(excinfo.value)
        helper.connector_logger.error.assert_called_once()

    def test_empty_string_raises(self):
        helper = _helper_stub()
        cfg = _cfg(connector_duration_period="")
        with pytest.raises(ValueError):
            ExternalImportHelper.validation_interval(cfg, helper)

    def test_none_raises(self):
        helper = _helper_stub()
        cfg = _cfg(connector_duration_period=None)
        with pytest.raises(ValueError):
            ExternalImportHelper.validation_interval(cfg, helper)

    def test_garbage_value_logs_error_message(self):
        helper = _helper_stub()
        cfg = _cfg(connector_duration_period="4 hours")
        with pytest.raises(ValueError):
            ExternalImportHelper.validation_interval(cfg, helper)
        # Error message must mention the actual offending value so an
        # operator can grep for it in container logs.
        call_args = helper.connector_logger.error.call_args
        assert "4 hours" in str(call_args)


class TestValidationUpdateExistingData:
    def test_bool_true(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data=True)
        assert ExternalImportHelper.validation_update_existing_data(cfg, helper) is True
        helper.connector_logger.warning.assert_not_called()

    def test_bool_false(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data=False)
        assert (
            ExternalImportHelper.validation_update_existing_data(cfg, helper) is False
        )

    def test_string_true_lowercase(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data="true")
        assert ExternalImportHelper.validation_update_existing_data(cfg, helper) is True

    def test_string_true_uppercase(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data="TRUE")
        assert ExternalImportHelper.validation_update_existing_data(cfg, helper) is True

    def test_string_true_mixedcase(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data="True")
        assert ExternalImportHelper.validation_update_existing_data(cfg, helper) is True

    def test_string_false_lowercase(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data="false")
        assert (
            ExternalImportHelper.validation_update_existing_data(cfg, helper) is False
        )

    def test_string_false_uppercase(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data="FALSE")
        assert (
            ExternalImportHelper.validation_update_existing_data(cfg, helper) is False
        )

    def test_invalid_string_falls_back_to_false(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data="maybe")
        assert (
            ExternalImportHelper.validation_update_existing_data(cfg, helper) is False
        )
        helper.connector_logger.warning.assert_called_once()
        # The warning must echo the offending raw value for operator debug.
        call_args = helper.connector_logger.warning.call_args
        assert "maybe" in str(call_args)

    def test_none_falls_back_to_false(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data=None)
        assert (
            ExternalImportHelper.validation_update_existing_data(cfg, helper) is False
        )
        helper.connector_logger.warning.assert_called_once()

    def test_int_falls_back_to_false(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data=1)
        # Strict semantics: only Python bool / "true"/"false" string are
        # accepted; ints fall through to the warning + False branch.
        assert (
            ExternalImportHelper.validation_update_existing_data(cfg, helper) is False
        )
        helper.connector_logger.warning.assert_called_once()

    def test_empty_string_falls_back_to_false(self):
        helper = _helper_stub()
        cfg = _cfg(connector_update_existing_data="")
        assert (
            ExternalImportHelper.validation_update_existing_data(cfg, helper) is False
        )


class TestValidationIntervalNonTimedelta:
    def test_isodate_duration_object_rejected(self):
        # ``parse_duration("P1M")`` returns ``isodate.Duration`` (months
        # aren't a fixed-length timedelta) — the isinstance check rejects it.
        cfg = SimpleNamespace(connector_duration_period="P1M")
        with pytest.raises(ValueError, match="CONNECTOR_DURATION_PERIOD"):
            ExternalImportHelper.validation_interval(cfg=cfg, helper=_helper_stub())


class TestValidationIntervalSuccessLog:
    def test_success_logs_validation_message(self):
        # Success path: info-log records the value being validated.
        helper = _helper_stub()
        cfg = SimpleNamespace(connector_duration_period="P1D")
        out = ExternalImportHelper.validation_interval(cfg=cfg, helper=helper)
        assert out == "P1D"
        helper.connector_logger.info.assert_called_once()
        msg = str(helper.connector_logger.info.call_args)
        assert "P1D" in msg
