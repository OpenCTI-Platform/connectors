from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from support.mitre_mapper import get_mitre_mapper


class TestGetMitreMapper:

    def test_decorated_call_returns_a_mapping(self):
        # End-to-end smoke through the ``@cache_data`` wrapper: the decorated
        # callable always yields a dict (fresh result or cached).
        helper = SimpleNamespace(connector_logger=MagicMock())
        adapter = MagicMock()
        poller = MagicMock()
        poller.get_mitre_attack_pattern_map.return_value = {
            "T1059": "Command Execution",
        }
        adapter._set_up_poller.return_value = poller
        out = get_mitre_mapper(adapter, helper)
        assert isinstance(out, dict)

    def test_function_body_loads_attack_patterns(self):
        unwrapped = getattr(get_mitre_mapper, "__wrapped__", get_mitre_mapper)
        helper = SimpleNamespace(connector_logger=MagicMock())
        poller = MagicMock()
        poller.get_mitre_attack_pattern_map.return_value = {
            "T1059": "Command Execution"
        }
        adapter = MagicMock()
        adapter._set_up_poller.return_value = poller

        out = unwrapped(adapter, helper)
        assert out == {"T1059": "Command Execution"}
        # Session always closed (finally clause).
        poller.close_session.assert_called_once()
        # Two info logs (start + completion).
        assert helper.connector_logger.info.call_count >= 2

    def test_session_closed_even_when_attack_pattern_call_fails(self):
        unwrapped = getattr(get_mitre_mapper, "__wrapped__", get_mitre_mapper)
        helper = SimpleNamespace(connector_logger=MagicMock())
        poller = MagicMock()
        poller.get_mitre_attack_pattern_map.side_effect = RuntimeError("boom")
        adapter = MagicMock()
        adapter._set_up_poller.return_value = poller

        with pytest.raises(RuntimeError, match="boom"):
            unwrapped(adapter, helper)
        # ``finally`` clause guarantees the session is closed even on error.
        poller.close_session.assert_called_once()
