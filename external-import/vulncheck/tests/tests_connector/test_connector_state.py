"""Per-source error isolation + state-advancement tests.

A source that raises must not (a) stop the other sources, nor (b) have its state
timestamp advanced — otherwise an incremental NVD2 source would skip the window
it failed to ingest.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from conftest import StubConnectorSettings
from connector.connector import ConnectorVulnCheck


def _connector():
    return ConnectorVulnCheck(config=StubConnectorSettings(), helper=MagicMock())


def _source(name, raises=False):
    return SimpleNamespace(
        name=name,
        collect=MagicMock(side_effect=Exception("boom") if raises else None),
    )


def test_collect_intelligence_isolates_failures_and_returns_successes():
    connector = _connector()
    ok1, bad, ok2 = _source("a"), _source("b", raises=True), _source("c")

    succeeded = connector._collect_intelligence([ok1, bad, ok2], {})

    # A failing source neither stops the others nor appears in the result.
    ok1.collect.assert_called_once()
    bad.collect.assert_called_once()
    ok2.collect.assert_called_once()
    assert succeeded == [ok1, ok2]


def test_updated_state_advances_only_succeeded_and_preserves_prior():
    connector = _connector()
    prior = {
        "a": "2026-06-01 00:00:00",
        "b": "2026-06-01 00:00:00",
        "last_run": "2026-06-01 00:00:00",
    }

    new_state = connector._get_updated_state(
        prior, [_source("a")], "2026-06-28 12:00:00"
    )

    assert new_state["a"] == "2026-06-28 12:00:00"  # collected -> advanced
    assert new_state["b"] == "2026-06-01 00:00:00"  # not collected -> preserved
    assert new_state["last_run"] == "2026-06-28 12:00:00"


def test_updated_state_handles_none_prior():
    connector = _connector()

    new_state = connector._get_updated_state(
        None, [_source("a")], "2026-06-28 12:00:00"
    )

    assert new_state == {
        "a": "2026-06-28 12:00:00",
        "last_run": "2026-06-28 12:00:00",
    }
