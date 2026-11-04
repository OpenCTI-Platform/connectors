"""Tests for connector state, worker conversion, file logging and the entry point."""

import logging
import runpy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import connector as connector_package
import connector.parallel_convert as parallel_convert
import pycti
import pytest
from checkfirst_client.api_models import Article
from connector.connector_state import ConnectorState
from connector.converter_to_stix import ConversionError
from utils.file_logging import _resolve_level, attach_file_logging

MAIN_PATH = Path(__file__).parents[2] / "src" / "main.py"


def _article() -> Article:
    return Article(
        _id="abc123",
        row_number=7,
        url="https://france.news-pravda.com/article-1",
        source_title="Telegram Source",
        source_url="https://t.me/source",
        published_date=datetime(2025, 3, 15, tzinfo=timezone.utc),
    )


# --- ConnectorState -----------------------------------------------------------


def test_state_load_reads_saved_values_once():
    helper = MagicMock()
    helper.get_state.return_value = {"last_cursor": "id-5", "legacy_key": 3}
    state = ConnectorState(helper)

    loaded = state.load()
    state.load()

    assert loaded.last_cursor == "id-5"
    helper.get_state.assert_called_once()


def test_state_save_always_writes_the_cursor_key():
    helper = MagicMock()
    state = ConnectorState(helper)
    state.last_run = datetime(2025, 1, 1, tzinfo=timezone.utc)

    state.save()

    saved = helper.set_state.call_args.args[0]
    assert saved["last_cursor"] is None
    assert saved["last_run"].startswith("2025-01-01")


def test_state_clear_cache_forces_a_reload():
    helper = MagicMock()
    helper.get_state.return_value = {}
    state = ConnectorState(helper)
    state.load()

    state.clear_cache()
    state.load()

    assert helper.get_state.call_count == 2


# --- Worker conversion --------------------------------------------------------


def test_worker_reports_an_uninitialized_converter(monkeypatch):
    monkeypatch.setattr(parallel_convert, "_worker_converter", None)

    row_id, row_number, entities, error = parallel_convert.convert_row_in_worker(
        _article()
    )

    assert (row_id, row_number, entities) == ("abc123", 7, None)
    assert error == "convert worker not initialized"


def test_worker_reports_conversion_errors(monkeypatch):
    converter = MagicMock()
    converter.get_campaign_for_year.side_effect = ConversionError("cannot convert")
    monkeypatch.setattr(parallel_convert, "_worker_converter", converter)

    _row_id, _row_number, entities, error = parallel_convert.convert_row_in_worker(
        _article()
    )

    assert entities is None
    assert error == "cannot convert"


def test_worker_propagates_unexpected_errors(monkeypatch):
    """An unexpected failure must stop the run, not be skipped like a bad row."""
    converter = MagicMock()
    converter.get_campaign_for_year.side_effect = RuntimeError("bug")
    monkeypatch.setattr(parallel_convert, "_worker_converter", converter)

    with pytest.raises(RuntimeError, match="bug"):
        parallel_convert.convert_row_in_worker(_article())


# --- File logging -------------------------------------------------------------


@pytest.fixture
def root_logger():
    root = logging.getLogger()
    handlers = list(root.handlers)
    yield root
    for handler in root.handlers[:]:
        if handler not in handlers:
            root.removeHandler(handler)
            handler.close()


def test_attach_file_logging_adds_one_handler_per_file(tmp_path, root_logger):
    log_file = tmp_path / "logs" / "connector.log"

    path = attach_file_logging(str(log_file), "error")
    again = attach_file_logging(str(log_file), "info")

    file_handlers = [
        h
        for h in root_logger.handlers
        if isinstance(h, logging.FileHandler) and Path(h.baseFilename) == path
    ]
    assert path == again == log_file.resolve()
    assert len(file_handlers) == 1
    assert file_handlers[0].level == logging.INFO

    logging.getLogger("checkfirst-test").warning("written to file")
    file_handlers[0].flush()
    assert "written to file" in log_file.read_text()


@pytest.mark.parametrize(
    "log_level, expected",
    [
        ("error", logging.ERROR),
        (" Debug ", logging.DEBUG),
        ("unknown", None),
        (None, None),
    ],
)
def test_resolve_level(log_level, expected):
    effective = logging.getLogger().getEffectiveLevel()
    assert _resolve_level(log_level) == (expected or effective)


# --- Entry point --------------------------------------------------------------


@pytest.fixture
def main_dependencies(monkeypatch):
    settings = MagicMock()
    settings.checkfirst.log_file = None
    connector_class = MagicMock()
    attach = MagicMock(return_value=Path("/tmp/connector.log"))

    monkeypatch.setattr(connector_package, "ConnectorSettings", lambda: settings)
    monkeypatch.setattr(connector_package, "CheckfirstImportConnector", connector_class)
    monkeypatch.setattr(pycti, "OpenCTIConnectorHelper", MagicMock())
    monkeypatch.setattr("utils.file_logging.attach_file_logging", attach)
    return settings, connector_class, attach


def test_main_runs_the_connector(main_dependencies):
    _settings, connector_class, attach = main_dependencies

    runpy.run_path(str(MAIN_PATH), run_name="__main__")

    connector_class.return_value.run.assert_called_once()
    attach.assert_not_called()


def test_main_enables_file_logging_when_configured(main_dependencies):
    settings, connector_class, attach = main_dependencies
    settings.checkfirst.log_file = "/tmp/connector.log"
    settings.connector.log_level = "info"

    runpy.run_path(str(MAIN_PATH), run_name="__main__")

    attach.assert_called_once_with("/tmp/connector.log", "info")
    connector_class.return_value.run.assert_called_once()


def test_main_exits_with_an_error_code_on_failure(main_dependencies):
    _settings, connector_class, _attach = main_dependencies
    connector_class.side_effect = RuntimeError("boom")

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(MAIN_PATH), run_name="__main__")

    assert exit_info.value.code == 1
