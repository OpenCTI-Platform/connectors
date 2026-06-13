"""Tests for the MWDB connector ``start_up`` work-lifecycle handling.

The connector lives in a flat script (``src/mwdb.py``) that imports
third-party packages at module top level, so the module is loaded by an
absolute path with an explicit spec/loader guard.
"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock

import pytest

_SRC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src",
    "mwdb.py",
)


def _load_mwdb_module():
    spec = importlib.util.spec_from_file_location("mwdb_under_test", _SRC_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("Unable to build an import spec for " + _SRC_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mwdb_module = _load_mwdb_module()
MWDB = mwdb_module.MWDB


def _build_connector():
    """Build an MWDB instance bypassing ``__init__`` and wire up mocks."""
    connector = MWDB.__new__(MWDB)
    connector.helper = MagicMock()
    connector.helper.api.work.initiate_work.return_value = "work-1"
    # Terminate the ``while True`` loop after a single iteration: the
    # connector calls ``sys.exit(0)`` at the end of the first pass.
    connector.helper.connect_run_and_terminate = True
    connector.mwdb = MagicMock()
    connector.start_date = "2020-01-01T00:00:00.000Z"
    connector.mwdb_interval = 1
    connector.identity = {"standard_id": "x"}
    return connector


def test_start_up_success_marks_work_done():
    connector = _build_connector()
    # First run (no state) -> connector enters the import branch.
    connector.helper.get_state.return_value = None
    # No samples returned -> the for-loop is skipped, message becomes "Done".
    connector.mwdb.search_files.return_value = []

    with pytest.raises(SystemExit):
        connector.start_up()

    initiate_call = connector.helper.api.work.initiate_work.call_args
    assert initiate_call.kwargs.get("is_multipart") is True

    connector.helper.api.work.to_processed.assert_called_once_with(
        "work-1", "Done", in_error=False
    )


def test_start_up_inner_error_marks_work_failed():
    connector = _build_connector()
    connector.helper.get_state.return_value = None
    # The inner try/except this PR fixed: a failing search must close the
    # work with in_error=True rather than silently reporting success.
    connector.mwdb.search_files.side_effect = Exception("boom")

    with pytest.raises(SystemExit):
        connector.start_up()

    connector.helper.api.work.to_processed.assert_called_once()
    args, kwargs = connector.helper.api.work.to_processed.call_args
    assert args[0] == "work-1"
    assert kwargs.get("in_error") is True
    assert "boom" in args[1]
