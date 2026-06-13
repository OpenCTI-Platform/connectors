"""Tests for the restore-files connector.

The connector lives in ``src/restore-files.py``. The hyphen in the filename
makes the module non-importable through the normal ``import`` machinery, so it
is loaded by absolute path via ``importlib`` instead.
"""

import importlib.util
import json
import os
import uuid
from unittest.mock import MagicMock

import pytest

_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "src", "restore-files.py")
)


def _load_restore_files_module():
    spec = importlib.util.spec_from_file_location("restore_files", _SRC)
    if spec is None or spec.loader is None:
        raise ImportError("Unable to load module spec for " + _SRC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_MODULE = _load_restore_files_module()
RestoreFilesConnector = _MODULE.RestoreFilesConnector

RUN_DIR_NAME = "20260101T000000Z"


def _make_connector(tmp_path, direct_creation=False):
    """Build a connector with a realistic backup tree under ``tmp_path``.

    Writes one minimal STIX object so ``objects_with_missing`` is non-empty and
    the per-directory work block in ``restore_files`` is reached.
    """
    backup_path = tmp_path / "backup"
    run_dir = backup_path / "opencti_data" / RUN_DIR_NAME
    run_dir.mkdir(parents=True)

    identity_id = "identity--" + str(uuid.uuid4())
    stix_payload = {
        "objects": [
            {"id": identity_id, "type": "identity", "name": "x"},
        ]
    }
    (run_dir / (identity_id + ".json")).write_text(
        json.dumps(stix_payload), encoding="utf-8"
    )

    connector = RestoreFilesConnector.__new__(RestoreFilesConnector)
    connector.helper = MagicMock()
    connector.helper.get_state.return_value = None
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.direct_creation = direct_creation
    connector.backup_path = str(backup_path)
    return connector


def test_restore_files_success(tmp_path):
    connector = _make_connector(tmp_path, direct_creation=False)

    connector.restore_files()

    initiate_work = connector.helper.api.work.initiate_work
    assert initiate_work.called
    _, initiate_kwargs = initiate_work.call_args
    assert initiate_kwargs.get("is_multipart") is True

    assert connector.helper.send_stix2_bundle.called

    to_processed = connector.helper.api.work.to_processed
    assert to_processed.called
    _, processed_kwargs = to_processed.call_args
    assert processed_kwargs.get("in_error") is False

    connector.helper.set_state.assert_called_once_with({"current": RUN_DIR_NAME})


def test_restore_files_direct_creation(tmp_path):
    connector = _make_connector(tmp_path, direct_creation=True)

    connector.restore_files()

    initiate_work = connector.helper.api.work.initiate_work
    assert initiate_work.called
    _, initiate_kwargs = initiate_work.call_args
    assert initiate_kwargs.get("is_multipart") is True

    assert connector.helper.api.stix2.import_bundle_from_json.called
    assert not connector.helper.send_stix2_bundle.called

    to_processed = connector.helper.api.work.to_processed
    assert to_processed.called
    _, processed_kwargs = to_processed.call_args
    assert processed_kwargs.get("in_error") is False

    connector.helper.set_state.assert_called_once_with({"current": RUN_DIR_NAME})


def test_restore_files_error_does_not_advance_cursor(tmp_path):
    connector = _make_connector(tmp_path, direct_creation=False)
    connector.helper.send_stix2_bundle.side_effect = Exception("boom")

    with pytest.raises(Exception):
        connector.restore_files()

    to_processed = connector.helper.api.work.to_processed
    assert to_processed.called
    _, processed_kwargs = to_processed.call_args
    assert processed_kwargs.get("in_error") is True

    assert not connector.helper.set_state.called
