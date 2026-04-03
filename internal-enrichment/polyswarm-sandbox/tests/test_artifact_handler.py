"""Unit tests for ArtifactHandler — download success/failure, size limits."""

import pytest
from unittest.mock import MagicMock

from connector.artifact_handler import ArtifactHandler


@pytest.fixture
def handler():
    helper = MagicMock()
    helper.api.api_url = "http://localhost:8080/graphql"
    helper.api.fetch_opencti_file = MagicMock(return_value=b"file-content-here")
    return ArtifactHandler(helper=helper, max_file_size=1024, download_enabled=True)


@pytest.fixture
def entity_with_file():
    return {"importFiles": [{"id": "file-001", "name": "sample.exe", "size": 500}]}


# ── Success cases ───────────────────────────────────────────────────────────


class TestDownloadSuccess:
    """Verify happy-path download returns file bytes with no error."""

    def test_returns_file_data(self, handler, entity_with_file):
        data, err = handler.download_artifact(entity_with_file)
        assert data == b"file-content-here"
        assert err is None

    def test_no_error_on_success(self, handler, entity_with_file):
        _, err = handler.download_artifact(entity_with_file)
        assert err is None


# ── Failure cases ───────────────────────────────────────────────────────────


class TestDownloadFailure:
    """Verify each failure path returns (None, descriptive_error_string)."""

    def test_download_disabled(self):
        handler = ArtifactHandler(helper=MagicMock(), download_enabled=False)
        data, err = handler.download_artifact({"importFiles": [{"id": "f1"}]})
        assert data is None
        assert "disabled" in err.lower()

    def test_no_import_files(self, handler):
        data, err = handler.download_artifact({"importFiles": []})
        assert data is None
        assert "No file attached" in err

    def test_no_file_id(self, handler):
        data, err = handler.download_artifact({"importFiles": [{"name": "test"}]})
        assert data is None
        assert "no ID" in err

    def test_empty_file(self, handler):
        handler.helper.api.fetch_opencti_file = MagicMock(return_value=b"")
        entity = {"importFiles": [{"id": "f1", "name": "empty.bin", "size": 0}]}
        data, err = handler.download_artifact(entity)
        assert data is None
        assert "empty" in err.lower()

    def test_file_not_found(self, handler):
        handler.helper.api.fetch_opencti_file = MagicMock(return_value=None)
        entity = {"importFiles": [{"id": "f1", "name": "gone.exe"}]}
        data, err = handler.download_artifact(entity)
        assert data is None
        assert "Failed to download" in err


# ── Size limits ─────────────────────────────────────────────────────────────


class TestSizeLimits:
    """Verify both metadata-reported and actual byte-count size checks."""

    def test_metadata_size_exceeded(self, handler):
        entity = {"importFiles": [{"id": "f1", "name": "big.exe", "size": 2048}]}
        data, err = handler.download_artifact(entity)
        assert data is None
        assert "exceeds" in err.lower()

    def test_actual_size_exceeded(self, handler):
        handler.helper.api.fetch_opencti_file = MagicMock(return_value=b"x" * 2048)
        entity = {"importFiles": [{"id": "f1", "name": "big.exe"}]}
        data, err = handler.download_artifact(entity)
        assert data is None
        assert "exceeds" in err.lower()

    def test_file_within_limit(self, handler, entity_with_file):
        data, err = handler.download_artifact(entity_with_file)
        assert data is not None
        assert err is None


# ── I/O errors ──────────────────────────────────────────────────────────────


class TestIOErrors:
    """Verify I/O and unexpected exceptions are caught and returned as error strings."""

    def test_io_error_handled(self, handler):
        handler.helper.api.fetch_opencti_file = MagicMock(side_effect=IOError("disk full"))
        entity = {"importFiles": [{"id": "f1", "name": "test.exe"}]}
        data, err = handler.download_artifact(entity)
        assert data is None
        assert "I/O error" in err

    def test_unexpected_error_handled(self, handler):
        handler.helper.api.fetch_opencti_file = MagicMock(side_effect=RuntimeError("boom"))
        entity = {"importFiles": [{"id": "f1", "name": "test.exe"}]}
        data, err = handler.download_artifact(entity)
        assert data is None
        assert "Unexpected" in err
