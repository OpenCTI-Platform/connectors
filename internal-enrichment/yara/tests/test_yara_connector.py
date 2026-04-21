from typing import Any
from unittest.mock import MagicMock

from connector import ConnectorSettings, YaraConnector


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "YARA",
                    "scope": "Artifact",
                    "log_level": "error",
                    "auto": True,
                },
            }
        )


def _make_connector():
    settings = StubConnectorSettings()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.connect_scope = "artifact"
    helper.api = MagicMock()
    connector = YaraConnector(config=settings, helper=helper)
    return connector


class TestYaraConnectorInit:
    """Tests for YaraConnector initialization."""

    def test_init(self):
        connector = _make_connector()
        assert connector.helper is not None
        assert connector.octi_api_url == "http://localhost"


class TestGetArtifactContents:
    """Tests for _get_artifact_contents method."""

    def test_no_import_files(self):
        connector = _make_connector()
        artifact = {"importFiles": []}
        result = connector._get_artifact_contents(artifact)
        assert result == []

    def test_missing_import_files_key(self):
        connector = _make_connector()
        artifact = {}
        result = connector._get_artifact_contents(artifact)
        assert result == []

    def test_with_files(self):
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"content")
        artifact = {"importFiles": [{"name": "test.bin", "id": "file-123"}]}
        result = connector._get_artifact_contents(artifact)
        assert result == [b"content"]


class TestGetYaraIndicators:
    """Tests for _get_yara_indicators pagination."""

    def test_single_page(self):
        connector = _make_connector()
        connector.helper.api.indicator.list = MagicMock(
            return_value={
                "pagination": {"hasNextPage": False, "endCursor": None},
                "entities": [
                    {
                        "id": "1",
                        "name": "rule1",
                        "pattern": "rule test { condition: true }",
                    }
                ],
            }
        )
        result = connector._get_yara_indicators()
        assert len(result) == 1

    def test_multiple_pages(self):
        connector = _make_connector()
        connector.helper.api.indicator.list = MagicMock(
            side_effect=[
                {
                    "pagination": {"hasNextPage": True, "endCursor": "cursor1"},
                    "entities": [{"id": "1"}],
                },
                {
                    "pagination": {"hasNextPage": False, "endCursor": None},
                    "entities": [{"id": "2"}],
                },
            ]
        )
        result = connector._get_yara_indicators()
        assert len(result) == 2
        assert result[0]["id"] == "1"
        assert result[1]["id"] == "2"


class TestScanArtifact:
    """Tests for YARA scanning logic."""

    def test_matching_rule_creates_relationship(self):
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )

        artifact = {
            "standard_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "importFiles": [{"name": "test.bin", "id": "file-123"}],
        }
        indicators = [
            {
                "name": "test_rule",
                "standard_id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                "pattern": 'rule test_rule { strings: $a = "test data" condition: $a }',
                "pattern_type": "yara",
                "valid_from": "2025-01-01T00:00:00Z",
            }
        ]
        result, errors = connector._scan_artifact(artifact, indicators)
        # result contains 1 relationship + 1 indicator
        assert len(result) == 2
        assert result[0]["relationship_type"] == "related-to"
        assert result[0]["created_by_ref"] == connector.author["id"]
        assert errors == []

    def test_no_match_no_bundle(self):
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"nothing interesting"
        )

        artifact = {
            "standard_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "importFiles": [{"name": "test.bin", "id": "file-123"}],
        }
        indicators = [
            {
                "name": "test_rule",
                "standard_id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                "pattern": 'rule test_rule { strings: $a = "VERYSECRETSTRING" condition: $a }',
            }
        ]
        result, errors = connector._scan_artifact(artifact, indicators)
        assert result == []
        assert errors == []

    def test_syntax_error_skipped(self):
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"data")

        artifact = {
            "standard_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "importFiles": [{"name": "test.bin", "id": "file-123"}],
        }
        indicators = [
            {
                "name": "bad_rule",
                "standard_id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                "pattern": "this is not valid yara",
            }
        ]
        objects, errors = connector._scan_artifact(artifact, indicators)
        assert objects == []
        assert len(errors) == 1
