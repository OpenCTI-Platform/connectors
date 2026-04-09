import json
from unittest.mock import MagicMock, patch

from main import YaraConnector


class TestYaraConnectorInit:
    """Tests for YaraConnector initialization."""

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_init(self, mock_isfile, mock_yaml, mock_get_config, mock_helper):
        connector = YaraConnector()
        assert connector.helper is not None
        assert connector.octi_api_url == "http://localhost"


class TestGetArtifactContents:
    """Tests for _get_artifact_contents method."""

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_no_import_files(
        self, mock_isfile, mock_yaml, mock_get_config, mock_helper
    ):

        connector = YaraConnector()
        artifact = {"importFiles": []}
        result = connector._get_artifact_contents(artifact)
        assert result == []

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_missing_import_files_key(
        self, mock_isfile, mock_yaml, mock_get_config, mock_helper
    ):

        connector = YaraConnector()
        artifact = {}
        result = connector._get_artifact_contents(artifact)
        assert result == []

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_with_files(self, mock_isfile, mock_yaml, mock_get_config, mock_helper):

        connector = YaraConnector()
        connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"content")
        artifact = {"importFiles": [{"name": "test.bin", "id": "file-123"}]}
        result = connector._get_artifact_contents(artifact)
        assert result == [b"content"]


class TestGetYaraIndicators:
    """Tests for _get_yara_indicators pagination."""

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_single_page(self, mock_isfile, mock_yaml, mock_get_config, mock_helper):

        connector = YaraConnector()
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

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_multiple_pages(self, mock_isfile, mock_yaml, mock_get_config, mock_helper):

        connector = YaraConnector()
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

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_matching_rule_creates_relationship(
        self, mock_isfile, mock_yaml, mock_get_config, mock_helper
    ):

        connector = YaraConnector()
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
            }
        ]
        result = connector._scan_artifact(artifact, indicators)
        assert len(result) == 1
        assert result[0]["relationship_type"] == "related-to"
        assert result[0]["created_by_ref"] == connector.author["id"]

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_no_match_no_bundle(
        self, mock_isfile, mock_yaml, mock_get_config, mock_helper
    ):

        connector = YaraConnector()
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
        result = connector._scan_artifact(artifact, indicators)
        assert result == []

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_syntax_error_skipped(
        self, mock_isfile, mock_yaml, mock_get_config, mock_helper
    ):

        connector = YaraConnector()
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
        connector._scan_artifact(artifact, indicators)
        assert connector._scan_artifact(artifact, indicators) == []


class TestProcessMessage:
    """Tests for _process_message scope check and bundle forwarding."""

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_out_of_scope_forwards_original_bundle(
        self, mock_isfile, mock_yaml, mock_get_config, mock_helper
    ):

        connector = YaraConnector()
        connector.helper.connect_scope = "Artifact"
        connector.helper.send_stix2_bundle = MagicMock()

        original_objects = [
            {
                "type": "domain-name",
                "id": "domain-name--c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f",
                "value": "example.com",
            }
        ]
        data = {
            "entity_id": "domain-name--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "stix_objects": original_objects,
        }
        result = connector._process_message(data)
        assert result == "Entity type not in scope"
        connector.helper.send_stix2_bundle.assert_called_once()

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_out_of_scope_no_stix_objects(
        self, mock_isfile, mock_yaml, mock_get_config, mock_helper
    ):

        connector = YaraConnector()
        connector.helper.connect_scope = "Artifact"
        connector.helper.send_stix2_bundle = MagicMock()

        data = {
            "entity_id": "domain-name--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        }
        result = connector._process_message(data)
        assert result == "Entity type not in scope"
        connector.helper.send_stix2_bundle.assert_not_called()

    @patch("main.OpenCTIConnectorHelper")
    @patch("main.get_config_variable", return_value="http://localhost")
    @patch("main.yaml.load", return_value={})
    @patch("main.os.path.isfile", return_value=False)
    def test_in_scope_with_matches_includes_author(
        self, mock_isfile, mock_yaml, mock_get_config, mock_helper
    ):

        connector = YaraConnector()
        connector.helper.connect_scope = "Artifact"
        connector.helper.send_stix2_bundle = MagicMock()
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        connector.helper.api.indicator.list = MagicMock(
            return_value={
                "pagination": {"hasNextPage": False, "endCursor": None},
                "entities": [
                    {
                        "name": "test_rule",
                        "standard_id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
                        "pattern": 'rule test_rule { strings: $a = "test data" condition: $a }',
                    }
                ],
            }
        )

        data = {
            "entity_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "enrichment_entity": {
                "standard_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                "importFiles": [{"name": "test.bin", "id": "file-123"}],
            },
            "stix_objects": [],
        }
        result = connector._process_message(data)
        assert result == "Done"
        connector.helper.send_stix2_bundle.assert_called_once()
        sent_bundle = json.loads(connector.helper.send_stix2_bundle.call_args[0][0])
        types = [obj["type"] for obj in sent_bundle["objects"]]
        assert "identity" in types
        assert "relationship" in types
