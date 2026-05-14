from typing import Any
from unittest.mock import MagicMock

from connector import ConnectorSettings, YaraConnector


def _build_stub_settings(yara: dict | None = None) -> ConnectorSettings:
    """Return a ``ConnectorSettings`` instance loaded from a fixed
    in-memory dict, optionally extended with a ``yara`` override block
    (e.g. ``yara={"propagate_labels": True}``).

    The model is frozen at runtime, so we have to inject the yara
    overrides through the loader rather than mutating the instance
    after construction.
    """
    settings_dict: dict[str, Any] = {
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
    if yara:
        settings_dict["yara"] = yara

    class _StubSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return _StubSettings()


# Backwards-compatible alias for the existing tests that just want a
# default-configured connector (the yara block defaults are applied by
# ``YaraConfig`` itself when ``yara`` is missing from the dict).
StubConnectorSettings = _build_stub_settings


def _make_connector(yara: dict | None = None):
    settings = _build_stub_settings(yara=yara)
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


class TestPropagateLabels:
    """Tests for the optional label-propagation path."""

    def _matching_artifact_and_indicator(self, labels):
        artifact = {
            "id": "artifact-uuid",
            "standard_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "importFiles": [{"name": "test.bin", "id": "file-123"}],
        }
        indicator = {
            "id": "indicator-uuid",
            "name": "test_rule",
            "standard_id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
            "pattern": 'rule test_rule { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
            "objectLabel": labels,
        }
        return artifact, indicator

    def test_propagates_each_label_when_enabled(self):
        connector = _make_connector(yara={"propagate_labels": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._matching_artifact_and_indicator(
            [
                {"id": "label-1", "value": "apt", "color": "#ff0000"},
                {"id": "label-2", "value": "ransomware", "color": "#00ff00"},
            ]
        )
        connector._scan_artifact(artifact, [indicator])

        # Each label is added through the side-channel ``add_label`` mutation.
        calls = connector.helper.api.stix_cyber_observable.add_label.call_args_list
        assert len(calls) == 2
        label_ids = sorted(c.kwargs["label_id"] for c in calls)
        assert label_ids == ["label-1", "label-2"]
        for call in calls:
            assert call.kwargs["id"] == artifact["id"]

    def test_does_nothing_when_disabled(self):
        connector = _make_connector(yara={"propagate_labels": False})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._matching_artifact_and_indicator(
            [{"id": "label-1", "value": "apt", "color": "#ff0000"}]
        )
        connector._scan_artifact(artifact, [indicator])

        # Add-label never called when the toggle is off.
        connector.helper.api.stix_cyber_observable.add_label.assert_not_called()

    def test_skips_labels_without_id(self):
        connector = _make_connector(yara={"propagate_labels": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._matching_artifact_and_indicator(
            [
                {"id": "label-1", "value": "apt", "color": "#ff0000"},
                {"value": "noid", "color": "#ff0000"},  # malformed payload
                "string-label",  # non-dict payload
            ]
        )
        connector._scan_artifact(artifact, [indicator])

        calls = connector.helper.api.stix_cyber_observable.add_label.call_args_list
        assert len(calls) == 1
        assert calls[0].kwargs["label_id"] == "label-1"


class TestPropagateMalwareRelationships:
    """Tests for the optional Artifact -> Malware relationship propagation."""

    def _matching_artifact_and_indicator(self):
        artifact = {
            "id": "artifact-uuid",
            "standard_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "importFiles": [{"name": "test.bin", "id": "file-123"}],
        }
        indicator = {
            "id": "indicator-uuid",
            "name": "test_rule",
            "standard_id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
            "pattern": 'rule test_rule { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
        }
        return artifact, indicator

    def test_emits_one_related_to_per_indicated_malware(self):
        connector = _make_connector(yara={"propagate_malware_relationship": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        connector.helper.api.stix_core_relationship.list = MagicMock(
            return_value=[
                {
                    "to": {
                        "standard_id": ("malware--11111111-1111-4111-8111-111111111111")
                    }
                },
                {
                    "to": {
                        "standard_id": ("malware--22222222-2222-4222-8222-222222222222")
                    }
                },
            ]
        )
        artifact, indicator = self._matching_artifact_and_indicator()

        result, errors = connector._scan_artifact(artifact, [indicator])
        assert errors == []

        # ``stix_core_relationship.list`` is called with the documented
        # filter (relationship_type='indicates', toTypes=['Malware']).
        connector.helper.api.stix_core_relationship.list.assert_called_once_with(
            fromId=indicator["id"],
            relationship_type="indicates",
            toTypes=["Malware"],
        )

        # One Artifact -> Indicator + one Indicator + two Artifact -> Malware.
        relationship_targets = [
            obj["target_ref"] for obj in result if obj["type"] == "relationship"
        ]
        assert "malware--11111111-1111-4111-8111-111111111111" in relationship_targets
        assert "malware--22222222-2222-4222-8222-222222222222" in relationship_targets

    def test_does_nothing_when_disabled(self):
        connector = _make_connector(yara={"propagate_malware_relationship": False})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._matching_artifact_and_indicator()

        connector._scan_artifact(artifact, [indicator])

        # The malware-relationship API is never queried when the toggle is off.
        connector.helper.api.stix_core_relationship.list.assert_not_called()

    def test_skips_relationships_without_target_standard_id(self):
        connector = _make_connector(yara={"propagate_malware_relationship": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        connector.helper.api.stix_core_relationship.list = MagicMock(
            return_value=[
                {"to": None},  # malformed payload
                {"to": {}},  # missing standard_id
                {
                    "to": {
                        "standard_id": ("malware--33333333-3333-4333-8333-333333333333")
                    }
                },
            ]
        )
        artifact, indicator = self._matching_artifact_and_indicator()

        result, _ = connector._scan_artifact(artifact, [indicator])
        malware_relationships = [
            obj
            for obj in result
            if obj["type"] == "relationship"
            and obj["target_ref"].startswith("malware--")
        ]
        assert len(malware_relationships) == 1
        assert (
            malware_relationships[0]["target_ref"]
            == "malware--33333333-3333-4333-8333-333333333333"
        )
