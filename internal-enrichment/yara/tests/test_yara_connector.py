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

    def test_logs_warning_for_malformed_label_payloads(self):
        # Each malformed ``objectLabel`` entry must produce a warning
        # log so an operator can spot a malformed platform response;
        # the loop still continues for the well-formed entry.
        connector = _make_connector(yara={"propagate_labels": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._matching_artifact_and_indicator(
            [
                {"id": "label-1", "value": "apt", "color": "#ff0000"},
                {"value": "noid", "color": "#ff0000"},  # missing ``id``
                "string-label",  # not a dict
            ]
        )
        connector._scan_artifact(artifact, [indicator])

        warning_calls = connector.helper.connector_logger.warning.call_args_list
        warning_messages = [call.args[0] for call in warning_calls]
        # One warning per malformed entry (missing id + non-dict), no
        # warning for the well-formed ``label-1`` entry.
        assert any("not a dict" in msg for msg in warning_messages)
        assert any("without 'id'" in msg for msg in warning_messages)
        # ``add_label`` is still called for the well-formed entry.
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
                        "standard_id": (
                            "malware--11111111-1111-4111-8111-111111111111"
                        ),
                        "name": "Emotet",
                        "description": "Banking trojan",
                        "is_family": True,
                    }
                },
                {
                    "to": {
                        "standard_id": (
                            "malware--22222222-2222-4222-8222-222222222222"
                        ),
                        "name": "TrickBot",
                        "is_family": False,
                    }
                },
            ]
        )
        artifact, indicator = self._matching_artifact_and_indicator()

        result, errors = connector._scan_artifact(artifact, [indicator])
        assert errors == []

        # ``stix_core_relationship.list`` is called with the documented
        # filter (relationship_type='indicates', toTypes=['Malware'])
        # and a ``customAttributes`` block that fetches the Malware
        # fields needed to build the SDO (name, description, is_family).
        call = connector.helper.api.stix_core_relationship.list.call_args
        assert call.kwargs["fromId"] == indicator["id"]
        assert call.kwargs["relationship_type"] == "indicates"
        assert call.kwargs["toTypes"] == ["Malware"]
        assert "customAttributes" in call.kwargs
        assert "is_family" in call.kwargs["customAttributes"]

        # The bundle now carries both the Artifact -> Malware
        # ``related-to`` relationships AND the Malware SDOs themselves
        # so ``send_stix2_bundle(..., cleanup_inconsistent_bundle=True)``
        # cannot drop the relationships for missing targets.
        relationship_targets = [
            obj["target_ref"] for obj in result if obj["type"] == "relationship"
        ]
        assert "malware--11111111-1111-4111-8111-111111111111" in relationship_targets
        assert "malware--22222222-2222-4222-8222-222222222222" in relationship_targets

        malware_sdos = [obj for obj in result if obj["type"] == "malware"]
        malware_by_id = {obj["id"]: obj for obj in malware_sdos}
        assert set(malware_by_id) == {
            "malware--11111111-1111-4111-8111-111111111111",
            "malware--22222222-2222-4222-8222-222222222222",
        }
        emotet = malware_by_id["malware--11111111-1111-4111-8111-111111111111"]
        assert emotet["name"] == "Emotet"
        assert emotet["is_family"] is True
        assert emotet["description"] == "Banking trojan"
        trickbot = malware_by_id["malware--22222222-2222-4222-8222-222222222222"]
        assert trickbot["name"] == "TrickBot"
        assert trickbot["is_family"] is False

    def test_malware_sdo_is_emitted_once_per_target(self):
        # The same Malware is returned by two distinct ``indicates``
        # relationships from the indicator: the SDO must only be emitted
        # once in the bundle (deduped by ``standard_id``) so we do not
        # carry duplicate Malware payloads.
        connector = _make_connector(yara={"propagate_malware_relationship": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        connector.helper.api.stix_core_relationship.list = MagicMock(
            return_value=[
                {
                    "to": {
                        "standard_id": (
                            "malware--44444444-4444-4444-8444-444444444444"
                        ),
                        "name": "Emotet",
                        "is_family": True,
                    }
                },
                {
                    "to": {
                        "standard_id": (
                            "malware--44444444-4444-4444-8444-444444444444"
                        ),
                        "name": "Emotet",
                        "is_family": True,
                    }
                },
            ]
        )
        artifact, indicator = self._matching_artifact_and_indicator()

        result, _ = connector._scan_artifact(artifact, [indicator])

        malware_sdos = [obj for obj in result if obj["type"] == "malware"]
        assert len(malware_sdos) == 1
        assert malware_sdos[0]["id"] == "malware--44444444-4444-4444-8444-444444444444"

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
                        "standard_id": (
                            "malware--33333333-3333-4333-8333-333333333333"
                        ),
                        "name": "RemoteAccessTool",
                        "is_family": False,
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
        # Only the relationship with a usable ``standard_id`` produces a
        # Malware SDO in the bundle.
        malware_sdos = [obj for obj in result if obj["type"] == "malware"]
        assert len(malware_sdos) == 1
        assert malware_sdos[0]["id"] == "malware--33333333-3333-4333-8333-333333333333"

    def test_malware_sdo_has_no_marking_refs(self):
        # The Malware SDO emitted by ``_build_malware_relationships``
        # uses the existing platform ``standard_id`` as its STIX ``id``,
        # so OpenCTI's ingestion path merges by id rather than creating
        # a new entity. Setting ``object_marking_refs`` on it would
        # propagate the Artifact / Indicator TLP markings onto the
        # already-existing Malware entity (potentially over-restricting
        # an entity shared across the platform). The TLP markings
        # belong on the Artifact -> Malware ``related-to`` relationship
        # only, which is the new object actually owned by this
        # enrichment cycle.
        artifact = {
            "id": "artifact-uuid",
            "standard_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "importFiles": [{"name": "test.bin", "id": "file-123"}],
            "objectMarking": [
                {
                    "standard_id": (
                        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                    )
                }
            ],
        }
        indicator = {
            "id": "indicator-uuid",
            "name": "test_rule",
            "standard_id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
            "pattern": 'rule test_rule { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
        }
        connector = _make_connector(yara={"propagate_malware_relationship": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        connector.helper.api.stix_core_relationship.list = MagicMock(
            return_value=[
                {
                    "to": {
                        "standard_id": (
                            "malware--55555555-5555-4555-8555-555555555555"
                        ),
                        "name": "Emotet",
                        "is_family": True,
                    }
                },
            ]
        )

        result, _ = connector._scan_artifact(artifact, [indicator])

        # The Malware SDO must NOT carry ``object_marking_refs``.
        malware_sdos = [obj for obj in result if obj["type"] == "malware"]
        assert len(malware_sdos) == 1
        assert "object_marking_refs" not in malware_sdos[0]

        # The Artifact -> Malware ``related-to`` relationship still
        # carries the Artifact's TLP markings, because that is the new
        # object this enrichment cycle owns.
        malware_relationships = [
            obj
            for obj in result
            if obj["type"] == "relationship"
            and obj["target_ref"].startswith("malware--")
        ]
        assert len(malware_relationships) == 1
        assert malware_relationships[0]["object_marking_refs"] == [
            "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
        ]


class TestScanArtifactDedupAcrossFiles:
    """``_scan_artifact`` runs propagation side-effects at most once per indicator.

    An Artifact may carry multiple ``importFiles``. The original
    implementation iterated ``for artifact_content in artifact_contents:
    for indicator in yara_indicators:`` and triggered the optional
    propagation side-effects (``stix_cyber_observable.add_label`` and
    ``stix_core_relationship.list``) on **every** file match — so a
    single Artifact / Indicator pair could produce N duplicate
    ``add_label`` mutations and N duplicate ``stix_core_relationship.list``
    round-trips when the same indicator matched N files. The dedup
    contract below pins the fix: propagation runs at most once per
    Artifact / Indicator pair, keyed by the indicator's
    ``standard_id``.
    """

    def _multi_file_artifact_and_indicator(self, *, labels=None):
        artifact = {
            "id": "artifact-uuid",
            "standard_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "importFiles": [
                {"name": "first.bin", "id": "file-1"},
                {"name": "second.bin", "id": "file-2"},
                {"name": "third.bin", "id": "file-3"},
            ],
        }
        indicator = {
            "id": "indicator-uuid",
            "name": "test_rule",
            "standard_id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
            "pattern": 'rule test_rule { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
        }
        if labels is not None:
            indicator["objectLabel"] = labels
        return artifact, indicator

    def test_add_label_runs_once_per_indicator_even_with_multiple_matching_files(
        self,
    ):
        connector = _make_connector(yara={"propagate_labels": True})
        # Every ``fetch_opencti_file`` call returns the matching payload
        # so the same indicator matches all three files.
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._multi_file_artifact_and_indicator(
            labels=[{"id": "label-1", "value": "apt", "color": "#ff0000"}]
        )

        connector._scan_artifact(artifact, [indicator])

        # ``add_label`` is called once per *label*, not once per
        # (file × label) — so a single label across three matching
        # files produces exactly one mutation.
        calls = connector.helper.api.stix_cyber_observable.add_label.call_args_list
        assert len(calls) == 1
        assert calls[0].kwargs["label_id"] == "label-1"

    def test_malware_lookup_runs_once_per_indicator_even_with_multiple_matching_files(
        self,
    ):
        connector = _make_connector(yara={"propagate_malware_relationship": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        connector.helper.api.stix_core_relationship.list = MagicMock(
            return_value=[
                {
                    "to": {
                        "standard_id": (
                            "malware--66666666-6666-4666-8666-666666666666"
                        ),
                        "name": "Emotet",
                        "is_family": True,
                    }
                },
            ]
        )
        artifact, indicator = self._multi_file_artifact_and_indicator()

        result, _ = connector._scan_artifact(artifact, [indicator])

        # ``stix_core_relationship.list`` is called once per indicator,
        # not once per (file × indicator).
        assert connector.helper.api.stix_core_relationship.list.call_count == 1

        # The Artifact -> Malware ``related-to`` relationship and the
        # Malware SDO are each emitted at most once across the multi-file
        # scan (the per-file Artifact -> Indicator ``related-to`` is
        # **not** deduped — that one is fine to emit multiple times
        # because each match represents one file's worth of evidence,
        # and the deterministic STIX id would dedupe it on ingestion if
        # required).
        malware_sdos = [obj for obj in result if obj["type"] == "malware"]
        assert len(malware_sdos) == 1
        malware_relationships = [
            obj
            for obj in result
            if obj["type"] == "relationship"
            and obj["target_ref"].startswith("malware--")
        ]
        assert len(malware_relationships) == 1

    def test_propagation_still_runs_for_each_distinct_indicator(self):
        # Dedup is *per Artifact / Indicator pair*, not per Artifact:
        # if two different indicators both match the artifact, both
        # must trigger their own propagation side-effects.
        connector = _make_connector(
            yara={
                "propagate_labels": True,
                "propagate_malware_relationship": True,
            }
        )
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        connector.helper.api.stix_core_relationship.list = MagicMock(return_value=[])
        artifact, _ = self._multi_file_artifact_and_indicator()
        indicator_a = {
            "id": "indicator-a",
            "name": "rule_a",
            "standard_id": "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "pattern": 'rule rule_a { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
            "objectLabel": [{"id": "label-a", "value": "apt", "color": "#ff0000"}],
        }
        indicator_b = {
            "id": "indicator-b",
            "name": "rule_b",
            "standard_id": "indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "pattern": 'rule rule_b { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
            "objectLabel": [
                {"id": "label-b", "value": "ransomware", "color": "#00ff00"}
            ],
        }

        connector._scan_artifact(artifact, [indicator_a, indicator_b])

        # Label propagation runs once per indicator (one ``add_label``
        # mutation per indicator, not per matching file).
        calls = connector.helper.api.stix_cyber_observable.add_label.call_args_list
        label_ids = sorted(c.kwargs["label_id"] for c in calls)
        assert label_ids == ["label-a", "label-b"]

        # Malware-relationship lookup runs once per indicator (two
        # distinct indicators -> two lookups, not 2 × 3 files).
        assert connector.helper.api.stix_core_relationship.list.call_count == 2
