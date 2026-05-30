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
        # Result contains 1 relationship + 1 indicator + 1 fallback TLP
        # MarkingDefinition. The MarkingDefinition is emitted because
        # neither the Artifact nor the matched Indicator carry an
        # ``objectMarking`` list, so ``_collect_marking_refs`` falls
        # back to ``self.tlp_level`` (``clear`` by default) and the
        # corresponding STIX object must ride along in the bundle so
        # ``send_stix2_bundle(..., cleanup_inconsistent_bundle=True)``
        # does not drop the relationship as inconsistent.
        assert len(result) == 3
        relationships = [obj for obj in result if obj.get("type") == "relationship"]
        indicators_emitted = [obj for obj in result if obj.get("type") == "indicator"]
        markings = [obj for obj in result if obj.get("type") == "marking-definition"]
        assert len(relationships) == 1
        assert relationships[0]["relationship_type"] == "related-to"
        assert relationships[0]["created_by_ref"] == connector.author["id"]
        assert markings[0]["id"] in relationships[0]["object_marking_refs"]
        assert len(indicators_emitted) == 1
        assert len(markings) == 1
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


class TestMarkingDefinitionInBundle:
    """``_collect_marking_refs`` fallback emits the corresponding
    ``MarkingDefinition`` object so the bundle is self-consistent under
    ``send_stix2_bundle(..., cleanup_inconsistent_bundle=True)``.

    The worker drops relationships whose ``object_marking_refs`` point
    at marking ids that are not also present as SDOs anywhere in the
    bundle. ``_collect_marking_refs`` generates the fallback id
    locally (no platform-side STIX object backs it), so the connector
    must emit the corresponding ``MarkingDefinition`` itself.
    """

    def _matching_artifact_and_indicator(
        self,
        artifact_markings=None,
        indicator_markings=None,
    ):
        artifact = {
            "id": "artifact-uuid",
            "standard_id": "artifact--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "importFiles": [{"name": "test.bin", "id": "file-123"}],
        }
        if artifact_markings is not None:
            artifact["objectMarking"] = artifact_markings
        indicator = {
            "id": "indicator-uuid",
            "name": "test_rule",
            "standard_id": "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
            "pattern": 'rule test_rule { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
        }
        if indicator_markings is not None:
            indicator["objectMarking"] = indicator_markings
        return artifact, indicator

    def test_fallback_marking_object_is_added_to_bundle(self):
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._matching_artifact_and_indicator()
        result, _errors = connector._scan_artifact(artifact, [indicator])

        markings = [obj for obj in result if obj.get("type") == "marking-definition"]
        relationships = [obj for obj in result if obj.get("type") == "relationship"]
        assert (
            len(markings) == 1
        ), "fallback TLP MarkingDefinition must ride along in the bundle"
        # The id on the relationship and on the emitted MarkingDefinition
        # have to match so the worker does not drop the relationship as
        # inconsistent.
        assert markings[0]["id"] in relationships[0]["object_marking_refs"]
        # Default TLP is ``clear`` (per ``yara.tlp_level`` default),
        # which materialises as a ``TLP:CLEAR`` marking definition.
        assert markings[0]["x_opencti_definition"] == "TLP:CLEAR"

    def test_fallback_marking_emitted_once_across_multiple_indicators(self):
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._matching_artifact_and_indicator()
        # Two distinct indicators that both match the same artifact; both
        # fall back to the same TLP, so we should emit the marking
        # object exactly once.
        second_indicator = {
            "id": "indicator-uuid-2",
            "name": "second_rule",
            "standard_id": "indicator--c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f",
            "pattern": 'rule second_rule { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
        }
        result, _errors = connector._scan_artifact(
            artifact, [indicator, second_indicator]
        )

        markings = [obj for obj in result if obj.get("type") == "marking-definition"]
        assert len(markings) == 1

    def test_no_fallback_marking_when_artifact_carries_markings(self):
        """When the Artifact already carries its own markings,
        ``_collect_marking_refs`` does **not** fall back to the
        configured default, so no MarkingDefinition is added to the
        bundle by this code path — the marking object is expected to
        ride along on ``stix_objects`` from the enrichment message.
        """
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact_marking_id = (
            "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"  # TLP:GREEN
        )
        artifact, indicator = self._matching_artifact_and_indicator(
            artifact_markings=[{"standard_id": artifact_marking_id}]
        )
        result, _errors = connector._scan_artifact(artifact, [indicator])

        markings = [obj for obj in result if obj.get("type") == "marking-definition"]
        relationships = [obj for obj in result if obj.get("type") == "relationship"]
        assert markings == []
        # The relationship still carries the inherited marking ref.
        assert artifact_marking_id in relationships[0]["object_marking_refs"]

    def test_marking_refs_are_sorted_for_deterministic_emission(self):
        """``object_marking_refs`` MUST be emitted in a stable order.

        ``_collect_marking_refs`` collects refs into a Python ``set`` for
        dedup, and ``set`` iteration order is unspecified across
        processes. Two consecutive scans of the same Artifact must
        therefore produce identical STIX bytes — otherwise OpenCTI's
        ingestion path would see the same Relationship as "modified" on
        every cycle, triggering needless downstream diff / update work.
        Pinning the contract: marking refs come out sorted.
        """
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        # Two markings whose alphanumeric order is the opposite of the
        # order they appear in the ``objectMarking`` payload, so we can
        # distinguish "preserved insertion order" from "sorted". Both
        # ids are valid STIX 2.1 UUIDv4 (variant nibble in
        # ``{8, 9, a, b}``).
        artifact_marking_id = "marking-definition--ffffffff-eeee-4ddd-bbbb-aaaaaaaaaaaa"
        indicator_marking_id = (
            "marking-definition--00000000-0000-4000-8000-000000000000"
        )
        artifact, indicator = self._matching_artifact_and_indicator(
            artifact_markings=[{"standard_id": artifact_marking_id}],
            indicator_markings=[{"standard_id": indicator_marking_id}],
        )
        result, _errors = connector._scan_artifact(artifact, [indicator])

        relationships = [obj for obj in result if obj.get("type") == "relationship"]
        assert len(relationships) == 1
        refs = list(relationships[0]["object_marking_refs"])
        assert refs == sorted(refs), (
            "object_marking_refs must be emitted in deterministic "
            f"(sorted) order; got {refs!r}"
        )
        # And both inherited markings made it through.
        assert artifact_marking_id in refs
        assert indicator_marking_id in refs


class TestPropagationTogglesDefaultOff:
    """Pin the no-config-override default for both propagation toggles.

    The ``propagate_labels=False`` / ``propagate_malware_relationship=False``
    cases below exercise the *explicit* off shape (operator setting the
    flag to ``False`` in config). This class covers the harder
    regression: a fresh deployment with **no** ``yara`` overrides in
    config (the shape every existing deployment has) must keep both
    side-channel APIs (``stix_cyber_observable.add_label``,
    ``stix_core_relationship.list``) silent, so the change to add the
    two opt-in fields cannot have an accidental backward-compat
    impact.
    """

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
            "pattern": ('rule test_rule { strings: $a = "test data" condition: $a }'),
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
            # Labels are populated to prove the default behaviour is
            # "do not propagate" rather than "no labels to propagate".
            "objectLabel": [
                {"id": "label-1", "value": "apt", "color": "#ff0000"},
            ],
        }
        return artifact, indicator

    def test_default_settings_do_not_call_side_channel_apis(self):
        # No ``yara`` overrides at all — pydantic defaults take effect.
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._matching_artifact_and_indicator()

        connector._scan_artifact(artifact, [indicator])

        # Both side-channel APIs must be silent in the default config.
        connector.helper.api.stix_cyber_observable.add_label.assert_not_called()
        connector.helper.api.stix_core_relationship.list.assert_not_called()

    def test_default_settings_still_emit_basic_relationship(self):
        """Default config must still emit the Artifact -> Indicator relationship.

        The two toggles are opt-in *additions* on top of the basic
        Artifact -> Indicator ``related-to`` relationship — disabling
        them must not silently kill the connector's primary output.
        """
        connector = _make_connector()
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        artifact, indicator = self._matching_artifact_and_indicator()

        result, _ = connector._scan_artifact(artifact, [indicator])

        relationships = [obj for obj in result if obj["type"] == "relationship"]
        # Exactly one Artifact -> Indicator ``related-to`` relationship,
        # and zero Artifact -> Malware relationships (propagation is off).
        artifact_to_indicator = [
            rel for rel in relationships if rel["target_ref"].startswith("indicator--")
        ]
        artifact_to_malware = [
            rel for rel in relationships if rel["target_ref"].startswith("malware--")
        ]
        assert len(artifact_to_indicator) == 1
        assert artifact_to_malware == []


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
        # Every malformed relationship payload below must be silently
        # skipped — none of them must raise. In particular the
        # truthy-but-not-a-dict shapes (``"to": ["..."]`` and
        # ``"to": "..."``) would slip past ``rel.get("to") or {}`` (only
        # falsy values trigger that fallback), and the subsequent
        # ``target.get("standard_id")`` would raise ``AttributeError``
        # and abort the whole scan — the very crash the
        # ``isinstance(target, dict)`` guard in
        # ``_build_malware_relationships`` is meant to prevent.
        connector = _make_connector(yara={"propagate_malware_relationship": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        connector.helper.api.stix_core_relationship.list = MagicMock(
            return_value=[
                {"to": None},  # falsy non-dict (caught by ``or {}``)
                {"to": {}},  # missing standard_id
                {"to": ["something"]},  # truthy non-dict (list)
                {"to": "some-id"},  # truthy non-dict (string)
                "not-a-relationship-dict",  # top-level non-dict
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

    def test_malware_dedup_is_shared_across_indicators(self):
        # Two different YARA Indicators commonly ``indicates`` the
        # same Malware (a generic loader rule + a family-specific
        # config rule, both pointing at the same Malware SDO). The
        # ``_build_malware_relationships`` helper deduplicates Malware
        # SDOs and Artifact -> Malware relationships **across** the
        # whole ``_scan_artifact`` run, not just within one call —
        # so the bundle carries each Malware SDO and each Artifact ->
        # Malware ``related-to`` relationship at most once even when
        # several Indicators point at the same target.
        connector = _make_connector(yara={"propagate_malware_relationship": True})
        connector.helper.api.fetch_opencti_file = MagicMock(
            return_value=b"This is test data"
        )
        # Both indicators ``indicates`` the same Malware (Emotet).
        shared_malware = {
            "to": {
                "standard_id": "malware--66666666-6666-4666-8666-666666666666",
                "name": "Emotet",
                "is_family": True,
            }
        }
        connector.helper.api.stix_core_relationship.list = MagicMock(
            return_value=[shared_malware]
        )
        artifact, _ = self._multi_file_artifact_and_indicator()
        indicator_a = {
            "id": "indicator-a",
            "name": "rule_a",
            "standard_id": "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "pattern": 'rule rule_a { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
        }
        indicator_b = {
            "id": "indicator-b",
            "name": "rule_b",
            "standard_id": "indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "pattern": 'rule rule_b { strings: $a = "test data" condition: $a }',
            "pattern_type": "yara",
            "valid_from": "2025-01-01T00:00:00Z",
        }

        result, _errors = connector._scan_artifact(artifact, [indicator_a, indicator_b])

        # The per-indicator ``indicates`` lookup still fires twice
        # (one per Indicator) — that's expected and exercises the
        # cross-call dedup.
        assert connector.helper.api.stix_core_relationship.list.call_count == 2

        # Across both calls, the shared Emotet Malware SDO is emitted
        # exactly once into the bundle.
        malware_sdos = [obj for obj in result if obj["type"] == "malware"]
        assert len(malware_sdos) == 1
        assert malware_sdos[0]["id"] == "malware--66666666-6666-4666-8666-666666666666"

        # The Artifact -> Malware ``related-to`` relationship is also
        # emitted exactly once (the deterministic STIX id is the same
        # because both source / target ids are the same).
        malware_relationships = [
            obj
            for obj in result
            if obj["type"] == "relationship"
            and obj["target_ref"].startswith("malware--")
        ]
        assert len(malware_relationships) == 1
        assert (
            malware_relationships[0]["target_ref"]
            == "malware--66666666-6666-4666-8666-666666666666"
        )
