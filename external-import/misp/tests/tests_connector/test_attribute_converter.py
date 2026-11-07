import pytest
import stix2
from api_client.models import (
    AttributeCategory,
    AttributeType,
    ExtendedAttributeItem,
    TagItem,
)
from connector.use_cases.common import ConverterConfig
from connector.use_cases.convert_attribute import AttributeConverter


def _make_config() -> ConverterConfig:
    return ConverterConfig(external_reference_base_url="http://dummy")


def _make_author() -> stix2.Identity:
    import pycti

    return stix2.Identity(
        id=pycti.Identity.generate_id(
            name="Test Author", identity_class="organization"
        ),
        name="Test Author",
        identity_class="organization",
    )


class TestThreatActorAttributionConversion:
    """Tests for MISP 'threat-actor' Attribution attribute → IntrusionSet conversion."""

    def test_threat_actor_attribution_creates_intrusion_set(self):
        # GIVEN a threat-actor attribute in Attribution category
        config = _make_config()
        converter = AttributeConverter(config)
        author = _make_author()
        attribute = ExtendedAttributeItem(
            type=AttributeType.threat_actor,
            category=AttributeCategory.Attribution,
            value="APT28",
            comment="Known threat actor",
        )

        # WHEN processing the attribute
        result = converter.process(
            attribute,
            labels=[],
            score=50,
            author=author,
            markings=[],
            external_references=[],
        )

        # THEN result contains exactly one IntrusionSet
        intrusion_sets = [obj for obj in result if isinstance(obj, stix2.IntrusionSet)]
        assert len(intrusion_sets) == 1
        assert intrusion_sets[0]["name"] == "APT28"


class TestLabelsPropagation:
    """Regression tests for the label-propagation fix (#4532)."""

    def test_process_does_not_mutate_caller_labels(self):
        """``AttributeConverter.process`` must never mutate its caller's list.

        Regression test for OpenCTI-Platform/connectors#4532: the previous
        implementation aliased the caller's ``labels`` list as
        ``attribute_labels`` and ``append``-ed the attribute tags to it,
        which made tags bleed into every subsequent attribute / object
        processed in the same event.
        """
        config = _make_config()
        converter = AttributeConverter(config)
        author = _make_author()
        attribute = ExtendedAttributeItem(
            type=AttributeType.domain,
            category=AttributeCategory.Network_activity,
            value="foo.bar",
            comment="",
            Tag=[TagItem(name="phishing")],
        )

        shared_labels = ["tlp:clear", "campaign:Alpha"]
        snapshot_before = list(shared_labels)

        converter.process(
            attribute,
            labels=shared_labels,
            score=50,
            author=author,
            markings=[],
            external_references=[],
        )

        # The caller's list must be untouched. ``snapshot_before`` is the
        # exact same content as ``shared_labels`` had at call time.
        assert shared_labels == snapshot_before


def _process_with_flags(
    attribute: ExtendedAttributeItem,
    create_indicators: bool,
    create_observables: bool,
    unsupported_as_text: bool = False,
) -> list:
    config = ConverterConfig(
        external_reference_base_url="http://dummy",
        convert_attribute_to_indicator=create_indicators,
        convert_attribute_to_observable=create_observables,
        convert_unsupported_object_to_text_observable=unsupported_as_text,
    )
    return AttributeConverter(config).process(
        attribute,
        labels=[],
        score=50,
        author=_make_author(),
        markings=[],
        external_references=[],
    )


def _make_ids_attribute(type_: str, value: str, **kwargs) -> ExtendedAttributeItem:
    return ExtendedAttributeItem.model_validate(
        {
            "type": type_,
            "category": "Network activity",
            "value": value,
            "to_ids": True,
            "timestamp": "1700000000",
            "comment": "",
            **kwargs,
        }
    )


def _of_type(stix_objects: list, stix_type: str) -> list:
    return [obj for obj in stix_objects if obj.get("type") == stix_type]


def _observables(stix_objects: list) -> list:
    return [obj for obj in stix_objects if isinstance(obj, stix2.v21._Observable)]


class TestIndicatorWithoutObservables:
    """Indicators must not depend on ``MISP_CREATE_OBSERVABLES`` (#8272)."""

    def test_indicator_is_created_when_observables_are_disabled(self):
        """An indicator is created and no observable is sent."""
        attribute = _make_ids_attribute("ip-dst", "203.0.113.10")

        result = _process_with_flags(
            attribute, create_indicators=True, create_observables=False
        )

        indicators = _of_type(result, "indicator")
        assert len(indicators) == 1
        assert indicators[0]["pattern"] == "[ipv4-addr:value = '203.0.113.10']"
        assert indicators[0]["x_opencti_main_observable_type"] == "IPv4-Addr"
        assert _observables(result) == []
        assert _of_type(result, "relationship") == []

    def test_indicator_is_based_on_observable_when_both_are_enabled(self):
        """With both options on, the indicator is still based on its observable."""
        attribute = _make_ids_attribute("ip-dst", "203.0.113.10")

        result = _process_with_flags(
            attribute, create_indicators=True, create_observables=True
        )

        indicators = _of_type(result, "indicator")
        observables = _observables(result)
        relationships = _of_type(result, "relationship")
        assert len(indicators) == 1
        assert len(observables) == 1
        assert len(relationships) == 1
        assert relationships[0]["relationship_type"] == "based-on"
        assert relationships[0]["source_ref"] == indicators[0]["id"]
        assert relationships[0]["target_ref"] == observables[0]["id"]

    def test_observables_only_when_indicators_are_disabled(self):
        """With indicators off, only the observable is sent, as before."""
        attribute = _make_ids_attribute("ip-dst", "203.0.113.10")

        result = _process_with_flags(
            attribute, create_indicators=False, create_observables=True
        )

        assert _of_type(result, "indicator") == []
        assert len(_observables(result)) == 1

    @pytest.mark.parametrize("create_observables", [True, False])
    def test_relationships_only_reference_sent_objects(self, create_observables):
        """No relationship points to an observable that is not sent."""
        attribute = _make_ids_attribute(
            "ip-dst",
            "203.0.113.10",
            Tag=[{"name": 'misp-galaxy:threat-actor="APT28"'}],
        )
        author = _make_author()

        result = _process_with_flags(
            attribute, create_indicators=True, create_observables=create_observables
        )

        sent_ids = {obj["id"] for obj in result} | {author["id"]}
        relationships = _of_type(result, "relationship")
        assert relationships
        for relationship in relationships:
            assert relationship["source_ref"] in sent_ids
            assert relationship["target_ref"] in sent_ids
        assert {r["relationship_type"] for r in relationships} == (
            {"based-on", "related-to", "indicates"}
            if create_observables
            else {"indicates"}
        )

    @pytest.mark.parametrize("create_observables", [True, False])
    @pytest.mark.parametrize("rule_type", ["yara", "sigma", "snort"])
    def test_rule_attribute_creates_indicator(self, rule_type, create_observables):
        """A rule becomes an indicator whose pattern is the rule itself."""
        rule = f"{rule_type} rule body"
        attribute = _make_ids_attribute(rule_type, rule, comment="Test rule")

        result = _process_with_flags(
            attribute,
            create_indicators=True,
            create_observables=create_observables,
        )

        indicators = _of_type(result, "indicator")
        assert len(indicators) == 1
        assert indicators[0]["pattern_type"] == rule_type
        assert indicators[0]["pattern"] == rule
        assert indicators[0]["name"] == "Test rule"
        assert "x_opencti_main_observable_type" not in indicators[0]
        assert _observables(result) == []

    def test_rule_attribute_without_comment_is_named_after_its_type(self):
        """Without a usable comment, the rule indicator is named after its type."""
        attribute = _make_ids_attribute("yara", "rule test { condition: true }")

        result = _process_with_flags(
            attribute, create_indicators=True, create_observables=True
        )

        assert _of_type(result, "indicator")[0]["name"] == "yara"

    def test_rule_attribute_keeps_text_observable_when_enabled(self):
        """With unsupported types imported as Text, a rule keeps its Text observable."""
        attribute = _make_ids_attribute("yara", "rule test { condition: true }")

        result = _process_with_flags(
            attribute,
            create_indicators=True,
            create_observables=True,
            unsupported_as_text=True,
        )

        indicators = _of_type(result, "indicator")
        observables = _observables(result)
        assert len(indicators) == 1
        assert indicators[0]["pattern_type"] == "yara"
        assert indicators[0]["x_opencti_main_observable_type"] == "Text"
        assert indicators[0]["name"] == "Text"
        assert [obs["type"] for obs in observables] == ["text"]
        assert _of_type(result, "relationship")[0]["relationship_type"] == "based-on"
