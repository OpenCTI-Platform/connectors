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
