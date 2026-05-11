import stix2
from api_client.models import AttributeCategory, AttributeType, ExtendedAttributeItem
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
