import stix2
from pycti import Identity, Indicator, MarkingDefinition


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=self.config.tlp_level.lower())

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="DShield.org", identity_class="organization"),
            name="DShield.org",
            identity_class="organization",
            description="DESCRIPTION",
            external_references=[
                stix2.ExternalReference(
                    source_name="DShield",
                    url="https://feeds.dshield.org/",
                    description="DShield provides a platform for users of firewalls to share intrusion information.",
                )
            ],
        )
        return author

    @staticmethod
    def _create_tlp_marking(level):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    def create_indicator(self, subnet: str) -> dict:
        """
        Create indicator according to pattern given
        :param subnet: Value in string
        :return: Stix object for Indicator
        """
        indicator = stix2.Indicator(
            id=Indicator.generate_id(subnet),
            pattern=f"[ipv4-addr:value = '{subnet}']",
            created_by_ref=self.author["id"],
            pattern_type="stix",
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "x_opencti_main_observable_type": "IPv4-Addr",
            },
        )
        return indicator
