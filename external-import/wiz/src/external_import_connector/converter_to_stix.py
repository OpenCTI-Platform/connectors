import stix2
from pycti import Identity, MarkingDefinition


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self._create_author(self.helper.connect_name)
        self.external_reference = self._create_external_reference(
            self.helper.connect_name
        )
        self.tlp_marking = self._create_tlp_marking(level=self.config.tlp_level.lower())

    @staticmethod
    def _create_external_reference(source_name: str) -> stix2.ExternalReference:
        return stix2.ExternalReference(
            source_name=source_name,
            url="https://www.wiz.io/api/feed/cloud-threat-landscape/stix.json",
            description="A comprehensive threat intelligence database of cloud security "
            "incidents, actors, tools and techniques. Powered by Wiz Research.",
        )

    @staticmethod
    def _create_author(name: str) -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name=name, identity_class="organization"),
            name=name,
            identity_class="organization",
            description="WIZ Research is an SME specialised in complex digital systems "
            "with a unique combination of expertise in data-driven digital twins, artificial "
            "intelligence staking, multi-organisation decentralised data structures and "
            "human-centred interfaces",
        )

    @staticmethod
    def _create_tlp_marking(level) -> stix2.MarkingDefinition:
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
