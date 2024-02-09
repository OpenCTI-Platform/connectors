import stix2
from pycti import Identity, Indicator, OpenCTIConnectorHelper, StixCoreRelationship


class MalbeaconConverter:
    """
    Convert data from Malbeacon to STIX 2 object
    """

    def __init__(self, helper):
        self.helper = helper

    @staticmethod
    def create_external_reference(url) -> list:
        """
        Create external reference
        :return: External reference STIX2 list
        """
        external_reference = stix2.ExternalReference(
            source_name="Malbeacon C2 Domains",
            url=url,
            description="Found in Malbeacon C2 Domains",
        )
        return [external_reference]

    @staticmethod
    def create_author() -> dict:
        """
        Create Malbeacon Author
        :return: Author in Stix2 object
        """
        return stix2.Identity(
            id=Identity.generate_id("Malbeacon", "organization"),
            name="Malbeacon",
            identity_class="organization",
            description="""The first system of its kind, MalBeacon implants \
                    beacons via malware bot check-in traffic. Adversaries conducting \
                    campaigns in the wild who are logging in to these malware C2 \
                    panels can now be tracked. MalBeacon is a tool for the good guys \
                    that provides additional intelligence on attack attribution.""",
        )
