"""STIX Converter."""

import stix2
from pycti import Identity, Vulnerability


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author()

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="FIRST EPSS", identity_class="organization"),
            name="FIRST EPSS",
            identity_class="organization",
        )
        return author

    def create_vulnerability(self, data: dict) -> dict:
        """Create vulnerability according to value given
        :param data: Dictionary of vulnerability properties
        :return: Vulnerability STIX2 object.
        """

        stix_vulnerability = stix2.Vulnerability(
            id=Vulnerability.generate_id(data["name"]),
            name=data["name"],
            created_by_ref=self.author["id"],
            custom_properties={
                "x_opencti_epss_score": data["x_opencti_epss_score"],
                "x_opencti_epss_percentile": data["x_opencti_epss_percentile"],
            },
        )

        return stix_vulnerability
