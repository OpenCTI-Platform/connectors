import stix2
from pycti import Identity


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(
        self,
    ):
        self.author = self.create_author()

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(
                identity_class="organization", name="The Aerospace Corporation"
            ),
            name="The Aerospace Corporation",
            identity_class="organization",
            object_marking_refs=[stix2.TLP_WHITE],
            external_references=[
                {
                    "source_name": "Aerospace Sparta Main URL",
                    "url": "https://sparta.aerospace.org/",
                }
            ],
        )
        return author
