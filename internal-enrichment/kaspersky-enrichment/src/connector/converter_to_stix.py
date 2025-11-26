import datetime

import stix2
from pycti import Identity, Note, OpenCTIConnectorHelper, StixCoreRelationship


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
        - `generate_id()` methods from `pycti` library MUST be used to generate the `id` of each entity (except observables),
        e.g. `pycti.Identity.generate_id(name="Source Name", identity_class="organization")` for a STIX Identity.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, tlp_level: str):
        """
        Initialize the converter with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `tlp_level`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            tlp_level (str): The TLP level to add to the created STIX entities.
        """
        self.helper = helper

        self.author = self.create_author()

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(
                name="Kaspersky Enrichment", identity_class="organization"
            ),
            name="Kaspersky Enrichment",
            identity_class="organization",
        )
        return author

    def create_file_note(self, obs_id, detection_info):
        """
        Create a note associated to the file observable
        """
        detection_name = (
            f"[{detection_info["DetectionName"]}]({detection_info["DescriptionUrl"]})"
        )
        content = "| Detection Date | Detection Name | Detection Method |\n"
        content += "|----------------|----------------|------------------|\n"
        content += (
            "| "
            + str(detection_info["LastDetectDate"])
            + " | "
            + str(detection_name)
            + " | "
            + str(detection_info["DetectionMethod"])
            + " |\n"
        )

        note = stix2.Note(
            type="note",
            id=Note.generate_id(datetime.datetime.now().isoformat(), content),
            abstract="Kaspersky Detections Info",
            content=content,
            created_by_ref=self.author,
            object_refs=[obs_id],
        )
        return note

    def create_sector(self, industry: str):
        """
        Create a Sector object
        """
        return stix2.Identity(
            id=Identity.generate_id(identity_class="class", name=industry),
            identity_class="class",
            name=industry,
            created_by_ref=self.author.id,
        )

    def create_url(self, obs_url_score: int, url_info: dict):
        """
        Create an URL object
        """
        return stix2.URL(
            value=url_info["Url"],
            # object_marking_refs=[self._default_tlp],
            custom_properties={
                "score": obs_url_score,
            },
        )

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> dict:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
        )
        return relationship
