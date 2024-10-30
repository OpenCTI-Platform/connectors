from datetime import datetime

import pycti
import stix2


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
        self.external_reference = self.create_external_reference()

    def create_external_reference(self) -> list:
        """
        Create external reference
        :return: External reference STIX2 list
        """
        external_reference = stix2.ExternalReference(
            source_name="External Source",
            url="CHANGEME",
            description="DESCRIPTION",
        )
        return [external_reference]

    def create_author(self) -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                name=self.config.author_name, identity_class="organization"
            ),
            name=self.config.author_name,
            identity_class="organization",
            description=self.config.author_description,
            x_opencti_reliability=self.config.author_reliability,
            allow_custom=True,
        )

    def create_note(self, abstract: str, content: str, object_refs: list) -> dict:
        """
        Create Note
        :param abstract: Abstract of note in string
        :param content: Content of note in string
        :param object_refs: ID of indicator in list
        :return: Note in Stix2 object
        """
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        return stix2.Note(
            id=pycti.Note.generate_id(created=now, content=content),
            abstract=abstract,
            content=content,
            object_refs=object_refs,
        )

    # Not used yet.
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
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
            external_references=self.external_reference,
        )
