import datetime

import pytz
from connectors_sdk.models import (
    URL,
    File,
    Note,
    OrganizationAuthor,
    Reference,
    Relationship,
    Sector,
)
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """
    Provides methods for converting various types of input data into
    STIX 2.1 objects with connectors_sdk models.
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """
        Initialize the converter with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
        """
        self.helper = helper
        self.author = self.create_author()

    @staticmethod
    def create_author() -> OrganizationAuthor:
        """
        Create Author
        """
        author = OrganizationAuthor(name="Kaspersky Enrichment")
        return author

    def create_file(self, observable: dict) -> File:
        file = File(
            hashes=observable.get("hashes"),
            size=observable.get("size"),
            name=observable.get("name"),
            mime_type=observable.get("mime_type"),
            ctime=observable.get("ctime"),
            mtime=observable.get("mtime"),
            atime=observable.get("atime"),
            additional_names=[observable.get("additional_names")],
        )
        return file

    def create_note(self, observable: Reference, content: str) -> Note:
        """
        Create a note associated to the file observable
        """
        return Note(
            abstract="Kaspersky Detections Info",
            content=content,
            objects=[observable],
            author=self.author,
            publication_date=datetime.datetime.now().astimezone(pytz.UTC),
        )

    def create_reference(self, obs_id: str) -> Reference:
        """
        Create a simple Reference object
        """
        return Reference(id=obs_id)

    def create_relationship(
        self, relationship_type: str, source_obj, target_obj
    ) -> Relationship:
        """
        Creates Relationship object
        """
        return Relationship(
            type=relationship_type,
            source=source_obj,
            target=target_obj,
            author=self.author,
        )

    def create_sector(self, industry: str) -> Sector:
        """
        Create a Sector object
        """
        return Sector(
            name=industry,
            author=self.author,
        )

    def create_url(self, obs_url_score: int, url_info: dict) -> URL:
        """
        Create an URL object
        """
        return URL(
            value=url_info["Url"],
            score=obs_url_score,
        )
