from typing import Literal
from pycti import OpenCTIConnectorHelper
from .config_loader import ConfigLoader
from ..models import opencti, spycloud


SEVERITY_LEVELS_BY_CODE = {2: "low", 5: "medium", 20: "high", 25: "critical"}


class ConverterToStix:
    """
    Provides methods for converting SpyCloud objects into OCTI objects following STIX 2.1 specification.
    """

    def __init__(
        self, helper: OpenCTIConnectorHelper = None, config: ConfigLoader = None
    ):
        self.helper = helper
        self.config = config
        self.author = ConverterToStix._create_author(
            name=self.helper.connect_name,
            description="SpyCloud external import connector",
            identity_class="organization",
        )

    def create_incident(
        self,
        breach_record: spycloud.BreachRecord = None,
        breach_catalog: spycloud.BreachCatalog = None,
    ) -> opencti.Incident:
        """
        Create an Incident from given breach record and its catalog.
        :param breach_record: SpyCloud breach record
        :param breach_catalog: SpyCloud breach record's catalog
        :return: OpenCTI Incident
        """
        incident_source = breach_catalog.title or "Unknown"
        incident_severity = SEVERITY_LEVELS_BY_CODE.get(breach_record.severity)
        incident_name = f"Spycloud {incident_severity} alert on {breach_record.email or breach_record.username or breach_record.ip[0] or breach_record.document_id}"
        incident_description = "a markdown table of breach record's keys/values"

        incident = opencti.Incident(
            name=incident_name,
            description=incident_description,
            source=incident_source,
            severity=incident_severity,
            incident_type="data-breach",
            author=self.author,
            created_at=breach_record.spycloud_publish_date,
            updated_at=breach_record.spycloud_publish_date,
            object_marking_refs=[],
        )
        return incident

    @staticmethod
    def _create_author(
        name: str = None, description: str = None, identity_class: str = None
    ) -> opencti.Author:
        """
        Create an Author.
        :return: OpenCTI Author
        """
        author = opencti.Author(
            name=name,
            identity_class=identity_class,
            description=description,
        )
        return author
    