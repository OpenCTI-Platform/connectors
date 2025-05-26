from datetime import datetime
from typing import Literal

from connector.models import (
    Author,
    TLPMarking,
    ExternalReference,
    Relationship,
)
import stix2
import pycti

class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self._author = self.make_author()
        self._tlp_marking = self.make_tlp_marking(
            level=self.config.cofense_threathq.tlp_level
        )

    @staticmethod
    def make_author() -> Author:
        """Make an Author object and its representation in STIX 2.1 format.
        The author represents Cofense ThreatHQ as the source of the data.

        Returns:
            Author: A Author object and its representation in STIX 2.1 format.
        """
        return Author(
            name="Cofense ThreatHQ",
            organization_type="vendor",
            description="Cofense ThreatHQ is a specialized phishing threat detection, analysis and management platform,"
                        " part of the Cofense Intelligence ecosystem. It provides real-time monitoring of indicators of"
                        " compromise (IOCs) linked to phishing attacks, enabling security teams (SOCs) to prioritize "
                        "and automate response to the most critical threats.",
        )

    def make_tlp_marking(self) -> stix2.MarkingDefinition:
        """ Creates a TLP marking definition object and its representation in STIX 2.1 format.
        This marking is used to classify the confidentiality level of the data.
        Return: stix2.MarkingDefinition
        """
        mapping = {
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[self.config.cofense_threathq.tlp_level]

    @staticmethod
    def make_external_reference(
            entity_number: str,
            external_id: str = None,
            description: str = None,
    ) -> ExternalReference:
        """Make an `ExternalReference` object and its representation in STIX 2.1 format.

        Args:
            entity_number (str): Represents the entity name on Cofense ThreatHQ (CTHQ).
            external_id (str | None): Unique identifier of the entity in Cofense ThreatHQ (CTHQ).
            description (str | None): Description of external reference.
        Returns:
            ExternalReference: An external reference in STIX 2.1 format.
        """
        return stix2.ExternalReference(
            source_name=f"",
            url=f"",
            description="",
            external_id="",
        )


    def make_relationship(
            self,
            source_object,
            relationship_type: str,
            target_object,
            start_time: datetime = None,
    ) -> stix2.Relationship:
        """Creates a relationship object and its representation in STIX 2.1 format.

        Args:
            source_object: The source object.
            relationship_type (str): The type of the relationship.
            target_object: The target object to relate to the source.
            start_time (datetime, optional): The time the relationship started being relevant or observed.
        Returns:
            Relationship: A Relationship object and its representation in STIX 2.1 format.
        """
        return stix2.Relationship(
            relationship_type=relationship_type,
            source=source_object,
            target=target_object,
            start_time=start_time,
            markings=[self._tlp_marking],
            author=self._author,
        )

    def make_url(
        self,
    ) -> stix2.URL:
        return stix2.URL(

        )

    def make_file(
            self,
    )-> stix2.File:
        return stix2.File(

        )

    def make_email(
            self,
    ) -> stix2.EmailAddress:
        return stix2.EmailAddress(

        )

    def make_email_subject(
            self,
    ) -> stix2.EmailMessage:
        return stix2.EmailMessage(

        )

    def make_ipv4_address(
            self,
    ) -> stix2.IPv4Address:
        return stix2.IPv4Address(

        )

    def make_domain_name(
            self,
    ) -> stix2.DomainName:
        return stix2.DomainName(
            value="",
            object_marking_refs="",
            custom_properties={
                x
            },
        )

    def make_report(
            self,
            report,
    ) -> stix2.Report:
        return stix2.Report(
            id=pycti.Report.generate_id(name="", published=""),
            name="",
            report_types="",
            object_refs="",
            created="",
            modified="",
            published="",
            labels="",
            object_marking_refs="",
            created_by_ref=self._author,
            external_references=[],
            custom_properties={
                "x_opencti_files": [report.get("report_pdf_binary")]
            }
        )
