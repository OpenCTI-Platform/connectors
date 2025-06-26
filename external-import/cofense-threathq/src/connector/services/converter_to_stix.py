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
        self._tlp_marking = self.make_tlp_marking()
        self._author = self.make_author()

    def make_author(self) -> stix2.Identity:
        """Make an Author object and its representation in STIX 2.1 format.
        The author represents Cofense ThreatHQ as the source of the data.

        Returns:
            Author: A Author object and its representation in STIX 2.1 format.
        """
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                identity_class="organization", name="Cofense ThreatHQ"
            ),
            name="Cofense ThreatHQ",
            identity_class="organization",
            description="Cofense ThreatHQ is a specialized phishing threat detection, analysis and management platform,"
            " part of the Cofense Intelligence ecosystem. It provides real-time monitoring of indicators of"
            " compromise (IOCs) linked to phishing attacks, enabling security teams (SOCs) to prioritize "
            "and automate response to the most critical threats.",
            custom_properties={"x_opencti_organization_type": "vendor"},
            object_marking_refs=[self._tlp_marking.get("id")],
            external_references=[
                stix2.ExternalReference(
                    source_name="Cofense-ThreatHQ",
                    url="https://www.threathq.com/login",
                    description="Official site of Cofense ThreatHQ.",
                )
            ],
        )

    def make_tlp_marking(self) -> stix2.MarkingDefinition:
        """Creates a TLP marking definition object and its representation in STIX 2.1 format.
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
        data: dict,
    ) -> stix2.ExternalReference:
        """Make an `ExternalReference` object and its representation in STIX 2.1 format.

        Args:
            data (dict):
        Returns:
            ExternalReference: An external reference in STIX 2.1 format.
        """
        return stix2.ExternalReference(
            source_name=f"{data.get("entity_name")}-{data.get("threat_id")}",
            url=data.get("threat_detail_url"),
            description=data.get("description"),
            external_id=data.get("threat_id"),
        )

    def make_relationship(
        self,
        source_id: str,
        relationship_type: str,
        target_id: str,
        start_time: datetime = None,
    ) -> stix2.Relationship:
        """Creates a relationship object and its representation in STIX 2.1 format.

        Args:
            source_id (str): The source id.
            relationship_type (str): The type of the relationship.
            target_id (str): The target id to relate to the source.
            start_time (datetime, optional): The time the relationship started being relevant or observed.
        Returns:
            Relationship: A Relationship object and its representation in STIX 2.1 format.
        """
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            start_time=start_time,
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            object_marking_refs=[self._tlp_marking.get("id")],
            created_by_ref=self._author.get("id"),
        )

    def make_url(
        self,
        data,
        labels,
        external_references,
    ) -> stix2.URL:
        return stix2.URL(
            value=data.get("data"),
            object_marking_refs=[self._tlp_marking.get("id")],
            custom_properties={
                "x_opencti_created_by": self._author.get("id"),
                "x_opencti_labels": labels,
                "x_opencti_description": data.get("roleDescription"),
                "x_opencti_external_references": external_references,
                "x_opencti_main_observable_type": "Url",
            },
        )

    def make_file(
        self,
        data,
        labels,
        external_references,
    ) -> stix2.File:

        hashes_mapping = {
            "md5Hex": "MD5",
            "sha1Hex": "SHA-1",
            "sha256Hex": "SHA-256",
            "sha512Hex": "SHA-512",
        }

        hashes = {}
        for field, stix_key in hashes_mapping.items():
            hash_value = data.get(field)
            if hash_value:
                hashes[stix_key] = hash_value
        return stix2.File(
            name=data.get("fileName"),
            hashes=hashes,
            object_marking_refs=[self._tlp_marking.get("id")],
            custom_properties={
                "x_opencti_created_by": self._author.get("id"),
                "x_opencti_labels": labels,
                "x_opencti_external_references": external_references,
                "x_opencti_main_observable_type": "StixFile",
            },
        )

    def make_email(
        self,
        data,
        labels,
        external_references,
    ) -> stix2.EmailAddress:
        return stix2.EmailAddress(
            value=data.get("data"),
            object_marking_refs=[self._tlp_marking.get("id")],
            custom_properties={
                "x_opencti_created_by": self._author.get("id"),
                "x_opencti_labels": labels,
                "x_opencti_description": data.get("roleDescription"),
                "x_opencti_external_references": external_references,
                "x_opencti_main_observable_type": "Email-Addr",
            },
        )

    def make_email_subject(
        self,
        email_subject,
        labels,
        external_references,
        description,
    ) -> stix2.EmailMessage:
        return stix2.EmailMessage(
            subject=email_subject,
            is_multipart=False,
            object_marking_refs=[self._tlp_marking.get("id")],
            custom_properties={
                "x_opencti_created_by": self._author.get("id"),
                "x_opencti_labels": labels,
                "x_opencti_description": description,
                "x_opencti_external_references": external_references,
                "x_opencti_main_observable_type": "Email-Message",
            },
        )

    def make_ipv4_address(
        self,
        data,
        labels,
        external_references,
    ) -> stix2.IPv4Address:
        return stix2.IPv4Address(
            value=data.get("data"),
            object_marking_refs=[self._tlp_marking.get("id")],
            custom_properties={
                "x_opencti_created_by": self._author.get("id"),
                "x_opencti_labels": labels,
                "x_opencti_description": data.get("roleDescription"),
                "x_opencti_external_references": external_references,
                "x_opencti_main_observable_type": "IPv4-Addr",
            },
        )

    def make_domain_name(
        self,
        data,
        labels,
        external_references,
    ) -> stix2.DomainName:
        return stix2.DomainName(
            value=data.get("data"),
            object_marking_refs=[self._tlp_marking.get("id")],
            custom_properties={
                "x_opencti_created_by": self._author.get("id"),
                "x_opencti_labels": labels,
                "x_opencti_description": data.get("roleDescription"),
                "x_opencti_external_references": external_references,
                "x_opencti_main_observable_type": "Domain-Name",
            },
        )

    def make_autonomous_system(
        self, data, labels, external_references
    ) -> stix2.AutonomousSystem:
        return stix2.AutonomousSystem(
            name=data.value,
            number=int(data.number),
            object_marking_refs=[self._tlp_marking.get("id")],
            custom_properties={
                "x_opencti_created_by": self._author.get("id"),
                "x_opencti_labels": labels,
                "x_opencti_external_references": external_references,
                "x_opencti_main_observable_type": "Autonomous-System",
            },
        )

    def make_vulnerability(
        self,
        data,
    ) -> stix2.Vulnerability:
        return stix2.Vulnerability(
            id=pycti.Vulnerability.generate_id(name=data.name),
            name=data.name,
            object_marking_refs=[self._tlp_marking.get("id")],
            custom_properties={
                "x_opencti_created_by": self._author.get("id"),
                "x_opencti_labels": data.labels,
                "x_opencti_description": data.description,
                "x_opencti_external_references": [data.external_reference],
            },
        )

    def make_report(
        self,
        new_report_info,
        description,
        labels,
        object_refs,
        external_references,
        first_published_timestamp_utc,
        last_published_timestamp_utc,
    ) -> stix2.Report:
        report_name = (
            str(new_report_info.get("threat_id"))
            + " - "
            + new_report_info.get("threat_title")
        )

        report_type = new_report_info.get("threat_title")

        if report_type and "credential phishing" not in report_type.lower():
            report_type = "Malware Campaign"
        else:
            report_type = "Credential Phishing"

        report_pdf_binary = new_report_info.get("pdf_binary")
        if report_pdf_binary:
            report_pdf_binary["object_marking_refs"] = [self._tlp_marking.get("id")]
        else:
            report_pdf_binary = None

        return stix2.Report(
            id=pycti.Report.generate_id(
                name=report_name, published=first_published_timestamp_utc
            ),
            name=report_name,
            description=description,
            report_types=[report_type],
            object_refs=object_refs,
            created=first_published_timestamp_utc,
            modified=last_published_timestamp_utc,
            published=first_published_timestamp_utc,
            labels=labels,
            object_marking_refs=[self._tlp_marking.get("id")],
            created_by_ref=self._author.get("id"),
            external_references=external_references,
            custom_properties={
                "x_opencti_files": [report_pdf_binary] if report_pdf_binary else []
            },
        )

    def make_sector(
        self,
        sector,
    ):
        return stix2.Identity(
            id=pycti.Identity.generate_id(identity_class="class", name=sector),
            name=sector,
            identity_class="class",
            object_marking_refs=[self._tlp_marking.get("id")],
        )
