import datetime

import stix2
from pycti import (
    Identity,
    IntrusionSet,
    Location,
    Report,
    StixCoreRelationship,
    ThreatActorGroup,
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self):
        self.marking = stix2.TLP_WHITE
        self.author = self.create_author()

    def create_author(self) -> dict:
        """
        Create STIX 2.1 Identity object representing the author of STIX objects
        :return: Author Identity in STIX 2.1 format
        """
        author = stix2.Identity(
            id=Identity.generate_id(
                name="Ransomware.Live", identity_class="organization"
            ),
            name="Ransomware.Live",
            identity_class="organization",
            type="identity",
            object_marking_refs=[self.marking.get("id")],
            contact_information="https://www.ransomware.live/about#data",
            x_opencti_reliability="A - Completely reliable",
            allow_custom=True,
        )

        return author

    def create_domain(self, domain_name: str, description="-"):
        """
        Create a STIX object for a domain
        :param domain_name: name of the domain in string
        :param description: description of the domain in string or "-"
        :return: DomainName in STIX 2.1 format
        """
        domain = stix2.DomainName(
            value=domain_name,
            type="domain-name",
            object_marking_refs=[self.marking.get("id")],
            custom_properties={
                "x_opencti_description": description,
                "x_opencti_created_by_ref": self.author.get("id"),
            },
        )
        return domain

    def create_external_reference(self, url: str, description: str):
        """
        Create a STIX object for an ExternalReference
        :param url: url of the external refenrence in string
        :param description: description of the external reference in string
        :return: ExternalReference in STIX 2.1 format
        """
        external_reference = stix2.ExternalReference(
            source_name="ransomware.live",
            url=url,
            description=description,
        )
        return external_reference

    def create_identity(self, victim_name: str, identity_class: str):
        """
        Create a STIX object for an Identity
        :param victim_name: victim name in string
        :param identity_class: "organization" or "individual" string
        :return: Identity in STIX 2.1 format
        """
        identity = stix2.Identity(
            id=Identity.generate_id(victim_name, identity_class),
            name=victim_name,
            identity_class=identity_class,
            type="identity",
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.get("id")],
        )
        return identity

    def create_ipv4(self, ip: str):
        """
        Create STIX 2.1 IPv4 Address object
        :param ip: ip in string
        :return: IPv4 Address in STIX 2.1 format
        """
        return stix2.IPv4Address(
            value=ip,
            type="ipv4-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )

    def create_ipv6(self, ip: str):
        """
        Create STIX 2.1 IPv6 Address object
        :param ip: ip in string
        :return: IPv6 Address in STIX 2.1 format
        """
        return stix2.IPv6Address(
            value=ip,
            type="ipv6-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )

    def create_intrusionset(
        self,
        name: str,
        intrusion_description: str,
        ransom_note_external_reference: stix2.ExternalReference,
    ):
        """
        Create STIX 2.1 IntrusionSet object
        :param name: name of the intrusion in string
        :param intrusion_description: description in string
        :param ransom_note_external_reference: ExternalReference in STIX2.1 format
        :return: IntrusionSet in STIX 2.1 format
        """
        intrusionset = stix2.IntrusionSet(
            id=IntrusionSet.generate_id(name),
            name=name,
            labels=["ransomware"],
            created_by_ref=self.author.get("id"),
            description=intrusion_description,
            object_marking_refs=[self.marking.get("id")],
            external_references=[ransom_note_external_reference],
        )
        return intrusionset

    def create_location(self, country_stix_id: str, country_name: str):
        """
        Create STIX 2.1 Location object
        :param country_stix_id: id of the country STIX2.1 object in string
        :param country_name: description in string
        :return: Location in STIX 2.1 format
        """
        location = stix2.Location(
            id=country_stix_id or Location.generate_id(country_name, "Country"),
            name=country_name,
            country=country_name,
            type="location",
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.get("id")],
        )
        return location

    def create_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str,
        start_time: datetime = None,
        created: datetime = None,
    ) -> stix2.Relationship:
        """
        Create STIX2.1 Relationship object
        :param source_ref: source id in string
        :param target_ref: target id in string
        :param relationship_type: relation type in string
        :param start_time: attack start date in datetime (optional)
        :param created: discovered date in datetime (optional)
        :return: Relationship in STIX 2.1 format
        """
        relation = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type,
                source_ref,
                target_ref,
                start_time,
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            start_time=start_time,
            created=created,
            created_by_ref=self.author.get("id"),
        )
        return relation

    def create_report(
        self,
        name: str,
        attack_date_iso: datetime,
        description: str,
        object_refs: list[str],
        discovered_iso: datetime,
        external_references: list[stix2.ExternalReference],
    ):
        """
        Create STIX2.1 Report object
        :param name: name of report in string
        :param attack_date_iso: attack date in datetime
        :param description: description in string
        :param object_refs: list of ids (victim, instrusionset, relationship victim-intrusionset.
            Optional: target_relation and relation_intrusion_threat_actor ids)
        :param discovered_iso: discovered datetime
        :param external_references: list of STIX2.1 ExternalReference
        :return: Report in STIX 2.1 format
        """
        report = stix2.Report(
            id=Report.generate_id(name, attack_date_iso),
            report_types=["Ransomware-report"],
            name=name,
            description=description,
            created_by_ref=self.author.get("id"),
            object_refs=object_refs,
            published=attack_date_iso,
            created=discovered_iso,
            object_marking_refs=[self.marking.get("id")],
            external_references=external_references,
        )
        return report

    def create_threat_actor(
        self,
        threat_actor_name: str,
        threat_description: str,
        ransom_note_external_reference: stix2.ExternalReference,
    ):
        """
        Create STIX2.1 ThreatActor object
        :param threat_actor_name: name of threat actor in string
        :param threat_description: description in string
        :param ransom_note_external_reference: STIX2.1 ExternalReference
        :return: ThreatActor in STIX 2.1 format
        """
        threat_actor = stix2.ThreatActor(
            id=ThreatActorGroup.generate_id(threat_actor_name),
            name=threat_actor_name,
            labels=["ransomware"],
            created_by_ref=self.author.get("id"),
            description=threat_description,
            object_marking_refs=[self.marking.get("id")],
            external_references=[ransom_note_external_reference],
        )
        return threat_actor
