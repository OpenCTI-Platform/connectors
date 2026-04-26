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
from ransomwarelive.utils import get_group_entry, threat_description_generator


class ConverterToStix:  # pylint: disable=too-many-public-methods
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, create_leak_site_domains: bool = True) -> None:
        self.marking = stix2.TLP_WHITE
        self.author = self.create_author()
        self.create_leak_site_domains = create_leak_site_domains

    def create_author(self) -> dict:
        """
        Create STIX 2.1 Identity object representing the author of STIX objects

        Return:
            Author Identity in STIX 2.1 format
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

    def create_domain(self, domain_name: str) -> stix2.DomainName:
        """
        Create a STIX object for a domain
        Params:
            domain_name: name of the domain in string
        Return:
            DomainName in STIX 2.1 format
        """
        domain = stix2.DomainName(
            value=domain_name,
            type="domain-name",
            object_marking_refs=[self.marking.get("id")],
            custom_properties={
                "x_opencti_created_by_ref": self.author.get("id"),
            },
        )
        return domain

    def create_external_reference(
        self, url: str, description: str
    ) -> stix2.ExternalReference:
        """
        Create a STIX object for an ExternalReference

        Params:
            url: url of the external refenrence in string
            description: description of the external reference in string
        Return:
            ExternalReference in STIX 2.1 format
        """
        external_reference = stix2.ExternalReference(
            source_name="ransomware.live",
            url=url,
            description=description,
        )
        return external_reference

    def create_identity(self, victim_name: str, identity_class: str) -> stix2.Identity:
        """
        Create a STIX object for an Identity

        Params:
            victim_name: victim name in string
            identity_class: "organization" or "individual" string
        Return:
            Identity in STIX 2.1 format
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

    def create_ipv4(self, ip: str) -> stix2.IPv4Address:
        """
        Create STIX 2.1 IPv4 Address object

        Param:
            ip: ip in string
        Return:
            IPv4 Address in STIX 2.1 format
        """
        return stix2.IPv4Address(
            value=ip,
            type="ipv4-addr",
            object_marking_refs=[self.marking.get("id")],
            created_by_ref=self.author.get("id"),
            allow_custom=True,
        )

    def create_ipv6(self, ip: str) -> stix2.IPv6Address:
        """
        Create STIX 2.1 IPv6 Address object

        Param:
            ip: ip in string
        Return:
            IPv6 Address in STIX 2.1 format
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
        aliases: list[str] | None = None,
        external_references: list | None = None,
    ) -> stix2.IntrusionSet:
        """
        Create STIX 2.1 IntrusionSet object

        Params:
            name: name of the intrusion in string
            intrusion_description: description in string
            aliases: optional list of alternative names
            external_references: optional list of stix2 ExternalReference objects
        Return:
            IntrusionSet in STIX 2.1 format
        """
        intrusionset = stix2.IntrusionSet(
            id=IntrusionSet.generate_id(name),
            name=name,
            labels=["ransomware"],
            created_by_ref=self.author.get("id"),
            description=intrusion_description,
            object_marking_refs=[self.marking.get("id")],
            aliases=aliases or None,
            external_references=external_references or None,
        )
        return intrusionset

    def create_country(self, country_name: str) -> stix2.Location:
        """
        Create STIX 2.1 Location (country) object with connectors_sdk

        Params:
            country_name: name of in string
        Return:
            Location in STIX 2.1 format
        """
        location = stix2.Location(
            id=Location.generate_id(country_name, "Country"),
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

        Params:
            source_ref: source id in string
            target_ref: target id in string
            relationship_type: relation type in string
            start_time: attack start date in datetime (optional)
            created: discovered date in datetime (optional)
        Return:
            Relationship in STIX 2.1 format
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
    ) -> stix2.Report:
        """
        Create STIX2.1 Report object

        Params:
            name: name of report in string
            attack_date_iso: attack date in datetime
            description: description in string
            object_refs: list of ids (victim, instrusionset, relationship victim-intrusionset.
                        Optional: target_relation and relation_intrusion_threat_actor ids)
            discovered_iso: discovered datetime
            external_references: list of STIX2.1 ExternalReference
        Return:
            Report in STIX 2.1 format
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

    def create_sector(self, name: str) -> stix2.Identity:
        """
        Create STIX2.1 Sector object

        Params:
            name: name of sector in string
        Return:
            Sector in STIX 2.1 format
        """
        sector = stix2.Identity(
            id=Identity.generate_id(name=name, identity_class="class"),
            name=name,
            identity_class="class",
            object_marking_refs=[self.marking.get("id")],
            allow_custom=True,
        )
        return sector

    def create_threat_actor(
        self,
        threat_actor_name: str,
        threat_description: str,
        aliases: list[str] | None = None,
        external_references: list | None = None,
    ) -> stix2.ThreatActor:
        """
        Create STIX2.1 ThreatActor object

        Params:
            threat_actor_name: name of threat actor in string
            threat_description: description in string
            aliases: optional list of alternative names
            external_references: optional list of stix2 ExternalReference objects
        Return:
            ThreatActor in STIX 2.1 format
        """
        threat_actor = stix2.ThreatActor(
            id=ThreatActorGroup.generate_id(threat_actor_name),
            name=threat_actor_name,
            labels=["ransomware"],
            created_by_ref=self.author.get("id"),
            description=threat_description,
            object_marking_refs=[self.marking.get("id")],
            aliases=aliases or None,
            external_references=external_references or None,
        )
        return threat_actor

    def _extract_group_aliases(self, group_entry: dict | None) -> list[str] | None:
        """Return [altname] if group_entry has a non-empty altname, else None."""
        if not group_entry:
            return None
        altname = group_entry.get("altname")
        if altname and str(altname).strip():
            return [str(altname).strip()]
        return None

    def _extract_group_aliases_and_refs(
        self, group_entry: dict | None
    ) -> tuple[list[str] | None, list | None]:
        """
        Extract aliases and external references from a group entry.
        Location slug URLs are only included when self.create_leak_site_domains is True.

        Returns:
            (aliases, external_references) both may be None
        """
        aliases = self._extract_group_aliases(group_entry)

        if not group_entry:
            return aliases, None

        ext_refs = []
        seen_urls: set[str] = set()

        group_url = group_entry.get("url")
        if group_url and group_url not in seen_urls:
            seen_urls.add(group_url)
            ext_refs.append(
                self.create_external_reference(
                    url=group_url,
                    description="ransomware.live group profile page",
                )
            )

        if self.create_leak_site_domains:
            for loc in group_entry.get("locations") or []:
                slug = loc.get("slug")
                if slug and slug not in seen_urls:
                    seen_urls.add(slug)
                    title = loc.get("title") or "Leak site"
                    ext_refs.append(
                        self.create_external_reference(
                            url=slug,
                            description=f"Leak site: {title}",
                        )
                    )

        return aliases, ext_refs or None

    def process_group_leak_sites(
        self,
        group_entry: dict,
        intrusion_set: stix2.IntrusionSet,
    ) -> list:
        """
        Create DomainName observables and related-to relationships for each leak site
        listed in the group entry's locations.

        Params:
            group_entry (dict): single group entry from /v2/groups API
            intrusion_set (stix2.IntrusionSet): the group's IntrusionSet object
        Returns:
            list of stix2 objects (domain + relationship pairs)
        """
        objects = []
        for loc in group_entry.get("locations") or []:
            fqdn = loc.get("fqdn")
            if not fqdn or not str(fqdn).strip():
                continue
            domain = self.create_domain(domain_name=fqdn.strip())
            relation = self.create_relationship(
                source_ref=domain.get("id"),
                target_ref=intrusion_set.get("id"),
                relationship_type="related-to",
            )
            objects.append(domain)
            objects.append(relation)
        return objects

    def process_domain(
        self, domain_name: str, victim: stix2.Identity
    ) -> tuple[stix2.DomainName, stix2.Relationship]:
        """
        Process domain to stix2 and create stix2 relationship linked

        Params:
            domain_name (str): name of the domain
            victim (Identity): stix2 Identity object of victim
        Returns:
            domain: stix2 Domain object
            relation_victim_domain: stix2 Relationship between victim and domain
        """
        domain = self.create_domain(domain_name=domain_name)

        relation_victim_domain = self.create_relationship(
            domain.get("id"), victim.get("id"), "belongs-to"
        )

        return domain, relation_victim_domain

    def process_external_references(
        self, item: dict, create_leak_post_refs: bool = True
    ) -> list:
        """
        Process external references to stix2

        Params:
            item (dict): dict of data from api call
            create_leak_post_refs (bool): whether to include the leak post URL
        Returns:
            external_references: stix2 ExternalReference object
        """
        external_references = []

        field_descriptions = {
            "url": "Ransomware.live victim page",
            "screenshot": "Screenshot of the ransomware group's post",
        }
        if create_leak_post_refs:
            field_descriptions["claim_url"] = (
                "Ransomware group's post on their leak site"
            )

        for field, description in field_descriptions.items():
            if item.get(field):
                external_references.append(
                    self.create_external_reference(
                        url=item[field],
                        description=description,
                    )
                )

        return external_references

    def process_intrusion_set(
        self,
        intrusion_set_name: str,
        group_data: dict,
        group_name_lockbit: str,
        victim: stix2.Identity,
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
    ) -> tuple[stix2.IntrusionSet, stix2.Relationship]:
        """
        Process intrusion set to stix2 and create stix2 relationship linked

        Params:
            intrusion_set_name (str): name of the intrusion set
            group_data (dict): result from ransomware api /group
            group_name_lockbit (str): group name if intrusionset is lockbit type
            victim (Identity): stix2 Identity of the victim
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime
        Returns:
            intrusion_set: stix2 IntrusionSet object
            relation_victim_intrusion: stix2 Relationship between victim and intrusionset
        """
        if intrusion_set_name in ["lockbit3", "lockbit2"]:
            intrusion_description = threat_description_generator(
                group_name_lockbit, group_data
            )
            group_entry = get_group_entry(intrusion_set_name, group_data)
            aliases, ext_refs = self._extract_group_aliases_and_refs(group_entry)
            intrusion_set = self.create_intrusionset(
                name="lockbit",
                intrusion_description=intrusion_description,
                aliases=aliases,
                external_references=ext_refs,
            )

        else:
            intrusion_description = threat_description_generator(
                intrusion_set_name, group_data
            )
            group_entry = get_group_entry(intrusion_set_name, group_data)
            aliases, ext_refs = self._extract_group_aliases_and_refs(group_entry)
            # Warning: IntrusionSet can have a name like "J".
            # No error from Stix2 but in OCTI name must be at least 2 characters
            intrusion_set = self.create_intrusionset(
                name=intrusion_set_name,
                intrusion_description=intrusion_description,
                aliases=aliases,
                external_references=ext_refs,
            )

        relation_victim_intrusion = self.create_relationship(
            source_ref=intrusion_set.get("id"),
            target_ref=victim.get("id"),
            relationship_type="targets",
            start_time=attack_date_iso,
            created=discovered_iso,
        )
        return intrusion_set, relation_victim_intrusion

    def process_location(
        self,
        location: stix2.Location,
        victim: stix2.Identity,
        intrusion_set: stix2.IntrusionSet,
        create_threat_actor: bool,
        threat_actor: stix2.ThreatActor = None,
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
    ) -> tuple[stix2.Relationship, stix2.Relationship, stix2.Relationship | None]:
        """
        Process location to stix2 and create stix2 relationship linked

        Params:
            country_name (str): name of the country
            victim (Identity): stix2 Identity of the victim
            intrusion_set (IntrusionSet): stix2 IntrusionSet object
            create_threat_actor (bool): env variable to create a Threat Actor object
            threat_actor (ThreatActor): stix2 ThreatActor object
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime
        Returns:
            location: stix2 Location object
            location_relation: stix2 Relationship between location and victim
            relation_intrusion_location: stix2 Relationship between location and intrusionset
            relation_threat_actor_location: stix2 Relationship between location and threatactor
        """
        location_relation = self.create_relationship(
            source_ref=victim.get("id"),
            target_ref=location.get("id"),
            relationship_type="located-at",
        )

        relation_intrusion_location = self.create_relationship(
            source_ref=intrusion_set.get("id"),
            target_ref=location.get("id"),
            relationship_type="targets",
            start_time=attack_date_iso,
            created=discovered_iso,
        )

        relation_threat_actor_location = None
        if create_threat_actor:
            relation_threat_actor_location = self.create_relationship(
                source_ref=threat_actor.get("id"),
                target_ref=location.get("id"),
                relationship_type="targets",
                start_time=attack_date_iso,
                created=discovered_iso,
            )
        return (
            location_relation,
            relation_intrusion_location,
            relation_threat_actor_location,
        )

    def process_report(
        self,
        report_name: str,
        victim_name: str,
        description: str,
        object_refs: list[str],
        external_references: list[stix2.ExternalReference],
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
    ) -> stix2.Report:
        """
        Process Report to stix2

        Params:
            report_name (str): name of the report
            victim_name (str): name of the victim
            description (str): description of the report
            object_refs (list[str]): list of ids (victim, instrusionset, relationship victim-intrusionset.
                                    Optional: target_relation and relation_intrusion_threat_actor ids)
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime
            external_references (list[ExternalReference]): list of stix2 ExternalReference objects
        Returns:
            report: stix2 Report object
        """
        report_name = report_name + " has published a new victim: " + victim_name
        report = self.create_report(
            name=report_name,
            attack_date_iso=attack_date_iso,
            description=description,
            object_refs=object_refs,
            discovered_iso=discovered_iso,
            external_references=external_references,
        )
        return report

    def process_sector(
        self,
        sector: stix2.Identity,
        victim: stix2.Identity,
        create_threat_actor: bool,
        intrusion_set: stix2.IntrusionSet,
        threat_actor: stix2.ThreatActor = None,
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
    ) -> tuple[stix2.Relationship, stix2.Relationship | None, stix2.Relationship]:
        """
        Create stix2 relationship linked to the given sector

        Params:
            sector_name (str): name of sector to create
            victim (Identity): stix2 Identity object of victim
            create_threat_actor (bool): env variable to create a Threat Actor object
            intrusion_set (IntrusionSet): stix2 IntrusionSet object
            threat_actor (ThreatActor): stix2 ThreatActor object or None
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime
        Returns:
            relation_sector_victim: stix2 Relationship between sector and victim
            relation_sector_threat_actor: stix2 Relationship between sector and threatactor or None
            relation_intrusion_sector: stix2 Relationship between sector and intrusionset
        """
        relation_sector_victim = self.create_relationship(
            source_ref=victim.get("id"),
            target_ref=sector.get("id"),
            relationship_type="part-of",
        )

        relation_sector_threat_actor = None
        if create_threat_actor:
            relation_sector_threat_actor = self.create_relationship(
                source_ref=threat_actor.get("id"),
                target_ref=sector.get("id"),
                relationship_type="targets",
                start_time=attack_date_iso,
                created=discovered_iso,
            )

        relation_intrusion_sector = self.create_relationship(
            intrusion_set.get("id"),
            sector.get("id"),
            "targets",
            attack_date_iso,
            discovered_iso,
        )

        return (
            relation_sector_victim,
            relation_sector_threat_actor,
            relation_intrusion_sector,
        )

    def process_threat_actor(
        self,
        threat_actor_name: str,
        group_data: dict,
        victim: stix2.Identity,
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
    ) -> tuple[stix2.ThreatActor, stix2.Relationship]:
        """
        Process threat actor to stix2 and create stix2 relationship linked

        Params:
            threat_actor_name (str): name of the domain
            group_data (dict): result from ransomware api /group
            victim (Identity): stix2 Identity object of victim
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime

        Returns:
            threat_actor: stix2 TreatActor object
            target_relation: stix2 Relationship between threatactor and victim
        """
        threat_description = threat_description_generator(threat_actor_name, group_data)
        group_entry = get_group_entry(threat_actor_name, group_data)
        aliases, ext_refs = self._extract_group_aliases_and_refs(group_entry)
        threat_actor = self.create_threat_actor(
            threat_actor_name=threat_actor_name,
            threat_description=threat_description,
            aliases=aliases,
            external_references=ext_refs,
        )

        target_relation = self.create_relationship(
            source_ref=threat_actor.get("id"),
            target_ref=victim.get("id"),
            relationship_type="targets",
            start_time=attack_date_iso,
            created=discovered_iso,
        )
        return threat_actor, target_relation

    def process_victim(self, victim_name: str) -> stix2.Identity:
        """
        Process victim to stix2

        Params:
            victim_name (str): name of the victim
        Returns:
            domain: stix2 Identity object
        """
        victim_name, identity_class = (
            (victim_name, "organization")
            if len(victim_name) > 2
            else ((victim_name + ":<)"), "individual")
        )
        victim = self.create_identity(
            victim_name=victim_name, identity_class=identity_class
        )
        return victim
