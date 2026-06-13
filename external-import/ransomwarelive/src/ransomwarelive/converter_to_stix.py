from datetime import datetime

import stix2
from pycti import (
    Campaign,
    Identity,
    IntrusionSet,
    Location,
    MarkingDefinition,
    Report,
    StixCoreRelationship,
    ThreatActorGroup,
)
from ransomwarelive.utils import get_group_entry, threat_description_generator


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, marking_value: str, create_leak_site_domains: bool = False):
        # Defaults to ``False`` so leak-site URL/domain enrichment is opt-in:
        # this mirrors the ``CONNECTOR_CREATE_LEAK_SITE_DOMAINS`` config default
        # and fails closed for the compliance-sensitive behaviour, so any call
        # site that forgets to pass the flag does not silently emit leak-site
        # links. The connector always passes the configured value explicitly.
        self.marking = self.load_marking_definition(marking_value)
        self.author = self.create_author()
        self.create_leak_site_domains = create_leak_site_domains

    def load_marking_definition(self, marking_value: str) -> stix2.MarkingDefinition:
        """Return the ``stix2.MarkingDefinition`` for ``marking_value``.

        ``TLP:CLEAR`` is intentionally NOT aliased to ``stix2.TLP_WHITE``.
        ``TLP:CLEAR`` is an OpenCTI-specific marking and the platform
        renders the modern label only when the bundle carries a
        ``MarkingDefinition`` with ``x_opencti_definition='TLP:CLEAR'``
        (built via ``pycti.MarkingDefinition.generate_id("TLP",
        "TLP:CLEAR")``). The earlier alias silently downgraded every
        indicator marked ``TLP:CLEAR`` to a ``TLP:WHITE`` display in the
        OpenCTI UI. The new shape mirrors the
        ``connectors_sdk.models.TLPMarking`` pattern used by other
        recent connectors (see PR #5193 / #5525 in this repo).
        ``TLP:AMBER+STRICT`` keeps its existing custom-marking shape for
        the same reason. ``TLP:WHITE`` / ``TLP:GREEN`` / ``TLP:AMBER`` /
        ``TLP:RED`` resolve to the canonical ``stix2.TLP_*`` constants.
        Unknown values fall back to ``TLP:CLEAR`` (the connector's safe
        default), matching the validated ``Literal`` enum on the
        connector config.
        """
        TLP_MAPPING = {
            "TLP:CLEAR": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:CLEAR",
            ),
            "TLP:WHITE": stix2.TLP_WHITE,
            "TLP:GREEN": stix2.TLP_GREEN,
            "TLP:AMBER": stix2.TLP_AMBER,
            "TLP:RED": stix2.TLP_RED,
            "TLP:AMBER+STRICT": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            ),
        }
        return TLP_MAPPING.get(marking_value, TLP_MAPPING["TLP:CLEAR"])

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
            object_marking_refs=[self.marking.id] if self.marking else [],
            contact_information="https://www.ransomware.live/about#data",
            x_opencti_reliability="A - Completely reliable",
            allow_custom=True,
        )
        return author

    def create_domain(self, domain_name: str):
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
            object_marking_refs=[self.marking.id] if self.marking else [],
            custom_properties={
                "x_opencti_created_by_ref": self.author.get("id"),
            },
        )
        return domain

    def create_external_reference(self, url: str, description: str):
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

    def create_identity(self, victim_name: str, identity_class: str):
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
            object_marking_refs=[self.marking.id] if self.marking else [],
        )
        return identity

    def create_ipv4(self, ip: str):
        """
        Create STIX 2.1 IPv4 Address object

        Param:
            ip: ip in string
        Return:
            IPv4 Address in STIX 2.1 format
        """
        # STIX 2.1 only defines ``created_by_ref`` on SDOs/SROs. For cyber
        # observables (SCOs) like ``ipv4-addr`` OpenCTI carries the author
        # via the custom property ``x_opencti_created_by_ref``; setting
        # the standard ``created_by_ref`` on the SCO would land in the
        # bundle as an arbitrary custom field and the platform would not
        # pick up the observable's author.
        return stix2.IPv4Address(
            value=ip,
            type="ipv4-addr",
            object_marking_refs=[self.marking.id] if self.marking else [],
            custom_properties={"x_opencti_created_by_ref": self.author.get("id")},
            allow_custom=True,
        )

    def create_ipv6(self, ip: str):
        """
        Create STIX 2.1 IPv6 Address object

        Param:
            ip: ip in string
        Return:
            IPv6 Address in STIX 2.1 format
        """
        # See ``create_ipv4`` for the rationale — SCO author propagation
        # goes through ``x_opencti_created_by_ref``, not ``created_by_ref``.
        return stix2.IPv6Address(
            value=ip,
            type="ipv6-addr",
            object_marking_refs=[self.marking.id] if self.marking else [],
            custom_properties={"x_opencti_created_by_ref": self.author.get("id")},
            allow_custom=True,
        )

    def create_campaign(
        self,
        name: str,
        description: str = None,
        first_seen: datetime = None,
        external_references: list = None,
    ):
        """
        Create STIX 2.1 Campaign object

        Params:
            name: name of the campaign in string
            description: optional description of the campaign in string
            first_seen: optional datetime indicating when the campaign was first observed
            external_references: optional list of external references related to the campaign
        Return:
            Campaign in STIX 2.1 format
        """

        campaign = stix2.Campaign(
            id=Campaign.generate_id(name),
            name=name,
            description=description,
            first_seen=first_seen,
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.id] if self.marking else [],
            external_references=external_references,
        )
        return campaign

    def create_intrusionset(
        self,
        name: str,
        intrusion_description: str,
        aliases: list[str] | None = None,
        external_references: list | None = None,
    ):
        """
        Create STIX 2.1 IntrusionSet object

        Params:
            name: name of the intrusion in string.
                If the name length is less than 2 characters, an extra
                space is appended to ensure a valid STIX ID can be
                generated.
            intrusion_description: description in string
            aliases: optional list of alternative names
            external_references: optional list of stix2 ExternalReference objects
        Return:
            IntrusionSet in STIX 2.1 format
        """
        if len(name.strip()) < 2:
            name = name + " "
        intrusionset = stix2.IntrusionSet(
            id=IntrusionSet.generate_id(name),
            name=name,
            labels=["ransomware"],
            resource_level="organization",
            created_by_ref=self.author.get("id"),
            description=intrusion_description,
            aliases=aliases or None,
            external_references=external_references or None,
            object_marking_refs=[self.marking.id] if self.marking else [],
        )
        return intrusionset

    def create_country(self, country_name: str):
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
            object_marking_refs=[self.marking.id] if self.marking else [],
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
            object_marking_refs=[self.marking.id] if self.marking else [],
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
            object_marking_refs=[self.marking.id] if self.marking else [],
            external_references=external_references,
        )
        return report

    def create_sector(self, name: str):
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
            object_marking_refs=[self.marking.id] if self.marking else [],
            allow_custom=True,
        )
        return sector

    def create_threat_actor(
        self,
        threat_actor_name: str,
        threat_description: str,
        aliases: list[str] | None = None,
        external_references: list | None = None,
    ):
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
            aliases=aliases or None,
            external_references=external_references or None,
            object_marking_refs=[self.marking.id] if self.marking else [],
        )
        return threat_actor

    def process_domain(self, domain_name: str, victim: stix2.Identity):
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
        self, item: dict, create_leak_post_refs: bool = False
    ):
        """
        Process external references to stix2

        Params:
            item (dict): dict of data from api call
            create_leak_post_refs (bool): whether to include the direct leak post
                URL (``post_url``) as an external reference. Defaults to ``False``
                (opt-in) to mirror the ``CONNECTOR_CREATE_LEAK_POST_REFS`` config
                default and fail closed for this compliance-sensitive behaviour;
                the connector always passes the configured value explicitly
        Returns:
            external_references: list of stix2 ExternalReference objects
                (empty list when ``item`` carries none of the expected fields)
        """
        external_references = []
        fields = ["screenshot", "website"]
        if create_leak_post_refs:
            fields.append("post_url")
        for field in fields:
            if item.get(field):
                external_reference = self.create_external_reference(
                    url=item[field],
                    description=f"This is the {field} for the ransomware campaign.",
                )
                external_references.append(external_reference)
        return external_references

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
        Create DomainName observables and related-to relationships for each leak
        site listed in the group entry's locations.

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

    def process_intrusion_set(
        self,
        intrusion_set_name: str,
        group_data: list[dict],
        group_name_lockbit: str,
        victim: stix2.Identity,
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
    ):
        """
        Process intrusion set to stix2 and create stix2 relationship linked

        Params:
            intrusion_set_name (str): name of the intrusion set
            group_data (list[dict]): result from the ransomware api ``/groups`` feed
                (list of group entries; ``RansomwareAPIClient.get_feed`` returns an
                empty list when the upstream payload is empty and raises on error,
                so callers never observe ``None`` here)
            group_name_lockbit (str): group name if intrusionset is lockbit type
            victim (Identity): stix2 Identity of the victim
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime
        Returns:
            intrusion_set: stix2 IntrusionSet object
            relation_victim_intrusion: stix2 Relationship between victim and intrusionset
        """
        if intrusion_set_name in ["lockbit3", "lockbit2"]:
            group_entry = get_group_entry(group_name_lockbit, group_data)
            aliases, ext_refs = self._extract_group_aliases_and_refs(group_entry)
            intrusion_description = threat_description_generator(
                group_name_lockbit, group_data
            )
            intrusion_set = self.create_intrusionset(
                name="lockbit",
                intrusion_description=intrusion_description,
                aliases=aliases,
                external_references=ext_refs,
            )
        else:
            group_entry = get_group_entry(intrusion_set_name, group_data)
            aliases, ext_refs = self._extract_group_aliases_and_refs(group_entry)
            intrusion_description = threat_description_generator(
                intrusion_set_name, group_data
            )
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

    def process_campaign(
        self,
        actor_name: str,
        group_data: list[dict],
        victim: stix2.Identity,
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
        description=None,
        external_references=None,
    ):
        """
        Process campaign to stix2 and create stix2 relationship linked

        Params:
            actor_name (str): Name of the ransomware group (Intrusion Set) attributed to the campaign.
            group_data (list[dict]): result from the ransomware api ``/groups`` feed
                (list of group entries; ``RansomwareAPIClient.get_feed`` returns an
                empty list when the upstream payload is empty and raises on error,
                so callers never observe ``None`` here)
            victim (Identity): stix2 Identity object of victim
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime
            description (str, optional): Custom description for the campaign. If not provided, a default description will be generated.
            external_references (list, optional): List of external references (stix2 ExternalReference objects) related to the campaign.

        Returns:
            campaign: stix2 Campaign object
            target_relation: stix2 Relationship between campaign and victim
        """

        actor_name = actor_name.strip() if actor_name else "Unknown"

        if victim and victim.get("name"):
            name = f"{actor_name} targets {victim.get('name')}"
        else:
            name = f"Ransomware Campaign by {actor_name}"

        # ``group_data[0]`` would raise ``IndexError`` whenever the
        # ransomware.live ``/groups`` feed returns an empty list, and is
        # not guaranteed to correspond to ``actor_name`` even when
        # non-empty. Look up the matching group by name first and fall
        # back to a description that does not depend on the feed entry
        # at all when no match is found — the campaign still emits with
        # a meaningful summary.
        if description is None:
            matching_group_description = ""
            if isinstance(group_data, list):
                for entry in group_data:
                    if (
                        isinstance(entry, dict)
                        and str(entry.get("name", "")).strip().lower()
                        == actor_name.lower()
                    ):
                        matching_group_description = entry.get("description", "") or ""
                        break
            if matching_group_description:
                description = (
                    f"Ransomware campaign attributed to {actor_name}. "
                    f"Description: {matching_group_description}"
                )
            else:
                description = f"Ransomware campaign attributed to {actor_name}."

        campaign = self.create_campaign(
            name=name,
            description=description,
            first_seen=attack_date_iso,
            external_references=external_references,
        )

        target_relation = self.create_relationship(
            source_ref=campaign.id,
            target_ref=victim.id,
            relationship_type="targets",
            start_time=attack_date_iso,
            created=discovered_iso,
        )
        return campaign, target_relation

    def process_location(
        self,
        location: stix2.Location,
        victim: stix2.Identity,
        intrusion_set: stix2.IntrusionSet = None,
        create_threat_actor: bool = False,
        create_intrusion_set: bool = False,
        threat_actor: stix2.ThreatActor = None,
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
    ):
        """
        Create stix2 relationships linked to the given location.

        Params:
            location (Location): already-resolved stix2 Location object
                for the country (built by ``location_fetcher`` either by
                resolving the name against OpenCTI or by falling back to
                ``create_country``)
            victim (Identity): stix2 Identity of the victim
            intrusion_set (IntrusionSet): stix2 IntrusionSet object
            create_threat_actor (bool): env variable to create a Threat Actor object
            create_intrusion_set (bool): Flag to create IntrusionSet relationship
            threat_actor (ThreatActor): stix2 ThreatActor object
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime
        Returns:
            location_relation: stix2 Relationship between victim and location
            relation_intrusion_location: stix2 Relationship between intrusionset and location, or None
            relation_threat_actor_location: stix2 Relationship between threatactor and location, or None
        """
        location_relation = self.create_relationship(
            source_ref=victim.get("id"),
            target_ref=location.get("id"),
            relationship_type="located-at",
        )

        relation_intrusion_location = None
        if create_intrusion_set and intrusion_set:
            relation_intrusion_location = self.create_relationship(
                source_ref=intrusion_set.get("id"),
                target_ref=location.get("id"),
                relationship_type="targets",
                start_time=attack_date_iso,
                created=discovered_iso,
            )

        relation_threat_actor_location = None
        if create_threat_actor and threat_actor:
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
    ):
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
        create_intrusion_set: bool = False,
        create_campaign: bool = False,
        intrusion_set: stix2.IntrusionSet = None,
        threat_actor: stix2.ThreatActor = None,
        campaign: stix2.Campaign = None,
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
    ):
        """
        Create stix2 relationships linked to the given sector.

        Params:
            sector (Identity): already-resolved stix2 Identity object for
                the sector (built by ``sector_fetcher`` either by
                resolving the name against OpenCTI or by falling back to
                ``create_sector``)
            victim (Identity): stix2 Identity object of victim
            create_threat_actor (bool): env variable to create a Threat Actor object
            create_intrusion_set (bool): Flag to create IntrusionSet relationship
            create_campaign (bool): Flag to create Campaign relationship
            intrusion_set (IntrusionSet): stix2 IntrusionSet object
            threat_actor (ThreatActor): stix2 ThreatActor object or None
            campaign (Campaign): stix2 Campaign object or None
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime
        Returns:
            relation_sector_victim: stix2 Relationship between sector and victim
            relation_sector_threat_actor: stix2 Relationship between sector and threatactor or None
            relation_intrusion_sector: stix2 Relationship between sector and intrusionset
            relation_campaign_sector: stix2 Relationship between sector and campaign
        """
        relation_sector_victim = self.create_relationship(
            source_ref=victim.get("id"),
            target_ref=sector.get("id"),
            relationship_type="part-of",
        )

        relation_sector_threat_actor = None
        if create_threat_actor and threat_actor:
            relation_sector_threat_actor = self.create_relationship(
                source_ref=threat_actor.get("id"),
                target_ref=sector.get("id"),
                relationship_type="targets",
                start_time=attack_date_iso,
                created=discovered_iso,
            )

        relation_intrusion_sector = None
        if create_intrusion_set and intrusion_set:
            relation_intrusion_sector = self.create_relationship(
                intrusion_set.get("id"),
                sector.get("id"),
                "targets",
                attack_date_iso,
                discovered_iso,
            )

        relation_campaign_sector = None
        if create_campaign and campaign:
            relation_campaign_sector = self.create_relationship(
                source_ref=campaign.get("id"),
                target_ref=sector.get("id"),
                relationship_type="targets",
                start_time=attack_date_iso,
                created=discovered_iso,
            )

        return (
            relation_sector_victim,
            relation_sector_threat_actor,
            relation_intrusion_sector,
            relation_campaign_sector,
        )

    def process_threat_actor(
        self,
        threat_actor_name: str,
        group_data: list[dict],
        victim: stix2.Identity,
        attack_date_iso: datetime = None,
        discovered_iso: datetime = None,
    ):
        """
        Process threat actor to stix2 and create stix2 relationship linked

        Params:
            threat_actor_name (str): name of the threat actor / ransomware group
            group_data (list[dict]): result from the ransomware api ``/groups`` feed
                (list of group entries; ``RansomwareAPIClient.get_feed`` returns an
                empty list when the upstream payload is empty and raises on error,
                so callers never observe ``None`` here)
            victim (Identity): stix2 Identity object of victim
            attack_date_iso (datetime): attack date in datetime
            discovered_iso (datetime): discovered datetime

        Returns:
            threat_actor: stix2 ThreatActor object
            target_relation: stix2 Relationship between threatactor and victim
        """
        group_entry = get_group_entry(threat_actor_name, group_data)
        aliases, ext_refs = self._extract_group_aliases_and_refs(group_entry)
        threat_description = threat_description_generator(threat_actor_name, group_data)
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

    def process_victim(self, victim_name):
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
