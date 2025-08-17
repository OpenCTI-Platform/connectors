import base64
from datetime import datetime

import stix2
from dateparser import parse
from flashpoint_client.models import CompromisedCredentialSighting
from pycti import (
    AttackPattern,
    Channel,
    CustomObjectChannel,
    CustomObservableMediaContent,
    Identity,
    Incident,
    IntrusionSet,
    Location,
    Malware,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    ThreatActorGroup,
    ThreatActorIndividual,
    Tool,
)

from .utils import is_domain, is_ipv4, is_ipv6


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.author_id = self._create_author()
        self.marking = stix2.MarkingDefinition(
            id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
            definition_type="statement",
            definition={"statement": "custom"},
            allow_custom=True,
            custom_properties={
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": "TLP:AMBER+STRICT",
            },
        )

    def _create_author(self) -> dict:
        """
        Create Author
        :return: Author ID
        """
        identity = self.helper.api.identity.create(
            type="Organization",
            name="Flashpoint",
            description="Flashpoint is a data and intelligence company that empowers our customers to take rapid, "
            "decisive action to stop threats and reduce risk.",
        )
        return identity["standard_id"]

    def create_relation(
        self, source_id: str, target_id: str, relation: str
    ) -> stix2.Relationship | None:
        """
        :param source_id:
        :param target_id:
        :param relation:
        :return:
        """
        try:
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(relation, source_id, target_id),
                relationship_type=relation,
                created_by_ref=self.author_id,
                source_ref=source_id,
                target_ref=target_id,
                object_marking_refs=[self.marking.get("id")],
                allow_custom=True,
            )
            return relationship
        except Exception as ex:
            message = f"An error occurred while creating relation: {source_id} {relation} {target_id}, error: {ex}"
            self.helper.connector_logger.error(message)
            return None

    def _guess_knowledge_graph(self, tags, guess_relationships_from_reports):
        """
        :param tags:
        :return:
        """
        report_objects = []
        elements = {
            "threat_actors": [],
            "intrusion_sets": [],
            "malwares": [],
            "tools": [],
            "attack_patterns": [],
            "sectors": [],
            "countries": [],
            "regions": [],
        }
        for tag in tags:
            if len(tag) > 0:
                resolved_elements = self.helper.api.stix_domain_object.list(
                    types=[
                        "Threat-Actor-Group",
                        "Threat-Actor-Individual",
                        "Intrusion-Set",
                        "Campaign",
                        "Malware",
                        "Tool",
                        "Attack-Pattern",
                        "Country",
                        "Region",
                        "Sector",
                    ],
                    filters={
                        "mode": "and",
                        "filters": [{"key": ["name", "x_mitre_id"], "values": [tag]}],
                        "filterGroups": [],
                    },
                )
                if len(resolved_elements) > 0:
                    resolved_element = resolved_elements[0]
                    if resolved_element["entity_type"] == "Threat-Actor-Group":
                        elements["threat_actors"].append(
                            stix2.ThreatActor(
                                id=ThreatActorGroup.generate_id(
                                    resolved_element["name"]
                                ),
                                name=resolved_element["name"],
                                allow_custom=True,
                            )
                        )
                    if resolved_element["entity_type"] == "Threat-Actor-Individual":
                        elements["threat_actors"].append(
                            stix2.ThreatActor(
                                id=ThreatActorIndividual.generate_id(
                                    resolved_element["name"]
                                ),
                                name=resolved_element["name"],
                                resource_level="individual",
                                allow_custom=True,
                            )
                        )
                    if resolved_element["entity_type"] == "Intrusion-Set":
                        elements["intrusion_sets"].append(
                            stix2.IntrusionSet(
                                id=IntrusionSet.generate_id(resolved_element["name"]),
                                name=resolved_element["name"],
                                allow_custom=True,
                            )
                        )
                    if resolved_element["entity_type"] == "Malware":
                        elements["malwares"].append(
                            stix2.Malware(
                                id=Malware.generate_id(resolved_element["name"]),
                                name=resolved_element["name"],
                                is_family=True,
                                allow_custom=True,
                            )
                        )
                    if resolved_element["entity_type"] == "Tool":
                        elements["tools"].append(
                            stix2.Tool(
                                id=Tool.generate_id(resolved_element["name"]),
                                name=resolved_element["name"],
                                allow_custom=True,
                            )
                        )
                    if resolved_element["entity_type"] == "Attack-Pattern":
                        elements["attack_patterns"].append(
                            stix2.AttackPattern(
                                id=AttackPattern.generate_id(resolved_element["name"]),
                                name=resolved_element["name"],
                                allow_custom=True,
                            )
                        )
                    if resolved_element["entity_type"] == "Country":
                        elements["countries"].append(
                            stix2.Location(
                                id=Location.generate_id(
                                    resolved_element["name"], "Country"
                                ),
                                name=resolved_element["name"],
                                country=resolved_element["name"],
                                allow_custom=True,
                                custom_properties={
                                    "x_opencti_location_type": "Country"
                                },
                            )
                        )
                    if resolved_element["entity_type"] == "Region":
                        elements["regions"].append(
                            stix2.Location(
                                id=Location.generate_id(
                                    resolved_element["name"], "Region"
                                ),
                                name=resolved_element["name"],
                                region=resolved_element["name"],
                                custom_properties={"x_opencti_location_type": "Region"},
                                allow_custom=True,
                            )
                        )
                    if resolved_element["entity_type"] == "Sector":
                        elements["sectors"].append(
                            stix2.Identity(
                                id=Identity.generate_id(
                                    resolved_element["name"], "class"
                                ),
                                name=resolved_element["name"],
                                identity_class="class",
                                allow_custom=True,
                            )
                        )
                if guess_relationships_from_reports:
                    for attack_pattern in elements["attack_patterns"]:
                        threats = (
                            elements["threat_actors"]
                            + elements["intrusion_sets"]
                            + elements["malwares"]
                        )
                        for threat in threats:
                            relationship_uses = self.create_relation(
                                source_id=threat.id,
                                target_id=attack_pattern.id,
                                relation="uses",
                            )
                            report_objects.append(relationship_uses)

                    for malware in elements["malwares"]:
                        threats = elements["threat_actors"] + elements["intrusion_sets"]
                        for threat in threats:
                            relationship_uses = self.create_relation(
                                source_id=threat.id,
                                target_id=malware.id,
                                relation="uses",
                            )
                            report_objects.append(relationship_uses)

                    for tool in elements["tools"]:
                        threats = elements["threat_actors"] + elements["intrusion_sets"]
                        for threat in threats:
                            relationship_uses = self.create_relation(
                                source_id=threat.id, target_id=tool.id, relation="uses"
                            )
                            report_objects.append(relationship_uses)

                    victims = (
                        elements["regions"]
                        + elements["countries"]
                        + elements["sectors"]
                    )
                    for victim in victims:
                        threats = (
                            elements["threat_actors"]
                            + elements["intrusion_sets"]
                            + elements["malwares"]
                        )
                        for threat in threats:
                            relationship_uses = self.create_relation(
                                source_id=threat.id,
                                target_id=victim.id,
                                relation="targets",
                            )
                            report_objects.append(relationship_uses)
                report_objects = (
                    report_objects
                    + elements["regions"]
                    + elements["countries"]
                    + elements["sectors"]
                    + elements["threat_actors"]
                    + elements["intrusion_sets"]
                    + elements["tools"]
                    + elements["malwares"]
                    + elements["attack_patterns"]
                )
        return report_objects

    def convert_flashpoint_report(self, report, guess_relationships_from_reports):
        """
        :param report:
        :return:
        """
        objects = [self.marking]
        # Try to resolve
        tags = report["tags"]
        actors = report["actors"]
        report_objects = self._guess_knowledge_graph(
            tags + actors, guess_relationships_from_reports
        )
        object_refs = []
        for report_object in report_objects:
            objects.append(report_object)
            object_refs.append(report_object.id)

        stix_external_reference = stix2.ExternalReference(
            source_name="Flashpoint", url=report.get("platform_url")
        )

        # Report in STIX lib must have at least one object_refs
        if len(object_refs) == 0:
            # Put a fake ID in the report
            object_refs.append("intrusion-set--fc5ee88d-7987-4c00-991e-a863e9aa8a0e")

        stix_report = stix2.Report(
            id=Report.generate_id(report["title"], report["posted_at"]),
            name=report["title"],
            report_types=["threat-report"],
            published=parse(report["posted_at"]),
            description=report["summary"],
            external_references=[stix_external_reference],
            labels=report["tags"],
            created_by_ref=self.author_id,
            object_marking_refs=[self.marking.get("id")],
            object_refs=object_refs,
            custom_properties={"x_opencti_content": report["body"].encode("utf-8")},
            allow_custom=True,
        )
        objects.append(stix_report)
        return objects

    @staticmethod
    def create_channel(channel_name, channel_aliases, channel_type, channel_ref):
        """
        :param channel_name:
        :param channel_aliases:
        :param channel_type:
        :param channel_ref:
        :return:
        """
        formatted_channel_name = "[" + channel_type + "] - " + channel_name
        external_refs = []
        if channel_ref:
            external_ref = stix2.ExternalReference(
                source_name=channel_type + " - " + channel_name, url=channel_ref
            )
            external_refs.append(external_ref)
        channel = CustomObjectChannel(
            id=Channel.generate_id(name=formatted_channel_name),
            name=formatted_channel_name,
            aliases=channel_aliases,
            channel_types=[channel_type],
            external_references=external_refs,
        )
        return channel

    @staticmethod
    def _generate_incident_name(alert: dict) -> str:
        """
        Create a STIX Incident's name from Flashpoint alert.
        :param alert: A Flashpoint alert
        :return: Incident's name
        """
        name = (
            "Alert: "
            + alert.get("alert_reason")
            + " - "
            + alert.get("channel_type")
            + " - "
            + alert.get("channel_name")
            + " - "
            + alert.get("alert_id")
        )
        return name

    @staticmethod
    def _generate_incident_description(alert: dict) -> str:
        """
        Create a STIX Incident's description from Flashpoint alert.
        :param alert: A Flashpoint alert
        :return: Incident's description
        """
        description = (
            f"A potential data exposure has been detected in **{alert.get('channel_type')}**. "
            f"The alert was triggered on "
            f"**{parse(alert.get('created_at')).strftime('%B %d, %Y, at %I:%M %p UTC')}** "
            f"by the rule **{alert.get('alert_reason').strip()}**. "
            f"For more details about this alert, please consult the Content tab."
        )
        return description

    @staticmethod
    def _convert_alert_to_markdown_content(alert: dict) -> str:
        """
        Create a markdown content representing an Alert from Flashpoint.
        :param alert: A Flashpoint alert to convert into markdown
        :return: Markdown as string
        """
        markdown_content = (
            "### Metadata"
            f"- **Alert Id**: {alert.get('alert_id')}  \n"
            f"- **Created**: {alert.get('created_at')}  \n"
            f"- **Site**: {alert.get('channel_type')}  \n"
            f"- **Title**: {alert.get('channel_name')}  \n"
            f"- **Author**: {alert.get('author')}  \n"
            f"- **Status**: {alert.get('alert_status')}  \n"
            f"- **Source**: {alert.get('alert_source')}  \n"
            f"- **Reason**: {alert.get('alert_reason')}  \n"
            f"- **Flashpoint or Code repository URL**: {alert.get('flashpoint_url')}  \n"
            "  \n"
            "### Post"
            "```"
            f"{alert.get('highlight_text')}  \n"
            "```"
        )

        if alert.get("media_content"):
            markdown_content += (
                "### Media"
                f"A media attachment ({alert.get('media_name')}) is available in Data section"
            )
        return markdown_content

    @staticmethod
    def _convert_ccm_alert_to_markdown_content(
        alert: CompromisedCredentialSighting,
    ) -> str:
        """
        Create a markdown content representing a CCM Alert from Flashpoint.
        :param alert: A Flashpoint CCM Alert to convert into markdown
        :return: Markdown as string
        """
        markdown_content = (
            "### Credential"
            f"- **Username**: {alert.username}  \n"
            f"- **Password**: {alert.password}  \n"
            f"- **Domain**: {alert.domain or '-'}  \n"
            f"- **Affected Domain**: {alert.affected_domain or '-'}  \n"
            f"- **Affected Url**: {alert.affected_url or '-'}  \n"
            "  \n"
            "### Password Complexity"
            f"- **Length**: {alert.password_complexity.length or '-'}  \n"
            f"- **Lowercase Letter**: {alert.password_complexity.has_lowercase or '-'}  \n"
            f"- **Uppercase Letter**: {alert.password_complexity.has_uppercase or '-'}  \n"
            f"- **Number**: {alert.password_complexity.has_number or '-'}  \n"
            f"- **Symbol**: {alert.password_complexity.has_symbol or '-'}  \n"
            "  \n"
            "### Breach"
            f"- **Title**: {alert.breach.title or '-'}  \n"
            f"- **Sourced From**: {alert.breach.source or '-'}  \n"
            f"- **Source Type**: {alert.breach.source_type or '-'}  \n"
            f"- **Breached At**: {datetime.isoformat(alert.breach.created_at, timespec='seconds') if alert.breach.created_at else '-'}  \n"
            f"- **Discovered At**: {datetime.isoformat(alert.breach.first_observed_at, timespec='seconds') if alert.breach.first_observed_at else '-'}  \n"
        )

        if alert.infected_host and alert.infected_host.malware:
            markdown_content += (
                "  \n"
                "### Infection / Malware Data"
                f"- **Malware Family**: {alert.infected_host.malware.family or '-'}  \n"
                f"- **Malware Version**: {alert.infected_host.malware.version or '-'}  \n"
            )

        return markdown_content

    def alert_to_incident(self, alert, create_related_entities):
        """
        Convert a Flashpoint communities Alert into an OpenCTI STIX incident
        :param alert:
        :param create_related_entities:
        :return:
        """
        stix_objects = [self.marking]

        # generated incident name
        incident_name = self._generate_incident_name(alert)

        # generated incident description
        incident_description = self._generate_incident_description(alert)

        # generate octi incident id
        incident_id = Incident.generate_id(
            name=incident_name, created=alert.get("created_at")
        )

        # add the origin and source as labels
        labels = [
            "rule:" + alert.get("alert_reason").lower(),
            alert.get("alert_source"),
        ]

        # generate a content based on alert useful information
        markdown_content = self._convert_alert_to_markdown_content(alert)

        # add the alert formatted content into a file attached to the incident
        files = []
        markdown_content_bytes = markdown_content.encode("utf-8")
        base64_bytes = base64.b64encode(markdown_content_bytes)
        files.append(
            {
                "name": "alert.md",
                "data": base64_bytes,
                "mime_type": "text/markdown",
                "no_trigger_import": False,
            }
        )

        # a media content is associated to the alert
        if alert.get("media_content"):
            files.append(
                {
                    "name": alert.get("media_name"),
                    "data": alert.get("media_content"),
                    "mime_type": alert.get("media_type"),
                    "no_trigger_import": False,
                }
            )

        # generated incident name
        incident_name = self._generate_incident_name(alert)

        # alert flashpoint reference
        incident_external_reference = stix2.ExternalReference(
            source_name="Flashpoint", url=alert.get("flashpoint_url")
        )

        # create the incident
        stix_incident = stix2.Incident(
            id=incident_id,
            name=incident_name,
            created=alert.get("created_at"),
            description=incident_description,
            created_by_ref=self.author_id,
            allow_custom=True,
            incident_type="alert",
            labels=labels,
            severity="low",
            object_marking_refs=[self.marking.get("id")],
            source="Flashpoint - " + alert.get("alert_source"),
            external_references=[incident_external_reference],
            custom_properties={"x_opencti_files": files},
        )
        stix_objects.append(stix_incident)

        if create_related_entities:
            # create a channel entity
            stix_channel = self.create_channel(
                alert.get("channel_name"),
                alert.get("channel_aliases"),
                alert.get("channel_type"),
                alert.get("channel_ref"),
            )
            stix_objects.append(stix_channel)

            # create relation between incident and channel
            relationship_uses = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "uses",
                    stix_incident.id,
                    stix_channel.id,
                ),
                relationship_type="uses",
                created_by_ref=self.author_id,
                source_ref=stix_incident.id,
                target_ref=stix_channel.id,
                object_marking_refs=[self.marking.get("id")],
                allow_custom=True,
            )
            stix_objects.append(relationship_uses)

            stix_media_content = CustomObservableMediaContent(
                content=alert.get("highlight_text"),
                url=alert.get("flashpoint_url"),
                publication_date=parse(alert.get("created_at")),
            )
            stix_objects.append(stix_media_content)

            # create relation between incident and channel
            relationship_uses = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    stix_media_content.id,
                    stix_incident.id,
                ),
                relationship_type="related-to",
                created_by_ref=self.author_id,
                source_ref=stix_media_content.id,
                target_ref=stix_incident.id,
                object_marking_refs=[self.marking.get("id")],
                allow_custom=True,
            )
            stix_objects.append(relationship_uses)

            # Waiting for FBI PR Persona / Monikers
            # author = CustomObservablePersona(
            #    title=community["title"],
            #    content=community["message"],
            #    url="https://app.flashpoint.io/search/context/communities/" + community["id"],
            #    publication_date=community["date"]
            # )

            relationship_publishes = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "publishes", stix_channel.id, stix_media_content.id
                ),
                relationship_type="publishes",
                created_by_ref=self.author_id,
                source_ref=stix_channel.id,
                target_ref=stix_media_content.id,
                start_time=parse(alert.get("created_at")),
                object_marking_refs=[self.marking.get("id")],
                allow_custom=True,
            )
            stix_objects.append(relationship_publishes)

        return stix_objects

    def convert_communities_search(self, data):
        """
        :param data:
        :return:
        """
        title = ""
        if "title" in data:
            title = data["title"]
        elif "message" in data:
            title = (
                (data["message"][:50] + "..")
                if len(data["message"]) > 50
                else data["message"]
            )

        start_time = (
            parse(data["first_observed_at"]) if "first_observed_at" in data else None
        )
        stop_time = (
            parse(data["last_observed_at"])
            if "last_observed_at" in data
            and parse(data["last_observed_at"]) > start_time
            else None
        )

        # Channel
        channel = CustomObjectChannel(
            id=Channel.generate_id(
                (
                    data["container_name"]
                    if "container_name" in data
                    else data["site_title"]
                )
                .replace("<x-fp-highlight>", "")
                .replace("</x-fp-highlight>", "")
            ),
            name=(
                data["container_name"]
                if "container_name" in data
                else data["site_title"]
            )
            .replace("<x-fp-highlight>", "")
            .replace("</x-fp-highlight>", ""),
            channel_types=[data["site"]],
            external_references=(
                [
                    stix2.ExternalReference(
                        source_name="URL",
                        url=data["site_source_uri"],
                    )
                ]
                if data.get("site_source_uri")
                else []
            ),
        )
        media_content = CustomObservableMediaContent(
            title=title,
            content=data["message"],
            url="https://app.flashpoint.io/search/context/communities/" + data["id"],
            publication_date=data["date"],
        )
        # Waiting for FBI PR Persona / Monikers
        # author = CustomObservablePersona(
        #    title=community["title"],
        #    content=community["message"],
        #    url="https://app.flashpoint.io/search/context/communities/" + community["id"],
        #    publication_date=community["date"]
        # )

        relationship_publishes = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "publishes", channel.id, media_content.id
            ),
            relationship_type="publishes",
            created_by_ref=self.author_id,
            source_ref=channel.id,
            target_ref=media_content.id,
            start_time=start_time,
            stop_time=stop_time,
            object_marking_refs=[stix2.TLP_GREEN.get("id")],
            allow_custom=True,
        )
        # TODO Implement personas after community merge for author

        stix_objects = [
            stix2.TLP_GREEN,
            channel,
            media_content,
            relationship_publishes,
        ]
        return stix_objects

    def convert_ccm_alert_to_incident(
        self, alert: CompromisedCredentialSighting
    ) -> list[stix2.v21._STIXBase21]:
        """
        Convert a Flashpoint CCM Alert into STIX 2.1 objects.
        :param alert: Flashpoint CCM alert to convert
        :return: List of STIX 2.1 objects
        """

        stix_objects = []

        incident_name = f"CCM Alert: {alert.username} - {alert.fpid}"
        incident_description = (
            f"A compromised credential has been detected for username:  **{alert.username}**"
            f" on affected URL: **{alert.affected_url or '_unknown_'}**.  \n"
            "The alert was triggered on "
            f"**{alert.header.indexed_at.strftime('%B %d, %Y, at %I:%M %p UTC') if alert.header.indexed_at else '_unknown date_'}**.  \n"
            "  \n"
            "For more details about this alert, please consult the Content tab.  \n"
        )
        incident_created_at = alert.breach.created_at
        incident_external_reference = stix2.ExternalReference(
            source_name="Flashpoint",
            url=f"https://app.flashpoint.io/cti/ato/credential/{alert.credential_record_fpid}::{alert.fpid}",
        )

        # Generate a markdown file gathering all Flashpoint useful information
        # and attach it as a file to the incident
        incident_markdown = self._convert_ccm_alert_to_markdown_content(alert)
        incident_markdown_file_data = {
            "name": "alert.md",
            "data": base64.b64encode(incident_markdown.encode("utf-8")),
            "mime_type": "text/markdown",
            "no_trigger_import": False,
        }

        stix_incident = stix2.Incident(
            id=Incident.generate_id(
                name=incident_name,
                created=incident_created_at,
            ),
            name=incident_name,
            created=incident_created_at,
            description=incident_description,
            labels=[alert.breach.source_type],
            external_references=[incident_external_reference],
            object_marking_refs=[self.marking],
            created_by_ref=self.author_id,
            custom_properties={
                "first_seen": incident_created_at,
                "last_seen": alert.last_observed_at,
                "source": "Flashpoint CCM",
                "incident_type": "compromised credential",
                "severity": "low",
                "x_opencti_files": [incident_markdown_file_data],
            },
        )
        stix_objects.append(stix_incident)

        related_stix_objects = []  # STIX objects extracted from CCM Alert's attributes
        if alert.email:
            stix_email = stix2.EmailAddress(
                value=alert.email,
                object_marking_refs=[self.marking],
                custom_properties={
                    "created_by_ref": self.author_id,
                },
            )
            related_stix_objects.append(stix_email)
        if alert.domain:
            stix_domain = self.convert_ccm_alert_domain(alert.domain)
            if stix_domain:
                related_stix_objects.append(stix_domain)
        if alert.affected_domain:
            stix_affected_domain = self.convert_ccm_alert_domain(alert.affected_domain)
            if stix_affected_domain:
                related_stix_objects.append(stix_affected_domain)
        if alert.affected_url:
            stix_url = stix2.URL(
                value=alert.affected_url,
                object_marking_refs=[self.marking],
                custom_properties={
                    "created_by_ref": self.author_id,
                },
            )
            related_stix_objects.append(stix_url)
        if alert.username and alert.password:
            stix_account = stix2.UserAccount(
                account_login=alert.username,
                credential=alert.password,
                object_marking_refs=[self.marking],
                custom_properties={
                    "created_by_ref": self.author_id,
                },
            )
            related_stix_objects.append(stix_account)
        if alert.infected_host and alert.infected_host.malware:
            malware_family = alert.infected_host.malware.family
            if malware_family:
                stix_malware = stix2.Malware(
                    id=Malware.generate_id(malware_family),
                    name=malware_family,
                    is_family=True,
                    object_marking_refs=[self.marking],
                    created_by_ref=self.author_id,
                )
                related_stix_objects.append(stix_malware)

        for related_stix_object in related_stix_objects:
            related_to_relationship = self.create_relation(
                source_id=related_stix_object.id,
                target_id=stix_incident.id,
                relation="related-to",
            )
            # self.create_relation currently handle exception internally and return None in case of error
            # Exceptions should probably be handled in FlashpointConnector class in the future
            if related_to_relationship:
                stix_objects.append(related_stix_object)
                stix_objects.append(related_to_relationship)

        # Add self.marking to ensure a consistent bundle.
        # Author is directly created through OpenCTI API in self.create_author()
        stix_objects = [self.marking] + stix_objects

        return stix_objects

    def convert_ccm_alert_domain(
        self, value: str
    ) -> stix2.DomainName | stix2.IPv4Address | stix2.IPv6Address | None:
        """
        Convert a CCM Alert's domain or affected domain to its counterpart STIX observable.
        CCM Alert's domain represents the domain of the user email.
        CCM Alert's affected domain represents the domain of the website the credentials have leaked from.
        :param value: Domain value
        :return: Corresponding STIX Observable (DomainName, IPv4Address or IPv6Address)
        """
        stix_affected_domain = None
        if is_domain(value):
            stix_affected_domain = stix2.DomainName(
                value=value,
                object_marking_refs=[self.marking],
                custom_properties={
                    "created_by_ref": self.author_id,
                },
            )
        elif is_ipv4(value):
            stix_affected_domain = stix2.IPv4Address(
                value=value,
                object_marking_refs=[self.marking],
                custom_properties={
                    "created_by_ref": self.author_id,
                },
            )
        elif is_ipv6(value):
            stix_affected_domain = stix2.IPv6Address(
                value=value,
                object_marking_refs=[self.marking],
                custom_properties={
                    "created_by_ref": self.author_id,
                },
            )
        else:
            self.helper.connector_logger.warning(
                f"Unable to convert 'domain' or 'affected_domain' value to a STIX observable, value: {value}"
            )

        return stix_affected_domain
