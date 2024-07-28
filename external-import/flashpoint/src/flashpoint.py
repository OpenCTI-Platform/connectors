"""Flashpoint connector module."""

import datetime
import json
import os
import sys
import time

import html2text
import pytz
import requests
import stix2
import yaml
from dateutil.parser import parse
from mispfeed import MispFeed
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
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    ThreatActorGroup,
    ThreatActorIndividual,
    Tool,
    get_config_variable,
)


class Flashpoint:
    """Flashpoint connector."""

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.flashpoint_interval = get_config_variable(
            "FLASHPOINT_INTERVAL",
            ["flashpoint", "interval"],
            config,
            isNumber=True,
            default=5,
        )

        # Extra config
        self.flashpoint_api_key = get_config_variable(
            "FLASHPOINT_API_KEY", ["flashpoint", "api_key"], config
        )
        self.flashpoint_import_start_date = get_config_variable(
            "FLASHPOINT_IMPORT_START_DATE", ["flashpoint", "import_start_date"], config
        )
        self.flashpoint_import_apt = get_config_variable(
            "FLASHPOINT_IMPORT_APT",
            ["flashpoint", "import_apt"],
            config,
            default=False,
        )
        self.flashpoint_import_malware = get_config_variable(
            "FLASHPOINT_IMPORT_MALWARE",
            ["flashpoint", "import_malware"],
            config,
            default=False,
        )
        self.flashpoint_import_reports = get_config_variable(
            "FLASHPOINT_IMPORT_REPORTS",
            ["flashpoint", "import_reports"],
            config,
            default=True,
        )
        self.flashpoint_import_indicators = get_config_variable(
            "FLASHPOINT_IMPORT_INDICATORS",
            ["flashpoint", "import_indicators"],
            config,
            default=True,
        )
        self.flashpoint_import_vulnerabilities = get_config_variable(
            "FLASHPOINT_IMPORT_VULNERABILITIES",
            ["flashpoint", "import_vulnerabilities"],
            config,
            default=True,
        )
        self.flashpoint_import_communities = get_config_variable(
            "FLASHPOINT_IMPORT_COMMUNITIES",
            ["flashpoint", "import_communities"],
            config,
            default=False,
        )
        self.flashpoint_communities_queries = get_config_variable(
            "FLASHPOINT_COMMUNITIES_QUERIES",
            ["flashpoint", "communities_queries"],
            config,
            default="",
        ).split(",")
        self.flashpoint_import_alerts = get_config_variable(
            "FLASHPOINT_IMPORT_ALERTS",
            ["flashpoint", "import_alerts"],
            config,
            default=True,
        )
        self.flashpoint_indicators_in_reports = get_config_variable(
            "FLASHPOINT_INDICATORS_IN_REPORTS",
            ["flashpoint", "indicators_in_reports"],
            config,
            default=False,
        )

        # Init variables
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Flashpoint",
            description="Flashpoint intelligence combines data, insights, and automation to identify risks and stop threats for cyber, fraud, and physical security teams.",
        )
        self.flashpoint_api_app_url = "https://app.flashpoint.io/api/v4"
        self.flashpoint_api_url = "https://api.flashpoint.io"

    def get_interval(self):
        return int(self.flashpoint_interval) * 60

    def _guess_knowledge_graph(self, tags):
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

                for attack_pattern in elements["attack_patterns"]:
                    threats = (
                        elements["threat_actors"]
                        + elements["intrusion_sets"]
                        + elements["malwares"]
                    )
                    for threat in threats:
                        relationship_uses = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "uses", threat.id, attack_pattern.id
                            ),
                            relationship_type="uses",
                            created_by_ref=self.identity["standard_id"],
                            source_ref=threat.id,
                            target_ref=attack_pattern.id,
                            object_marking_refs=[stix2.TLP_GREEN.get("id")],
                            allow_custom=True,
                        )
                        report_objects.append(relationship_uses)
                for malware in elements["malwares"]:
                    threats = elements["threat_actors"] + elements["intrusion_sets"]
                    for threat in threats:
                        relationship_uses = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "uses", threat.id, malware.id
                            ),
                            relationship_type="uses",
                            created_by_ref=self.identity["standard_id"],
                            source_ref=threat.id,
                            target_ref=malware.id,
                            object_marking_refs=[stix2.TLP_GREEN.get("id")],
                            allow_custom=True,
                        )
                        report_objects.append(relationship_uses)
                for tool in elements["tools"]:
                    threats = elements["threat_actors"] + elements["intrusion_sets"]
                    for threat in threats:
                        relationship_uses = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "uses", threat.id, tool.id
                            ),
                            relationship_type="uses",
                            created_by_ref=self.identity["standard_id"],
                            source_ref=threat.id,
                            target_ref=tool.id,
                            object_marking_refs=[stix2.TLP_GREEN.get("id")],
                            allow_custom=True,
                        )
                        report_objects.append(relationship_uses)
                victims = (
                    elements["regions"] + elements["countries"] + elements["sectors"]
                )
                for victim in victims:
                    threats = (
                        elements["threat_actors"]
                        + elements["intrusion_sets"]
                        + elements["malwares"]
                    )
                    for threat in threats:
                        relationship_uses = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "targets", threat.id, victim.id
                            ),
                            relationship_type="targets",
                            created_by_ref=self.identity["standard_id"],
                            source_ref=threat.id,
                            target_ref=victim.id,
                            object_marking_refs=[stix2.TLP_GREEN.get("id")],
                            allow_custom=True,
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

    def _convert_to_markdown(self, content):
        text_maker = html2text.HTML2Text()
        text_maker.body_width = 0
        text_maker.ignore_links = False
        text_maker.ignore_images = False
        text_maker.ignore_tables = False
        text_maker.ignore_emphasis = False
        text_maker.skip_internal_links = False
        text_maker.inline_links = True
        text_maker.protect_links = True
        text_maker.mark_code = True
        content_md = text_maker.handle(content)
        content_md = content_md.replace("hxxps", "https")
        content_md = content_md.replace("](//", "](https://")
        return content_md

    def _import_apt(self, work_id):
        # Query params
        url = self.flashpoint_api_app_url + "/documents/apt/wiki"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.flashpoint_api_key,
        }
        response = requests.get(url, headers=headers)
        data = json.loads(response.content)
        objects = []
        try:
            if "data" in data:
                for apt in data["data"]:
                    intrusion_set_stix = stix2.IntrusionSet(
                        id=IntrusionSet.generate_id(apt["apt_group"]),
                        name=apt["apt_group"],
                        aliases=apt["aliases"],
                        description=self._convert_to_markdown(apt["body"]["raw"]),
                        created_by_ref=self.identity["standard_id"],
                        object_marking_refs=[stix2.TLP_GREEN.get("id")],
                    )
                    objects.append(intrusion_set_stix)
            self.helper.send_stix2_bundle(
                stix2.Bundle(
                    objects=objects,
                    allow_custom=True,
                ).serialize(),
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(str(e))

    def _import_malware(self, work_id):
        # Query params
        url = self.flashpoint_api_app_url + "/documents/malware/wiki"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.flashpoint_api_key,
        }
        response = requests.get(url, headers=headers)
        data = json.loads(response.content)
        objects = []
        try:
            if "data" in data:
                for malware in data["data"]:
                    malware_stix = stix2.Malware(
                        id=Malware.generate_id(malware["malware_family_name"]),
                        name=malware["malware_family_name"],
                        is_family=True,
                        aliases=malware["aliases"],
                        description=self._convert_to_markdown(malware["body"]["raw"]),
                        created_by_ref=self.identity["standard_id"],
                        object_marking_refs=[stix2.TLP_AMBER.get("id")],
                    )
                    objects.append(malware_stix)
            self.helper.send_stix2_bundle(
                stix2.Bundle(
                    objects=objects,
                    allow_custom=True,
                ).serialize(),
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(str(e))

    def _import_reports(self, work_id, start_date):
        # Query params
        url = self.flashpoint_api_url + "/finished-intelligence/v1/reports"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.flashpoint_api_key,
        }
        params = {
            "since": start_date,
            "limit": 100,
            "skip": 0,
            "sort": "updated_at:asc",
        }
        response = requests.get(url, headers=headers, params=params)
        data = json.loads(response.content)
        try:
            if "data" in data:
                skip = 0
                while len(data["data"]) > 0:
                    self.helper.log_info(
                        "Iterating over reports with skip=" + str(skip)
                    )
                    try:
                        for report in data["data"]:
                            objects = []
                            # Try to resolve
                            tags = report["tags"]
                            actors = report["actors"]
                            report_objects = self._guess_knowledge_graph(tags + actors)
                            object_refs = []
                            for report_object in report_objects:
                                objects.append(report_object)
                                object_refs.append(report_object.id)

                            stix_external_reference = stix2.ExternalReference(
                                source_name="Flashpoint",
                                url="https://app.flashpoint.io/cti/intelligence/report/"
                                + report["id"],
                            )
                            # Report in STIX lib must have at least one object_refs
                            if len(object_refs) == 0:
                                # Put a fake ID in the report
                                object_refs.append(
                                    "intrusion-set--fc5ee88d-7987-4c00-991e-a863e9aa8a0e"
                                )
                            stix_report = stix2.Report(
                                id=Report.generate_id(
                                    report["title"], report["posted_at"]
                                ),
                                name=report["title"],
                                report_types=["threat-report"],
                                published=parse(report["posted_at"]),
                                description=report["summary"],
                                external_references=[stix_external_reference],
                                labels=report["tags"],
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_AMBER.get("id")],
                                object_refs=object_refs,
                                custom_properties={
                                    "x_opencti_content": report["body"].encode("utf-8")
                                },
                                allow_custom=True,
                            )
                            objects.append(stix_report)
                            bundle = self.helper.stix2_create_bundle(objects)
                            self.helper.send_stix2_bundle(
                                bundle,
                                work_id=work_id,
                            )
                    except Exception as e:
                        self.helper.log_error(str(e))
                    skip = skip + 100
                    params = {
                        "updated_since": start_date,
                        "limit": 100,
                        "skip": skip,
                        "sort": "updated_at:asc",
                    }
                    response = requests.get(url, headers=headers, params=params)
                    data = json.loads(response.content)
        except Exception as e:
            self.helper.log_error(str(e))

    def _import_communities(self, work_id, start_date):
        # Query params
        url = self.flashpoint_api_url + "/sources/v2/communities"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer " + self.flashpoint_api_key,
        }
        for query in self.flashpoint_communities_queries:
            body_params = {
                "query": query,
                "include": {
                    "date": {"start": start_date.replace("+00:00", "Z"), "end": ""}
                },
                "size": "1000",
                "sort": {"date": "asc"},
                "page": 0,
            }
            response = requests.post(url, headers=headers, json=body_params)
            data = json.loads(response.content)
            try:
                if "items" in data:
                    page = 0
                    while "items" in data and len(data["items"]) > 0:
                        self.helper.log_info(
                            "Iterating over communities with page=" + str(page)
                        )
                        try:
                            for item in data["items"]:
                                title = ""
                                if "title" in item:
                                    title = item["title"]
                                elif "message" in item:
                                    title = (
                                        (item["message"][:50] + "..")
                                        if len(item["message"]) > 50
                                        else item["message"]
                                    )

                                start_time = (
                                    parse(item["first_observed_at"])
                                    if "first_observed_at" in item
                                    else None
                                )
                                stop_time = (
                                    parse(item["last_observed_at"])
                                    if "last_observed_at" in item
                                    and parse(item["last_observed_at"]) > start_time
                                    else None
                                )

                                # Channel
                                channel_external_reference = stix2.ExternalReference(
                                    source_name="URL", url=item["site_source_uri"]
                                )
                                channel = CustomObjectChannel(
                                    id=Channel.generate_id(
                                        (
                                            item["container_name"]
                                            if "container_name" in item
                                            else item["site_title"]
                                        )
                                        .replace("<x-fp-highlight>", "")
                                        .replace("</x-fp-highlight>", "")
                                    ),
                                    name=(
                                        item["container_name"]
                                        if "container_name" in item
                                        else item["site_title"]
                                    )
                                    .replace("<x-fp-highlight>", "")
                                    .replace("</x-fp-highlight>", ""),
                                    channel_types=[item["site"]],
                                    external_references=[channel_external_reference],
                                )
                                media_content = CustomObservableMediaContent(
                                    title=title,
                                    content=item["message"],
                                    url="https://app.flashpoint.io/search/context/communities/"
                                    + item["id"],
                                    publication_date=item["date"],
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
                                    created_by_ref=self.identity["standard_id"],
                                    source_ref=channel.id,
                                    target_ref=media_content.id,
                                    start_time=start_time,
                                    stop_time=stop_time,
                                    object_marking_refs=[stix2.TLP_GREEN.get("id")],
                                    allow_custom=True,
                                )
                                # TODO Implement personas after community merge for author

                                objects = [
                                    channel,
                                    media_content,
                                    relationship_publishes,
                                ]
                                bundle = self.helper.stix2_create_bundle(objects)
                                self.helper.send_stix2_bundle(
                                    bundle,
                                    work_id=work_id,
                                )
                        except Exception as e:
                            self.helper.log_error(str(e))
                        page = page + 1
                        body_params = {
                            "query": query,
                            "include": {"date": {"start": start_date, "end": ""}},
                            "size": "1000",
                            "sort": {"date": "asc"},
                            "page": page,
                        }
                        response = requests.post(url, headers=headers, json=body_params)
                        data = json.loads(response.content)
            except Exception as e:
                self.helper.log_error(str(e))

    def _import_alerts(self, work_id, start_date):
        # Query params
        url = self.flashpoint_api_url + "/alert-management/v1/queries"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.flashpoint_api_key,
        }
        params = {"size": 100, "from": 0}
        response = requests.get(url, headers=headers, params=params)
        data = json.loads(response.content)
        try:
            if "items" in data:
                from_iterator = 0
                while len(data["items"]) > 0:
                    self.helper.log_info(
                        "Iterating over queries with from=" + str(from_iterator)
                    )
                    try:
                        for query in data["items"]:
                            # Get only when the query is subscribed as an alert
                            if (
                                "subscriptions" in query
                                and len(query["subscriptions"]) > 0
                            ):
                                self.helper.log_info(
                                    "Get all alerts for query=" + str(query["name"])
                                )
                                for source in query["sources"]:
                                    if source == "communities":
                                        url_source = (
                                            self.flashpoint_api_url
                                            + "/sources/v2/communities"
                                        )
                                    elif source == "media":
                                        url_source = (
                                            self.flashpoint_api_url
                                            + "/sources/v2/media"
                                        )
                                    else:
                                        url_source = (
                                            self.flashpoint_api_url
                                            + "/sources/v2/markets"
                                        )
                                    headers = {
                                        "Content-Type": "application/json",
                                        "Accept": "application/json",
                                        "Authorization": "Bearer "
                                        + self.flashpoint_api_key,
                                    }
                                    include = (
                                        query["params"]["include"]
                                        if "include" in query["params"]
                                        else {}
                                    )
                                    exclude = (
                                        query["params"]["exclude"]
                                        if "exclude" in query["params"]
                                        else {}
                                    )
                                    include["date"] = {
                                        "start": start_date.replace("+00:00", "Z"),
                                        "end": "",
                                    }
                                    body_params_source = {
                                        "query": query["value"],
                                        "include": include,
                                        "exclude": exclude,
                                        "size": "1000",
                                        "sort": {"date": "asc"},
                                        "page": 0,
                                    }
                                    response_source = requests.post(
                                        url_source,
                                        headers=headers,
                                        json=body_params_source,
                                    )
                                    data_source = json.loads(response_source.content)
                                    try:
                                        if "items" in data_source:
                                            page = 0
                                            while (
                                                "items" in data_source
                                                and len(data_source["items"]) > 0
                                            ):
                                                self.helper.log_info(
                                                    "Iterating over "
                                                    + source
                                                    + " with page="
                                                    + str(page)
                                                )
                                                try:
                                                    for item in data_source["items"]:
                                                        title = ""
                                                        if "title" in item:
                                                            title = item["title"]
                                                        elif "message" in item:
                                                            title = (
                                                                (
                                                                    item["message"][:50]
                                                                    + ".."
                                                                )
                                                                if len(item["message"])
                                                                > 50
                                                                else item["message"]
                                                            )
                                                        description = ""
                                                        if "description" in item:
                                                            description = item[
                                                                "description"
                                                            ]
                                                        elif "item_description" in item:
                                                            description = item[
                                                                "item_description"
                                                            ]
                                                        message = ""
                                                        if "message" in item:
                                                            message = item["message"]
                                                        elif "media" in item:
                                                            for media in item["media"]:
                                                                message = (
                                                                    media["type"]
                                                                    + " "
                                                                    + media["mime_type"]
                                                                )
                                                        start_time = (
                                                            parse(
                                                                item[
                                                                    "first_observed_at"
                                                                ]
                                                            )
                                                            if "first_observed_at"
                                                            in item
                                                            else None
                                                        )
                                                        stop_time = (
                                                            parse(
                                                                item["last_observed_at"]
                                                            )
                                                            if "last_observed_at"
                                                            in item
                                                            and parse(
                                                                item["last_observed_at"]
                                                            )
                                                            > start_time
                                                            else None
                                                        )
                                                        # Incident
                                                        incident_external_reference = stix2.ExternalReference(
                                                            source_name="Flashpoint",
                                                            url="https://app.flashpoint.io/search/context/"
                                                            + source
                                                            + "/"
                                                            + item["id"],
                                                        )
                                                        incident = stix2.Incident(
                                                            id=Incident.generate_id(
                                                                title,
                                                                parse(item["date"]),
                                                            ),
                                                            name=title.replace(
                                                                "<x-fp-highlight>", ""
                                                            ).replace(
                                                                "</x-fp-highlight>", ""
                                                            ),
                                                            labels=[
                                                                "rule:"
                                                                + str(query["name"])
                                                            ],
                                                            incident_type="alert",
                                                            description=description.replace(
                                                                "<x-fp-highlight>", ""
                                                            ).replace(
                                                                "</x-fp-highlight>", ""
                                                            ),
                                                            created_by_ref=self.identity[
                                                                "standard_id"
                                                            ],
                                                            external_references=[
                                                                incident_external_reference
                                                            ],
                                                            created=parse(item["date"]),
                                                            modified=parse(
                                                                item["date"]
                                                            ),
                                                            first_seen=start_time,
                                                            last_seen=stop_time,
                                                            source="Flashpoint - "
                                                            + source,
                                                            severity="low",
                                                            allow_custom=True,
                                                            object_marking_refs=[
                                                                stix2.TLP_AMBER.get(
                                                                    "id"
                                                                )
                                                            ],
                                                        )
                                                        # Channel
                                                        channel_external_reference = (
                                                            stix2.ExternalReference(
                                                                source_name="URL",
                                                                url=item[
                                                                    "site_source_uri"
                                                                ],
                                                            )
                                                        )
                                                        channel = CustomObjectChannel(
                                                            name=(
                                                                item["container_name"]
                                                                if "container_name"
                                                                in item
                                                                else item["site_title"]
                                                            )
                                                            .replace(
                                                                "<x-fp-highlight>", ""
                                                            )
                                                            .replace(
                                                                "</x-fp-highlight>", ""
                                                            ),
                                                            channel_types=[
                                                                item["site"]
                                                                .replace(
                                                                    "<x-fp-highlight>",
                                                                    "",
                                                                )
                                                                .replace(
                                                                    "</x-fp-highlight>",
                                                                    "",
                                                                )
                                                            ],
                                                            external_references=[
                                                                channel_external_reference
                                                            ],
                                                        )
                                                        relationship_uses = stix2.Relationship(
                                                            id=StixCoreRelationship.generate_id(
                                                                "uses",
                                                                incident.id,
                                                                channel.id,
                                                            ),
                                                            relationship_type="uses",
                                                            created_by_ref=self.identity[
                                                                "standard_id"
                                                            ],
                                                            source_ref=incident.id,
                                                            target_ref=channel.id,
                                                            object_marking_refs=[
                                                                stix2.TLP_AMBER.get(
                                                                    "id"
                                                                )
                                                            ],
                                                            allow_custom=True,
                                                        )
                                                        media_content = CustomObservableMediaContent(
                                                            title=title.replace(
                                                                "<x-fp-highlight>", ""
                                                            ).replace(
                                                                "</x-fp-highlight>", ""
                                                            ),
                                                            content=message.replace(
                                                                "<x-fp-highlight>", ""
                                                            ).replace(
                                                                "</x-fp-highlight>", ""
                                                            ),
                                                            url="https://app.flashpoint.io/search/context/"
                                                            + source
                                                            + "/"
                                                            + item["id"],
                                                            publication_date=item[
                                                                "date"
                                                            ],
                                                        )
                                                        # author = CustomObservablePersona(
                                                        #    title=community["title"],
                                                        #    content=community["message"],
                                                        #    url="https://app.flashpoint.io/search/context/communities/" + community["id"],
                                                        #    publication_date=community["date"]
                                                        # )
                                                        relationship_publishes = stix2.Relationship(
                                                            id=StixCoreRelationship.generate_id(
                                                                "publishes",
                                                                channel.id,
                                                                media_content.id,
                                                            ),
                                                            relationship_type="publishes",
                                                            created_by_ref=self.identity[
                                                                "standard_id"
                                                            ],
                                                            source_ref=channel.id,
                                                            target_ref=media_content.id,
                                                            start_time=start_time,
                                                            stop_time=stop_time,
                                                            object_marking_refs=[
                                                                stix2.TLP_GREEN.get(
                                                                    "id"
                                                                )
                                                            ],
                                                            allow_custom=True,
                                                        )
                                                        relationship_related_to = stix2.Relationship(
                                                            id=StixCoreRelationship.generate_id(
                                                                "related-to",
                                                                media_content.id,
                                                                incident.id,
                                                            ),
                                                            relationship_type="related-to",
                                                            created_by_ref=self.identity[
                                                                "standard_id"
                                                            ],
                                                            source_ref=media_content.id,
                                                            target_ref=incident.id,
                                                            object_marking_refs=[
                                                                stix2.TLP_AMBER.get(
                                                                    "id"
                                                                )
                                                            ],
                                                            allow_custom=True,
                                                        )
                                                        objects = [
                                                            incident,
                                                            relationship_uses,
                                                            channel,
                                                            media_content,
                                                            relationship_publishes,
                                                            relationship_related_to,
                                                        ]
                                                        bundle = self.helper.stix2_create_bundle(
                                                            objects
                                                        )
                                                        self.helper.send_stix2_bundle(
                                                            bundle,
                                                            work_id=work_id,
                                                        )
                                                except Exception as e:
                                                    self.helper.log_error(str(e))
                                                page = page + 1
                                                body_params_source = {
                                                    "query": query["value"],
                                                    "include": include,
                                                    "exclude": exclude,
                                                    "size": "1000",
                                                    "sort": {"date": "asc"},
                                                    "page": page,
                                                }
                                                response_source = requests.post(
                                                    url_source,
                                                    headers=headers,
                                                    json=body_params_source,
                                                )
                                                data_source = json.loads(
                                                    response_source.content
                                                )
                                    except Exception as e:
                                        self.helper.log_error(str(e))
                    except Exception as e:
                        self.helper.log_error(str(e))
                    from_iterator = from_iterator + 100
                    params = {"size": 100, "from": from_iterator}
                    response = requests.get(url, headers=headers, params=params)
                    data = json.loads(response.content)
        except Exception as e:
            self.helper.log_error(str(e))

    def process_data(self):
        try:
            self.helper.log_info("Synchronizing with Flashpoint APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.utcfromtimestamp(timestamp)
            friendly_name = "Flashpoint run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            if current_state is None:
                self.helper.set_state(
                    {
                        "last_run": parse(self.flashpoint_import_start_date)
                        .astimezone(pytz.UTC)
                        .isoformat()
                    }
                )
            else:
                if "last_run" not in current_state:
                    current_state["last_run"] = (
                        parse(self.flashpoint_import_start_date)
                        .astimezone(pytz.UTC)
                        .isoformat()
                    )
                    self.helper.set_state(current_state)
            current_state = self.helper.get_state()
            if self.flashpoint_import_apt:
                self.helper.log_info("Get APTs since " + current_state["last_run"])
                self._import_apt(work_id)
            if self.flashpoint_import_malware:
                self.helper.log_info("Get Malwares since " + current_state["last_run"])
                self._import_malware(work_id)
            if self.flashpoint_import_reports:
                self.helper.log_info("Get Reports since " + current_state["last_run"])
                self._import_reports(work_id, current_state["last_run"])
            if self.flashpoint_import_communities:
                self.helper.log_info(
                    "Get Communities since " + current_state["last_run"]
                )
                self._import_communities(work_id, current_state["last_run"])
            if self.flashpoint_import_alerts:
                self.helper.log_info("Get Alerts since " + current_state["last_run"])
                self._import_alerts(work_id, current_state["last_run"])
            current_state = self.helper.get_state()
            current_state["last_run"] = now.astimezone(pytz.UTC).isoformat()
            self.helper.set_state(current_state)
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)
            time.sleep(self.get_interval())
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching Flashpoint datasets...")
        if self.flashpoint_import_indicators:
            self.misp_feed = MispFeed(
                self.helper,
                self.flashpoint_api_key,
                self.flashpoint_import_start_date,
                self.flashpoint_indicators_in_reports,
            )
            self.misp_feed.start()
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.get_interval())

    def send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")


if __name__ == "__main__":
    try:
        flashpointConnector = Flashpoint()
        flashpointConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
