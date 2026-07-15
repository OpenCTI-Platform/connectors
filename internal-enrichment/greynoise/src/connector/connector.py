import os
from datetime import datetime

import pycountry
import stix2
import yaml
from connector.settings import ConnectorSettings
from dateutil.parser import parse
from greynoise.api import APIConfig, GreyNoise
from greynoise.exceptions import RequestFailure
from pycti import (
    Identity,
    Indicator,
    Location,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    StixSightingRelationship,
    ThreatActorGroup,
    Tool,
    Vulnerability,
)

INTEGRATION_NAME = "opencti-enricher-v4.0"


class GreyNoiseConnector:
    def __init__(self):
        # NOTE:
        # The real connector is instantiated from main.py.tmp with:
        #   GreyNoiseConnector(config=settings, helper=helper)
        # Tests also instantiate it this way.
        # This __init__ must therefore accept config/helper passed in runtime.
        raise RuntimeError(
            "GreyNoiseConnector must be instantiated with (config, helper). "
            "Please use main.py.tmp entrypoint."
        )

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        # Greynoise configuration
        self.greynoise_key = self.config.greynoise.key
        self.max_tlp = self.config.greynoise.max_tlp
        self.sighting_not_seen = self.config.greynoise.sighting_not_seen
        self.no_sightings = self.config.greynoise.no_sightings

        # Optional config not present in settings model: keep previous defaults
        self.greynoise_ent_name = os.environ.get(
            "GREYNOISE_NAME", "GreyNoise Intelligence"
        )
        self.greynoise_ent_desc = os.environ.get(
            "GREYNOISE_DESCRIPTION",
            "GreyNoise collects and analyzes untargeted, widespread, and opportunistic scan and attack activity that reaches every server directly connected to the Internet.",
        )
        self.indicator_score_malicious = int(
            os.environ.get("GREYNOISE_INDICATOR_SCORE_MALICIOUS", "75")
        )
        self.indicator_score_suspicious = int(
            os.environ.get("GREYNOISE_INDICATOR_SCORE_SUSPICIOUS", "50")
        )
        self.indicator_score_benign = int(
            os.environ.get("GREYNOISE_INDICATOR_SCORE_BENIGN", "20")
        )

        self._CONNECTOR_RUN_INTERVAL_SEC = 60 * 60
        self.tlp = None
        self.stix_objects = []

    def _get_indicator_score(self, classification):
        if classification == "malicious":
            self.indicator_score = self.indicator_score_malicious
        elif classification == "suspicious" or classification == "2":
            self.indicator_score = self.indicator_score_suspicious
        else:
            self.indicator_score = self.indicator_score_benign
        return self.indicator_score

    def _extract_and_check_markings(self, opencti_entity: dict) -> bool:
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                self.tlp = marking_definition["definition"]
        is_valid_max_tlp = OpenCTIConnectorHelper.check_max_tlp(self.tlp, self.max_tlp)
        return is_valid_max_tlp

    def _generate_stix_relationship(
        self,
        source_ref: str,
        stix_core_relationship_type: str,
        target_ref: str,
        start_time: str | None = None,
        stop_time: str | None = None,
    ) -> dict:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            start_time=start_time,
            stop_time=stop_time,
            target_ref=target_ref,
            created_by_ref=self.greynoise_identity["id"],
        )

    def _create_custom_label(self, name_label: str, color_label: str):
        new_custom_label = self.helper.api.label.read_or_create_unchecked(
            value=name_label,
            color=color_label,
            createdBy=self.greynoise_identity["id"],
        )
        if new_custom_label is None:
            self.helper.connector_logger.error(
                "[ERROR] The label could not be created. If your connector does not have the permission to create labels, please create it manually before launching",
                {"name_label": name_label},
            )
        else:
            self.all_labels.append(new_custom_label["value"])

    def _process_labels(self, data: dict) -> tuple:
        self.all_labels = []
        all_malwares = []
        entity_tags = data["internet_scanner_intelligence"].get("tags", [])
        if data["internet_scanner_intelligence"]["classification"] == "benign":
            self._create_custom_label("gn-classification: benign", "#06c93a")
            self._create_custom_label(
                f"gn-benign-actor: {data['internet_scanner_intelligence']['actor']} ",
                "#06c93a",
            )
        elif data["internet_scanner_intelligence"]["classification"] == "unknown":
            self._create_custom_label("gn-classification: unknown", "#a6a09f")
        elif data["internet_scanner_intelligence"]["classification"] == "malicious":
            self._create_custom_label("gn-classification: malicious", "#ff8178")
        elif data["internet_scanner_intelligence"]["classification"] == "suspicious":
            self._create_custom_label("gn-classification: suspicious", "#e3d922")
        if data["business_service_intelligence"]["trust_level"] == "1":
            self._create_custom_label("gn-trust-level: reasonably ignore", "#90D5FF")
            self._create_custom_label(
                f"gn-provider: {data['business_service_intelligence']['name']} ",
                "#90D5FF",
            )
        elif data["business_service_intelligence"]["trust_level"] == "2":
            self._create_custom_label("gn-trust-level: commonly seen", "#57B9FF")
            self._create_custom_label(
                f"gn-provider: {data['business_service_intelligence']['name']} ",
                "#57B9FF",
            )
        if data["internet_scanner_intelligence"].get("bot") is True:
            self._create_custom_label("Known BOT Activity", "#7e4ec2")
        if data["internet_scanner_intelligence"]["tor"] is True:
            self._create_custom_label("Known TOR Exit Node", "#7e4ec2")
        if data["internet_scanner_intelligence"]["vpn"] is True:
            self._create_custom_label("Known VPN", "#7e4ec2")
        for tag in entity_tags:
            if tag["intention"] == "malicious" and tag["category"] not in ["worm"]:
                self._create_custom_label(f"{tag['name']}", "#ff8178")
            elif tag["category"] == "worm":
                malware_worm = {
                    "name": f"{tag}",
                    "description": f"{tag['description']}",
                    "type": "worm",
                }
                all_malwares.append(malware_worm)
                self.all_labels.append(tag["name"])
            elif tag["intention"] == "benign":
                self._create_custom_label(f"{tag['name']}", "#06c93a")
            elif tag["intention"] == "suspicious":
                self._create_custom_label(f"{tag['name']}", "#e3d922")
            else:
                self._create_custom_label(f"{tag['name']}", "#ffffff")
        return (self.all_labels, all_malwares)

    def _generate_stix_external_reference(self, data: dict) -> list:
        description = ""
        if data["internet_scanner_intelligence"]["found"] is True:
            description = "This reference will direct to the GreyNoise Visualizer IP details page for an IP that has been seen mass scanning the internet."
        elif data["business_service_intelligence"]["found"] is True:
            description = "This reference will direct to the GreyNoise Visualizer IP details page for an IP that is part of a common business service."
        else:
            description = "This reference will direct to the GreyNoise Visualizer IP details page for an IP that has not yet been identified by GreyNoise, meaning it has not been seen mass scanning the internet nor does it belong to a business service that we monitor."
        external_reference = stix2.ExternalReference(
            source_name=self.greynoise_ent_name,
            url=f"https://viz.greynoise.io/ip/{data['ip']}",
            external_id=data["ip"],
            description=description,
        )
        return [external_reference]

    def _generate_greynoise_stix_identity(self):
        self.greynoise_identity = stix2.Identity(
            id=Identity.generate_id(self.greynoise_ent_name, "organization"),
            name=self.greynoise_ent_name,
            description=f"Connector Enrichment {self.greynoise_ent_name}",
            identity_class="organization",
        )
        self.stix_objects.append(self.greynoise_identity)

    def _generate_other_stix_identity_with_relationship(self, data: dict):
        organization = data["internet_scanner_intelligence"]["metadata"].get(
            "organization", ""
        )
        if organization != "":
            stix_organization = stix2.Identity(
                id=Identity.generate_id(organization, "organization"),
                name=organization,
                identity_class="organization",
                created_by_ref=self.greynoise_identity["id"],
            )
            self.stix_objects.append(stix_organization)
            observable_to_organization = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_organization.id
            )
            self.stix_objects.append(observable_to_organization)

    def _generate_stix_asn_with_relationship(self, data: dict):
        entity_asn = data["internet_scanner_intelligence"]["metadata"].get("asn", "")
        if entity_asn != "":
            asn_number = int(
                data["internet_scanner_intelligence"]["metadata"]["asn"].replace(
                    "AS", ""
                )
            )
            stix_asn = stix2.AutonomousSystem(
                type="autonomous-system",
                number=asn_number,
                name=entity_asn,
                custom_properties={
                    "created_by_ref": self.greynoise_identity["id"],
                    "x_opencti_score": self.indicator_score,
                },
            )
            self.stix_objects.append(stix_asn)
            observable_to_asn = self._generate_stix_relationship(
                self.stix_entity["id"], "belongs-to", stix_asn.id
            )
            self.stix_objects.append(observable_to_asn)

    def _generate_stix_domain_with_relationship(self, data: dict):
        entity_domain = data["internet_scanner_intelligence"]["metadata"].get(
            "rdns", ""
        )
        if entity_domain != "":
            stix_domain = stix2.DomainName(
                type="domain-name",
                value=entity_domain,
                custom_properties={
                    "created_by_ref": self.greynoise_identity["id"],
                    "x_opencti_score": self.indicator_score,
                },
            )
            self.stix_objects.append(stix_domain)
            domain_to_observable = self._generate_stix_relationship(
                stix_domain.id, "resolves-to", self.stix_entity["id"]
            )
            self.stix_objects.append(domain_to_observable)

    def _generate_stix_location_with_relationship(self, data: dict):
        if data["internet_scanner_intelligence"]["found"] is True:
            country = pycountry.countries.get(
                alpha_2=data["internet_scanner_intelligence"]["metadata"][
                    "source_country_code"
                ]
            )
            country_name = (
                country.official_name
                if hasattr(country, "official_name")
                else country.name
            )
            stix_city_location = stix2.Location(
                id=Location.generate_id(
                    data["internet_scanner_intelligence"]["metadata"]["source_city"],
                    "City",
                ),
                name=data["internet_scanner_intelligence"]["metadata"]["source_city"],
                country=country_name,
                custom_properties={"x_opencti_location_type": "City"},
            )
            self.stix_objects.append(stix_city_location)
            observable_to_city = self._generate_stix_relationship(
                self.stix_entity["id"], "located-at", stix_city_location.id
            )
            self.stix_objects.append(observable_to_city)
            stix_country_location = stix2.Location(
                id=Location.generate_id(country.name, "Country"),
                name=country_name,
                country=country_name,
                custom_properties={
                    "x_opencti_location_type": "Country",
                    "x_opencti_aliases": [
                        data["internet_scanner_intelligence"]["metadata"][
                            "source_country_code"
                        ]
                    ],
                },
            )
            self.stix_objects.append(stix_country_location)
            city_to_country = self._generate_stix_relationship(
                stix_city_location.id, "located-at", stix_country_location.id
            )
            self.stix_objects.append(city_to_country)

    def _generate_stix_vulnerability_with_relationship(self, data: dict):
        if (
            "cves" in data["internet_scanner_intelligence"]
            and data["internet_scanner_intelligence"].get("cves", []) is not []
        ):
            entity_vulns = data["internet_scanner_intelligence"]["cves"]
            for vuln in entity_vulns:
                stix_vulnerability = stix2.Vulnerability(
                    id=Vulnerability.generate_id(vuln),
                    name=vuln,
                    created_by_ref=self.greynoise_identity["id"],
                    allow_custom=True,
                )
                self.stix_objects.append(stix_vulnerability)
                observable_to_vulnerability = self._generate_stix_relationship(
                    self.stix_entity["id"],
                    "related-to",
                    stix_vulnerability.id,
                    self.first_seen,
                    self.last_seen,
                )
                self.stix_objects.append(observable_to_vulnerability)

    def _generate_stix_tool_with_relationship(self, data: dict):
        if data["internet_scanner_intelligence"]["vpn"] is True:
            stix_tool = stix2.Tool(
                id=Tool.generate_id(
                    f"VPN: {data['internet_scanner_intelligence']['vpn_service']}"
                ),
                name=f"VPN: {data['internet_scanner_intelligence']['vpn_service']}",
                labels=["tool"],
                created_by_ref=self.greynoise_identity["id"],
                custom_properties={
                    "x_opencti_aliases": data["internet_scanner_intelligence"][
                        "vpn_service"
                    ]
                },
                allow_custom=True,
            )
            self.stix_objects.append(stix_tool)
            observable_to_tool = self._generate_stix_relationship(
                self.stix_entity["id"],
                "related-to",
                stix_tool.id,
                self.first_seen,
                self.last_seen,
            )
            self.stix_objects.append(observable_to_tool)

    def _generate_stix_sighting(
        self,
        external_reference: list,
        stix_indicator: dict,
        sighting_not_seen: bool = False,
    ):
        default_now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        first_seen = default_now if sighting_not_seen is True else self.first_seen
        last_seen = default_now if sighting_not_seen is True else self.last_seen
        sighting_count = 0 if sighting_not_seen is True else 1
        stix_sighting_entity = stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                self.stix_entity["id"],
                self.greynoise_identity["id"],
                first_seen,
                last_seen,
            ),
            first_seen=first_seen,
            last_seen=last_seen,
            count=sighting_count,
            description=self.greynoise_ent_desc,
            created_by_ref=self.greynoise_identity["id"],
            where_sighted_refs=[self.greynoise_identity["id"]],
            external_references=external_reference,
            object_marking_refs=stix2.TLP_WHITE,
            sighting_of_ref="indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac8",
            custom_properties={
                "x_opencti_sighting_of_ref": self.stix_entity["id"],
                "x_opencti_negative": True,
            },
        )
        self.stix_objects.append(stix_sighting_entity)
        stix_sighting_indicator = stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                stix_indicator["id"],
                self.greynoise_identity["id"],
                first_seen,
                last_seen,
            ),
            first_seen=first_seen,
            last_seen=last_seen,
            count=sighting_count,
            description=self.greynoise_ent_desc,
            created_by_ref=self.greynoise_identity["id"],
            sighting_of_ref=stix_indicator["id"],
            where_sighted_refs=[self.greynoise_identity["id"]],
            external_references=external_reference,
            object_marking_refs=stix2.TLP_WHITE,
            custom_properties={"x_opencti_negative": True},
        )
        self.stix_objects.append(stix_sighting_indicator)

    def _generate_stix_malware_with_relationship(self, malwares: list):
        for malware in malwares:
            stix_malware = stix2.Malware(
                id=Malware.generate_id(malware["name"]),
                created_by_ref=self.greynoise_identity["id"],
                name=malware["name"],
                description=malware["description"],
                is_family=False,
                malware_types=malware["type"] if malware["type"] == "worm" else None,
                created=self.first_seen,
            )
            self.stix_objects.append(stix_malware)
            observable_to_malware = self._generate_stix_relationship(
                self.stix_entity["id"],
                "related-to",
                stix_malware.id,
                self.first_seen,
                self.last_seen,
            )
            self.stix_objects.append(observable_to_malware)

    def _generate_stix_threat_actor_with_relationship(self, data: dict):
        if (
            data["internet_scanner_intelligence"]["actor"]
            and data["internet_scanner_intelligence"]["actor"] != "unknown"
            and (data["internet_scanner_intelligence"]["actor"] != "")
            and (data["internet_scanner_intelligence"]["classification"] != "benign")
        ):
            stix_threat_actor = stix2.ThreatActor(
                id=ThreatActorGroup.generate_id(
                    data["internet_scanner_intelligence"]["actor"]
                ),
                name=data["internet_scanner_intelligence"]["actor"],
                created_by_ref=self.greynoise_identity["id"],
            )
            self.stix_objects.append(stix_threat_actor)
            observable_to_threat_actor = self._generate_stix_relationship(
                self.stix_entity["id"],
                "related-to",
                stix_threat_actor.id,
                self.first_seen,
                self.last_seen,
            )
            self.stix_objects.append
