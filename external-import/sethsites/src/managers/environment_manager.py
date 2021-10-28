import threading
import time

import ciso8601
from datetime import datetime
from pycti import OpenCTIConnectorHelper
from stix2.v21 import (Location, Identity, IPv4Address, IPv6Address, Relationship, Bundle, NetworkTraffic, Indicator,
                       ThreatActor, IntrusionSet)
from managers import RelationshipManager


class EnvironmentManager:
    def __init__(self, helper: OpenCTIConnectorHelper, relationship_manager: RelationshipManager, config=None,
                 environment=None):
        if environment is None:
            environment = {}
        if config is None:
            config = {}

        self.relationship_manager = relationship_manager
        self.environment = environment
        self.helper = helper
        self.config = config
        self.confidence = int(config.get("connector.confidence_level", 90))

        self.author = None
        self.report = None
        self.public_networks: [str] = []
        self.private_networks: [str] = []
        self.ignore_networks: [str] = []
        self.hosts_by_tag: dict[str, [str]] = {}
        self.threat_actors: [str] = []
        self.intrusion_sets: [str] = []

    def get_ignore_networks(self) -> [IPv4Address]:
        return self.ignore_networks

    def get_public_networks(self) -> [IPv4Address]:
        return self.public_networks

    def get_private_networks(self) -> [IPv4Address]:
        return self.private_networks

    def get_hosts_with_tag(self, tag: str) -> [str]:
        if tag in self.hosts_by_tag:
            return self.hosts_by_tag[tag]
        else:
            return []

    def get_sector_for_ip_addr(self, ip_addr: str) -> str:
        for city in self.environment["cities"]:
            for sector in city["sectors"]:
                for host in sector["hosts"]:
                    if host["ip_address"] == ip_addr:
                        return sector["id"]
            search_str = ""
            try:
                search_str_parts = ip_addr.split(".")
                search_str = '.'.join([search_str_parts[0], search_str_parts[1], search_str_parts[2]])
                for network in city["networks"]:
                    if search_str in network["ip_range"]:
                        for sector in city["sectors"]:
                            if sector["name"] == network["sectors"][0]:
                                return sector["id"]
            except Exception:
                return None
        return None


    def find_or_create_ipv4(self, ip_address, stix_id="", description="") -> IPv4Address:
        self.helper.log_info(f"Processing ip address {ip_address}")
        found_ipv4_addresses = self.helper.api.stix_cyber_observable.list(
            types=["IPv4Addr"],
            filters={"key": "value", "values": [ip_address]},
            customAttributes="""
                                        id
                                        standard_id
                                        ... on IPv4Addr {
                                            value
                                        }
                                        """
        )
        if len(found_ipv4_addresses) > 0:
            for ip_address in found_ipv4_addresses:
                found_ipv4_address = ip_address
                self.helper.log_info(f"found {found_ipv4_address}")
                return found_ipv4_address
        else:
            self.helper.log_info(f"Creating ipv4_address")
            observable_data = {
                "type": "ipv4-addr",
                "value": ip_address,
                "x_opencti_description": description,
                "x_opencti_score": self.confidence
            }
            if stix_id != "":
                observable_data["id"] = stix_id
            found_ipv4_address = self.helper.api.stix_cyber_observable.create(
                observableData=observable_data,
                createdBy=self.author
            )
            found_ipv4_address["created"] = True
            self.helper.log_info(f"Response {found_ipv4_address}")
            return found_ipv4_address

    def find_or_create_ipv6(self, ip_address, stix_id="", description="") -> IPv6Address:
        self.helper.log_info(f"Processing ip address {ip_address}")
        found_ipv6_addresses = self.helper.api.stix_cyber_observable.list(
            types=["IPv6Addr"],
            filters={"key": "value", "values": [ip_address]},
            customAttributes="""
                                        id
                                        standard_id
                                        ... on IPv6Addr {
                                            value
                                        }
                                        """
        )
        if len(found_ipv6_addresses) > 0:
            for ip_address in found_ipv6_addresses:
                found_ipv6_address = ip_address
                self.helper.log_debug(f"found {found_ipv6_address}")
                return found_ipv6_address
        else:
            self.helper.log_debug(f"Creating ipv6_address")
            observable_data = {
                "type": "ipv6-addr",
                "value": ip_address,
                "x_opencti_description": description,
                "x_opencti_score": self.confidence,
            }
            if stix_id != "":
                observable_data["id"] = stix_id
            found_ipv6_address = self.helper.api.stix_cyber_observable.create(
                observableData=observable_data,
                createdBy=self.author
            )
            found_ipv6_address["created"] = True
            self.helper.log_debug(f"Response {found_ipv6_address}")
            return found_ipv6_address

    def add_item_to_report(self, stix_id: str):
        if self.report is not None:
            if not self.helper.api.report.contains_stix_object_or_stix_relationship(
                id=self.report,
                stixObjectOrStixRelationshipId=stix_id
            ):
                self.helper.api.report.add_stix_object_or_stix_relationship(
                    id=self.report,
                    stixObjectOrStixRelationshipId=stix_id
                )

    def check_environment(self):
        if "author" in self.environment:
            author = self.environment["author"]
            self.author = author["id"]
            self.helper.log_debug(f"Processing author {author}")
            authors = self.helper.api.identity.read(
                filters={"key": "name", "values": [author["name"]]}
            )
            if authors:
                self.helper.log_info(f"Found {authors}")
            else:
                created_author = self.helper.api.identity.create(
                    stix_id=author["id"],
                    name=author["name"],
                    type="Organization",
                    confidence=self.confidence
                )
                self.helper.log_debug(f"Response {created_author}")
        if "report" in self.environment:
            report = self.environment["report"]
            self.report = report["id"]
            self.helper.log_debug(f"Processing report {report}")
            reports = self.helper.api.report.read(
                filters={"key": "name", "values": [report["name"]]}
            )
            if reports:
                self.helper.log_info(f"Found {reports}")
            else:
                created_report = self.helper.api.report.create(
                    stix_id=report["id"],
                    name=report["name"],
                    description=report["description"],
                    createdBy=self.author,
                    report_types=["internal-report"],
                    published=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    confidence=self.confidence
                )
                self.helper.log_debug(f"Response {created_report}")
        for city in self.environment["cities"]:
            self.helper.log_debug(f"Processing city {city}")
            cti_city = self.helper.api.location.list(
                types=["City"],
                filters={"key": "name", "values": [city["name"]]},
                customAttributes="""
                    standard_id
                    ... on City {
                        name
                        standard_id
                    }
                    name
                        """
            )
            if cti_city:
                self.helper.log_debug(f"Response was {cti_city}")
                for ccity in cti_city:
                    self.helper.log_debug(f"Found city {ccity}")
            else:
                self.helper.log_debug(f"Creating city")
                ccity = self.helper.api.location.create(
                    stix_id=city["id"],
                    name=city["name"],
                    type="City",
                    confidence=self.confidence,
                    createdBy=self.author
                )
                self.helper.log_debug(f"Response {ccity}")
                city["id"] = ccity["standard_id"]

            self.add_item_to_report(city["id"])

            for network in city["networks"]:
                ip_network = self.find_or_create_ipv4(network["ip_range"], network["id"])
                if network["ignore"] == "true":
                    self.ignore_networks.append(network["ip_range"])
                else:
                    if network["public"] == "true":
                        self.public_networks.append(network["ip_range"])
                    else:
                        self.private_networks.append(network["ip_range"])

                if "created" in ip_network:
                    relationship = self.helper.api.stix_core_relationship.create(
                        fromId=network["id"],
                        toId=city["id"],
                        relationship_type="located-at",
                        confidence=self.confidence,
                        createdBy=self.author
                    )
                    self.helper.log_debug(f"Response {relationship}")

            for sector in city["sectors"]:
                self.helper.log_debug(f"Processing sector {sector}")
                cti_sector = self.helper.api.identity.read(
                    filters={"key": "name", "values": [sector["name"]]}
                )
                if cti_sector:
                    self.helper.log_info(f"Found {cti_sector}")
                else:
                    cti_sector = self.helper.api.identity.create(
                        stix_id=sector["id"],
                        name=sector["name"],
                        type="Sector",
                        confidence=self.confidence,
                        createdBy=self.author
                    )
                    self.helper.log_debug(f"Response {cti_sector}")

                    relationship = self.helper.api.stix_core_relationship.create(
                        fromId=sector["id"],
                        toId=city["id"],
                        relationship_type="related-to",
                        confidence=self.confidence,
                        createdBy=self.author
                    )
                    self.helper.log_debug(f"Response {relationship}")

                for host in sector["hosts"]:
                    ipv4_address = self.find_or_create_ipv4(host["ip_address"], host["id"], host["desc"])
                    for role in host["roles"]:
                        if role not in self.hosts_by_tag:
                            self.hosts_by_tag[role] = []

                        self.hosts_by_tag[role].append(host["ip_address"])

                    if "created" in ipv4_address:
                        relationship = self.helper.api.stix_core_relationship.create(
                            fromId=host["id"],
                            toId=sector["id"],
                            relationship_type="related-to",
                            confidence=self.confidence,
                            createdBy=self.author
                        )
                        self.helper.log_debug(f"Response {relationship}")

                        relationship = self.helper.api.stix_core_relationship.create(
                            fromId=host["id"],
                            toId=city["id"],
                            relationship_type="located-at",
                            confidence=self.confidence,
                            createdBy=self.author
                        )
                        self.helper.log_debug(f"Response {relationship}")

        for threat in self.environment["threats"]:
            threat_actors = self.helper.api.threat_actor.list(
                filters={"key": "name", "values": [threat["name"]]}
            )
            if len(threat_actors) > 0:
                threat_actor = threat_actors[0]
            else:
                threat_actor = self.helper.api.threat_actor.create(
                    stix_id=threat["id"],
                    name=threat["name"],
                    description=threat["description"],
                    createdBy=self.author
                )
            self.threat_actors.append(threat["id"])
            self.add_item_to_report(threat["id"])

            for int_set in threat["intrusion_sets"]:
                intrusion_sets = self.helper.api.intrusion_set.list(
                    filters={"key": "name", "values": [int_set["name"]]}
                )

                if len(intrusion_sets) > 0:
                    intrusion_set = intrusion_sets[0]
                else:
                    intrusion_set = self.helper.api.intrusion_set.create(
                        stix_id=int_set["id"],
                        name=int_set["name"],
                        description=int_set["description"],
                        confidence=self.confidence,
                        createdBy=self.author
                    )
                self.intrusion_sets.append(int_set["id"])
                self.add_item_to_report(int_set["id"])

                relationship = self.relationship_manager.find_or_create_relationship(
                    relationship_type="related-to",
                    fromId=int_set["id"],
                    toId=threat["id"],
                    confidence=self.confidence,
                    createdBy=self.author
                )
                self.add_item_to_report(relationship["standard_id"])

            for city in self.environment["cities"]:
                relationship = self.relationship_manager.find_or_create_relationship(
                    relationship_type="related-to",
                    fromId=threat["id"],
                    toId=city["id"],
                    confidence=self.confidence,
                    createdBy=self.author
                )
                self.add_item_to_report(relationship["standard_id"])
