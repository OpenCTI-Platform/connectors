import os
import sys
import time
from typing import Dict

import yaml
from client import GoogleDNSClient
from pycti import CustomObservableText, OpenCTIConnectorHelper, StixCoreRelationship
from stix2 import TLP_WHITE, Bundle, DomainName, IPv4Address, Relationship


class GoogleDNSConnector:
    def __init__(self):
        config_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=True)
        self.dns_client = GoogleDNSClient()

    def _build_ip_addrs(self, domain, a_records) -> list:
        self.helper.log_debug("Creating and sending STIX bundle")

        objects = []
        for record in a_records:
            # Create IPv4 Addr
            ipv4 = IPv4Address(
                value=record,
                object_marking_refs=TLP_WHITE,
            )
            objects.append(ipv4)
            self.helper.log_debug("Created IPv4 Addr")

            # Create resolves-to Relationship from Domain Name to IPv4 Addr
            relationship = Relationship(
                id=StixCoreRelationship.generate_id(
                    "resolves-to", domain["standard_id"], ipv4.id
                ),
                relationship_type="resolves-to",
                source_ref=domain["standard_id"],
                target_ref=ipv4.id,
                object_marking_refs=TLP_WHITE,
                confidence=100,
            )
            objects.append(relationship)
            self.helper.log_debug("Created Relationship from Domain Name to IPv4 Addr")

        return objects

    def _build_nameservers(self, domain, ns_records) -> list:
        self.helper.log_debug("Creating and sending STIX bundle")

        objects = []
        for record in ns_records:
            # Create Domain Name
            ns_domain = DomainName(
                value=record,
                object_marking_refs=TLP_WHITE,
            )
            objects.append(ns_domain)
            self.helper.log_debug("Created Domain Name")

            # Create resolves-to Relationship from Domain Name to Domain Name
            if domain["standard_id"] != ns_domain.id:
                relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "resolves-to", domain["standard_id"], ns_domain.id
                    ),
                    relationship_type="resolves-to",
                    source_ref=domain["standard_id"],
                    target_ref=ns_domain.id,
                    description="name-server",
                    object_marking_refs=TLP_WHITE,
                    confidence=100,
                )
                objects.append(relationship)
                self.helper.log_debug(
                    "Created Relationship from Domain Name to Domain Name"
                )

        return objects

    def _build_cname_domains(self, domain, cname_records) -> list:
        self.helper.log_debug("Creating and sending STIX bundle")

        objects = []
        for record in cname_records:
            # Create Domain Name Addr
            cname_domain = DomainName(
                value=record,
                object_marking_refs=TLP_WHITE,
            )
            objects.append(cname_domain)
            self.helper.log_debug("Created Domain Name")

            # Create resolves-to Relationship from Domain Name to Domain Name
            if domain["standard_id"] != cname_domain.id:
                relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "resolves-to", domain["standard_id"], cname_domain.id
                    ),
                    relationship_type="resolves-to",
                    source_ref=domain["standard_id"],
                    target_ref=cname_domain.id,
                    description="cname",
                    object_marking_refs=TLP_WHITE,
                    confidence=100,
                )
                objects.append(relationship)
                self.helper.log_debug(
                    "Created Relationship from Domain Name to Domain Name"
                )

        return objects

    def _build_mx_domains(self, domain, mx_records) -> list:
        self.helper.log_debug("Creating and sending STIX bundle")

        objects = []
        for record in mx_records:
            # Create Domain Name Addr
            mx_domain = DomainName(
                value=record,
                object_marking_refs=TLP_WHITE,
            )
            objects.append(mx_domain)
            self.helper.log_debug("Created Domain Name")

            # Create resolves-to Relationship from Domain Name to Domain Name
            if domain["standard_id"] != mx_domain.id:
                relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "resolves-to", domain["standard_id"], mx_domain.id
                    ),
                    relationship_type="resolves-to",
                    source_ref=domain["standard_id"],
                    target_ref=mx_domain.id,
                    description="mx",
                    object_marking_refs=TLP_WHITE,
                    confidence=100,
                )
                objects.append(relationship)
                self.helper.log_debug(
                    "Created Relationship from Domain Name to Domain Name"
                )

        return objects

    def _build_txt_objects(self, domain, txt_records) -> list:
        self.helper.log_debug("Creating and sending STIX bundle")

        objects = []
        for record in txt_records:
            # Create a Text Observable
            txt_object = CustomObservableText(
                value=record,
                object_marking_refs=TLP_WHITE,
            )
            objects.append(txt_object)
            self.helper.log_debug("Created Text Observable")

            # Create related-to Relationship from Domain Name to Text
            relationship = Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", domain["standard_id"], txt_object.id
                ),
                relationship_type="related-to",
                source_ref=domain["standard_id"],
                target_ref=txt_object.id,
                description="TXT",
                object_marking_refs=TLP_WHITE,
                confidence=100,
            )
            objects.append(relationship)
            self.helper.log_debug("Created Relationship from Domain Name to Text")

        return objects

    def _process_message(self, data: Dict) -> str:
        domain = data["enrichment_entity"]
        # Handle 'NS' records
        self.helper.log_debug("Getting 'NS' records via Google Public DNS")
        ns_records = self.dns_client.ns(domain["observable_value"])
        if any(ns_records):
            ns_objects = self._build_nameservers(domain, ns_records)
            bundle = Bundle(objects=ns_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        # Handle any 'A' records
        self.helper.log_debug("Getting 'A' records via Google Public DNS")
        a_records = self.dns_client.a(domain["observable_value"])
        if any(a_records):
            ipv4_objects = self._build_ip_addrs(domain, a_records)
            bundle = Bundle(objects=ipv4_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        # Handle any 'CNAME' records
        self.helper.log_debug("Getting 'CNAME' records via Google Public DNS")
        cname_records = self.dns_client.cname(domain["observable_value"])
        if any(cname_records):
            domain_objects = self._build_cname_domains(domain, cname_records)
            bundle = Bundle(objects=domain_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        # Handle any 'MX' records
        self.helper.log_debug("Getting 'MX' records via Google Public DNS")
        mx_records = self.dns_client.mx(domain["observable_value"])
        if any(mx_records):
            domain_objects = self._build_mx_domains(domain, mx_records)
            bundle = Bundle(objects=domain_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        # Handle any 'TXT' records
        self.helper.log_debug("Getting 'TXT' records via Google Public DNS")
        txt_records = self.dns_client.txt(domain["observable_value"])
        if any(txt_records):
            txt_objects = self._build_txt_objects(domain, txt_records)
            bundle = Bundle(objects=txt_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        return "Done"

    def start(self) -> None:
        self.helper.log_info("Google DNS connector started")
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        connector = GoogleDNSConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
