import os
import sys
import time

import yaml
from client import GoogleDNSClient
from pycti import OpenCTIConnectorHelper, StixCoreRelationship
from stix2 import (
    TLP_WHITE,
    Bundle,
    CustomObservable,
    DomainName,
    IPv4Address,
    Relationship,
)
from stix2.properties import ListProperty, ReferenceProperty, StringProperty


@CustomObservable(
    "text",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class Text:
    pass


class GoogleDNSConnector:
    def __init__(self):
        config_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.dns_client = GoogleDNSClient()

    def _get_domain(self, entity_id):
        self.helper.log_debug("Getting Domain Name from OpenCTI")
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        return observable

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
            txt_object = Text(
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

    def _process_message(self, data: dict) -> str:
        entity_id = data["entity_id"]
        self.helper.log_info(f"Enriching {entity_id}")
        domain = self._get_domain(entity_id)

        # Handle 'NS' records
        self.helper.log_debug("Getting 'NS' records via Google Public DNS")
        ns_records = self.dns_client.ns(domain["value"])
        if any(ns_records):
            ns_objects = self._build_nameservers(domain, ns_records)
            bundle = Bundle(objects=ns_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        # Handle any 'A' records
        self.helper.log_debug("Getting 'A' records via Google Public DNS")
        a_records = self.dns_client.a(domain["value"])
        if any(a_records):
            ipv4_objects = self._build_ip_addrs(domain, a_records)
            bundle = Bundle(objects=ipv4_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        # Handle any 'CNAME' records
        self.helper.log_debug("Getting 'CNAME' records via Google Public DNS")
        cname_records = self.dns_client.cname(domain["value"])
        if any(cname_records):
            domain_objects = self._build_cname_domains(domain, cname_records)
            bundle = Bundle(objects=domain_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        # Handle any 'MX' records
        self.helper.log_debug("Getting 'MX' records via Google Public DNS")
        mx_records = self.dns_client.mx(domain["value"])
        if any(mx_records):
            domain_objects = self._build_mx_domains(domain, mx_records)
            bundle = Bundle(objects=domain_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        # Handle any 'TXT' records
        self.helper.log_debug("Getting 'TXT' records via Google Public DNS")
        txt_records = self.dns_client.txt(domain["value"])
        if any(txt_records):
            txt_objects = self._build_txt_objects(domain, txt_records)
            bundle = Bundle(objects=txt_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        return "Done"

    def start(self) -> None:
        self.helper.log_info("Google DNS connector started")
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector = GoogleDNSConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
