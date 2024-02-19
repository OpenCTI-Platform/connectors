import os
import re
import time
from datetime import datetime

import dnstwist
import whois
from pycti import OpenCTIConnectorHelper
from stix2 import DomainName, IPv4Address, IPv6Address, Note, Relationship


class DnsTwistConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.dictonary_path = "/dictionaries/"
        self.total_threads = os.environ.get("CONNECTOR_DNS_TWIST_THREADS", "20")

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        if update_existing_data.lower() in ["true", "false"]:
            self.update_existing_data = update_existing_data.lower()
        else:
            msg = f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{self.interval}'. It SHOULD be either `true` or `false`. `false` is assumed. "
            self.helper.log_warning(msg)
            self.update_existing_data = "false"

    def detect_ip_version(self, value, type=False):
        if re.match(
            r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/([1-9]|[1-2]\d|3[0-2]))?$",
            value,
        ):
            if type:
                return "IPv4-Addr"
            return "ipv4-addr"
        else:
            if type:
                return "IPv6-Addr"
            return "ipv6-addr"

    def dns_twist_enrichment(self, observable):
        """Enriching the domain name using DNS Twist"""

        tld_file = os.path.join(self.dictonary_path, "common_tlds.dict")
        stix_objects = []
        self.registered = os.environ.get("CONNECTOR_FETCH_REGISTERED", None).lower()

        if self.registered == "true":
            self.registered = True
        else:
            self.registered = False

        # DNS Twist API call
        data = dnstwist.run(
            domain=observable.get("value"),
            registered=self.registered,
            format="null",
            m=True,
            threads=self.total_threads,
            tld=tld_file,
            w=True,
        )

        for item in data:
            if item.get("domain") and item.get("domain") != observable.get("value"):
                stix_objects = []

                domain_object = DomainName(
                    type="domain-name",
                    value=item.get("domain"),
                )

                relation_object = Relationship(
                    relationship_type="related-to",
                    source_ref=self.entity_id,
                    target_ref=domain_object.id,
                    description="related-to",
                )
                stix_objects.append(domain_object)
                stix_objects.append(relation_object)

                ## Creating Name Server records

                if item.get("dns_ns"):

                    for ns in item.get("dns_ns"):

                        if ns != "!ServFail":
                            ns_object = DomainName(type="domain-name", value=ns)

                            ns_relation_object = Relationship(
                                relationship_type="resolves-to",
                                source_ref=domain_object.get("id"),
                                target_ref=ns_object.get("id"),
                                description="related-to",
                            )
                            stix_objects.append(ns_object)
                            stix_objects.append(ns_relation_object)

                ## Creating A records and relationships

                if item.get("dns_a"):

                    for a in item.get("dns_a"):

                        if a != "!ServFail":

                            if self.detect_ip_version(a, True) == "IPv4-Addr":
                                a_object = IPv4Address(type="ipv4-addr", value=a)
                            else:

                                a_object = IPv6Address(type="ipv6-addr", value=a)

                            a_relation_object = Relationship(
                                relationship_type="resolves-to",
                                source_ref=domain_object.get("id"),
                                target_ref=a_object.get("id"),
                                description="related-to",
                            )
                            stix_objects.append(a_object)
                            stix_objects.append(a_relation_object)

                ## Creating AAAA records and relationships

                if item.get("dns_aaaa"):

                    for aaaa in item.get("dns_aaaa"):

                        if aaaa != "!ServFail":

                            if self.detect_ip_version(aaaa, True) == "IPv4-Addr":
                                aaaa_object = IPv4Address(type="ipv4-addr", value=aaaa)
                            else:
                                aaaa_object = IPv6Address(type="ipv6-addr", value=aaaa)
                            aaaa_relation_object = Relationship(
                                relationship_type="resolves-to",
                                source_ref=domain_object.get("id"),
                                target_ref=aaaa_object.get("id"),
                                description="related-to",
                            )
                            stix_objects.append(aaaa_object)
                            stix_objects.append(aaaa_relation_object)

                ## Creating MX records and relationships
                if item.get("dns_mx"):

                    for mx in item.get("dns_mx"):
                        if mx != "!ServFail":
                            mx_object = DomainName(type="domain-name", value=mx)
                            mx_relation_object = Relationship(
                                relationship_type="resolves-to",
                                source_ref=domain_object.get("id"),
                                target_ref=mx_object.get("id"),
                                description="related-to",
                            )
                        stix_objects.append(mx_object)

                bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(bundle)

                self.helper.api.stix_nested_ref_relationship.create(
                    fromId=self.entity_id,
                    toId=domain_object["id"],
                    relationship_type="resolves-to",
                    description="related-to",
                )
                self.helper.log_info(
                    f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
                )

        return "Success"

    def process_message(self, data):
        """Processing the DNS enrichment request"""
        self.helper.log_info("process data: " + str(data))

        self.entity_id = data["entity_id"]

        observable = self.helper.api.stix_cyber_observable.read(id=self.entity_id)

        ## Checking if the observable is a domain name
        if observable["entity_type"] == "Domain-Name":
            self.helper.log_info(f"Processing observable: {observable}")
            # Calling the DNS Twist enrichment function
            return self.dns_twist_enrichment(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self.process_message)
