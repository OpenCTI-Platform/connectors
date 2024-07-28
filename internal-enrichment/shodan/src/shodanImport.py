import json
import os
from datetime import datetime
from typing import Dict

import shodan
import stix2
import yaml
from pycti import (
    STIX_EXT_OCTI_SCO,
    CustomObservableHostname,
    Identity,
    Location,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
    get_config_variable,
)

FACETS = [
    ("org", 20),
    ("domain", 20),
    ("port", 20),
    ("asn", 20),
    ("country", 20),
]

FACET_TITLES = {
    "org": "Top 20 Organizations",
    "domain": "Top 20 Domains",
    "port": "Top 20 Ports",
    "asn": "Top 20 Autonomous Systems",
    "country": "Top 20 Countries",
}


class ShodanConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)
        self.token = get_config_variable("SHODAN_TOKEN", ["shodan", "token"], config)
        self.max_tlp = get_config_variable(
            "SHODAN_MAX_TLP", ["shodan", "max_tlp"], config, default="TLP:AMBER"
        )
        self.shodanAPI = shodan.Shodan(self.token)
        self.default_score = get_config_variable(
            "SHODAN_DEFAULT_SCORE",
            ["shodan", "default_score"],
            config,
            isNumber=True,
            default=50,
        )
        self.import_search_results = get_config_variable(
            "SHODAN_IMPORT_SEARCH_RESULTS",
            ["shodan", "import_search_results"],
            config,
            default=True,
        )

        # Shodan Identity
        self.shodan_identity = self.helper.api.identity.create(
            type="Organization",
            name=self.helper.get_name(),
            description=f"Connector Enrichment {self.helper.get_name()}",
        )

    def _extract_and_check_markings(self, entity):
        tlp = "TLP:CLEAR"
        for marking_definition in entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        is_valid_max_tlp = OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp)
        if not is_valid_max_tlp:
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        return tlp

    def _generate_stix_relationship(
        self, source_ref, stix_core_relationship_type, target_ref
    ):
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=self.shodan_identity["standard_id"],
        )

    @staticmethod
    def _generate_description(data):
        # Generate Services Desc Block
        services_desc = "Services:\n"
        for service in data["data"]:
            service_data = service["data"].strip()
            services_desc = (
                services_desc
                + f'\n**{str(service["port"])}:**\n```\n{service_data}\n```'
            )

            if "opts" in service:
                if "heartbleed" in service["opts"]:
                    services_desc = (
                        services_desc + f'\nHEARTBLEED: {service["opts"]["heartbleed"]}'
                    )
            services_desc = services_desc + "\n------------------"

        global_description = f"""
**ISP:** {data["isp"]}

**OS:** {str(data["os"]) if data["os"] is not None else "-"}

--------------------------
{services_desc}
"""
        return global_description

    def _generate_labels(self, data):
        entity_tags = data["tags"]
        # Create Labels
        for tag in entity_tags:
            self.helper.api.stix2.put_attribute_in_extension(
                self.stix_entity, STIX_EXT_OCTI_SCO, "labels", tag, True
            )
        return entity_tags

    @staticmethod
    def _generate_stix_external_reference(data):
        # Generate ExternalReference
        external_reference = stix2.ExternalReference(
            source_name="Shodan",
            url=f'https://www.shodan.io/host/{data["ip_str"]}',
            external_id=data["ip_str"],
            description=f'[{data["country_code"]}] [{data["region_code"]} - {data["city"]}] - {" ".join(data["hostnames"])}',
        )
        return external_reference

    def _generate_stix_identity(self, data):
        stix_organization_with_relationship = []
        organization = data["org"]
        if organization is not None and len(organization) > 0:
            # Generate Identity
            stix_organization = stix2.Identity(
                id=Identity.generate_id(organization, "organization"),
                name=organization,
                identity_class="organization",
                created_by_ref=self.shodan_identity["standard_id"],
            )
            self.stix_objects.append(stix_organization)
            stix_organization_with_relationship.append(stix_organization)

            # Generate Relationship : Observable -> "related-to" -> Organization
            observable_to_organization = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_organization.id
            )
            self.stix_objects.append(observable_to_organization)

    def _generate_stix_domain(self, data):
        entity_domains = data["domains"]
        for entity_domain in entity_domains:
            # Generate Domain
            stix_domain = stix2.DomainName(
                type="domain-name",
                value=entity_domain,
                custom_properties={
                    "x_opencti_created_by_ref": self.shodan_identity["standard_id"],
                    "x_opencti_score": self.score,
                },
            )
            self.stix_objects.append(stix_domain)
            # Generate Relationship : observable -> "related-to" -> domain
            observable_to_domain = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_domain.id
            )
            self.stix_objects.append(observable_to_domain)

    def _generate_stix_hostname(self, data):
        entity_hostnames = data["hostnames"]
        for entity_hostname in entity_hostnames:
            # Generate Hostname
            stix_hostname = CustomObservableHostname(
                value=entity_hostname,
                custom_properties={
                    "x_opencti_created_by_ref": self.shodan_identity["standard_id"],
                    "x_opencti_score": self.score,
                },
            )
            self.stix_objects.append(stix_hostname)
            # Generate Relationship : observable -> "related-to -> hostname
            observable_to_hostname = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_hostname.id
            )
            self.stix_objects.append(observable_to_hostname)

    def _generate_stix_asn(self, data):
        if "asn" in data and data["asn"] is not None and len(data["asn"]) > 0:
            # Generate Asn
            entity_asn = data["asn"]
            asn_number = int(data["asn"].replace("AS", ""))
            stix_asn = stix2.AutonomousSystem(
                type="autonomous-system",
                number=asn_number,
                name=entity_asn,
                custom_properties={
                    "x_opencti_created_by_ref": self.shodan_identity["standard_id"],
                    "x_opencti_score": self.score,
                },
            )
            self.stix_objects.append(stix_asn)
            # Generate Relationship : observable -> "belongs-to" -> Asn
            observable_to_asn = self._generate_stix_relationship(
                self.stix_entity["id"], "belongs-to", stix_asn.id
            )
            self.stix_objects.append(observable_to_asn)

    def _generate_stix_x509(self, data):
        for item in data["data"]:
            if "ssl" in item:
                ssl_object = item["ssl"]
                issued: datetime = datetime.strptime(
                    ssl_object["cert"]["issued"], "%Y%m%d%H%M%SZ"
                )
                expires: datetime = datetime.strptime(
                    ssl_object["cert"]["expires"], "%Y%m%d%H%M%SZ"
                )

                issuer = ", ".join(
                    (f"{k}={v}" for k, v in ssl_object["cert"]["issuer"].items())
                )
                subject = ", ".join(
                    (f"{k}={v}" for k, v in ssl_object["cert"]["subject"].items())
                )
                validity_not_before = issued.isoformat().split(".")[0] + "Z"
                validity_not_after = expires.isoformat().split(".")[0] + "Z"
                serial_number = ":".join(
                    [
                        str(ssl_object["cert"]["serial"])[i : i + 2]
                        for i in range(0, len(str(ssl_object["cert"]["serial"])), 2)
                    ]
                )
                signature_algorithm = ssl_object["cert"]["sig_alg"]
                subject_public_key_algorithm = ssl_object["cert"]["pubkey"]["type"]
                hashes = {
                    "SHA-256": ssl_object["cert"]["fingerprint"]["sha256"],
                    "SHA-1": ssl_object["cert"]["fingerprint"]["sha1"],
                }
                version = str(ssl_object["cert"]["version"])

                # Generate X509 certificate
                stix_x509 = stix2.X509Certificate(
                    type="x509-certificate",
                    issuer=issuer,
                    validity_not_before=validity_not_before,
                    validity_not_after=validity_not_after,
                    subject=subject,
                    serial_number=serial_number,
                    signature_algorithm=signature_algorithm,
                    subject_public_key_algorithm=subject_public_key_algorithm,
                    hashes=hashes,
                    version=version,
                    custom_properties={
                        "x_opencti_created_by_ref": self.shodan_identity["standard_id"]
                    },
                )
                self.stix_objects.append(stix_x509)
                # Generate Relationship : observable -> "related-to" -> x509
                observable_to_x509 = self._generate_stix_relationship(
                    self.stix_entity["id"], "related-to", stix_x509.id
                )
                self.stix_objects.append(observable_to_x509)

    def _generate_stix_location(self, data):
        # Generate City Location
        stix_city_location = stix2.Location(
            id=Location.generate_id(data["city"], "City"),
            name=data["city"],
            country=data["country_name"],
            latitude=data["latitude"],
            longitude=data["longitude"],
            custom_properties={"x_opencti_location_type": "City"},
        )
        self.stix_objects.append(stix_city_location)
        # Generate Relationship : observable -> "located-at" -> city
        observable_to_city = self._generate_stix_relationship(
            self.stix_entity["id"], "located-at", stix_city_location.id
        )
        self.stix_objects.append(observable_to_city)
        # Generate Country Location
        stix_country_location = stix2.Location(
            id=Location.generate_id(data["country_name"], "Country"),
            name=data["country_name"],
            country=data["country_name"],
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [data["country_code"]],
            },
        )
        self.stix_objects.append(stix_country_location)
        # Generate Relationship : city -> "located-at" -> country
        city_to_country = self._generate_stix_relationship(
            stix_city_location.id, "located-at", stix_country_location.id
        )
        self.stix_objects.append(city_to_country)

    def _generate_stix_vulnerability(self, data):
        if "vulns" in data:
            entity_vulns = data["vulns"]
            for vuln in entity_vulns:
                # Generate Vulnerability
                stix_vulnerability = stix2.Vulnerability(
                    id=Vulnerability.generate_id(vuln),
                    name=vuln,
                    created_by_ref=self.shodan_identity["standard_id"],
                    allow_custom=True,
                )
                self.stix_objects.append(stix_vulnerability)
                # Generate Relationship : observable -> "related-to" -> vulnerability
                observable_to_vulnerability = self._generate_stix_relationship(
                    self.stix_entity["id"], "related-to", stix_vulnerability.id
                )
                self.stix_objects.append(observable_to_vulnerability)

    def _upsert_stix_observable(self, description, labels, external_reference):
        # Upsert Observable
        stix_observable = stix2.IPv4Address(
            id=self.stix_entity["id"],
            type="ipv4-addr",
            value=self.stix_entity["value"],
            custom_properties={
                "x_opencti_external_references": [external_reference],
                "x_opencti_description": description,
                "x_opencti_score": self.score,
                "x_opencti_labels": labels,
                "x_opencti_created_by_ref": self.shodan_identity["standard_id"],
            },
        )
        self.stix_objects.append(stix_observable)
        """
        {
                    "source_name": "Shodan",
                    "url": f"www.shodan.io/host/{data['ip_str']}",
                    "description": "ceci est une description",
                    # "external_id": str(data['ip_str']),
                }
        """
        return stix_observable

    def _generate_stix_bundle(
        self, data, stix_objects, stix_entity, score=None, only_objects=False
    ):
        if score is not None:
            self.score = score
        else:
            self.score = self.default_score
        self.stix_objects = stix_objects
        self.stix_entity = stix_entity

        # Generate Stix Object for bundle
        description = self._generate_description(data)
        labels = self._generate_labels(data)
        external_reference = self._generate_stix_external_reference(data)

        self._generate_stix_identity(data)
        self._generate_stix_domain(data)
        self._generate_stix_hostname(data)
        self._generate_stix_asn(data)
        self._generate_stix_x509(data)
        self._generate_stix_location(data)  # City + Country
        self._generate_stix_vulnerability(data)
        self._upsert_stix_observable(description, labels, external_reference)

        uniq_bundles_objects = list(
            {obj["id"]: obj for obj in self.stix_objects}.values()
        )
        if only_objects:
            return uniq_bundles_objects
        return self.helper.stix2_create_bundle(uniq_bundles_objects)

    def _process_message(self, data: Dict):
        # OpenCTI entity information retrieval
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        """
        Extract TLP and we check if the variable "max_tlp" is less than 
        or equal to the markings access of the entity. 
        If this is true, we can send the data to connector for enrichment.
        """
        self._extract_and_check_markings(opencti_entity)

        # Extract Value from opencti entity data
        if stix_entity["type"] == "ipv4-addr":
            ip_value = stix_entity["value"]
            try:
                # Get Shodan API Response
                response = self.shodanAPI.host(ip_value)

                # Generate a stix bundle
                bundle = self._generate_stix_bundle(response, stix_objects, stix_entity)

                # send stix2 bundle
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"
            except shodan.APIError as e:
                # Handling specific errors for Shodan API
                raise ValueError(f"Shodan API Error : {str(e)}")
            except Exception as e:
                return self.helper.log_error(f"Unexpected Error occurred: {str(e)}")
        elif (
            stix_entity["type"] == "indicator"
            and stix_entity["pattern_type"] == "shodan"
        ):
            if "x_opencti_score" in stix_entity:
                score = stix_entity["x_opencti_score"]
            else:
                score = self.helper.get_attribute_in_extension("score", stix_entity)
            pattern_value = stix_entity["pattern"]
            threats = []
            # Resolve indicates
            relationships = self.helper.api.stix_core_relationship.list(
                relationship_type="indicates", fromId=opencti_entity["id"]
            )
            for relationship in relationships:
                indicates_stix_entity = (
                    self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                        entity_type=relationship["to"]["entity_type"],
                        entity_id=relationship["to"]["id"],
                        only_entity=True,
                    )
                )
                threats.append(indicates_stix_entity)
            try:
                bundle_objects = []
                number_processed = 1
                # Facets
                result = self.shodanAPI.count(pattern_value, facets=FACETS)
                note_title = "Shodan Summary Information"
                note_content = "### Global\n"
                note_content += "| Value | Count |\n|------|-------|\n"
                note_content += "| Total Results |" + str(result["total"]) + " |\n"
                for facet in result["facets"]:
                    note_content += "### " + FACET_TITLES[facet] + "\n\n"
                    note_content += "| Value | Count |\n|------|-------|\n"
                    for term in result["facets"][facet]:
                        note_content += (
                            "| "
                            + str(term["value"])
                            + " |"
                            + str(term["count"])
                            + " |\n"
                        )
                    note_content += "\n"
                created = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                note = stix2.Note(
                    id=Note.generate_id(created, note_content),
                    abstract=note_title,
                    content=note_content,
                    created_by_ref=self.shodan_identity["standard_id"],
                    object_refs=[stix_entity["id"]],
                )
                bundle_objects.append(note)

                # Get Shodan API Response
                if self.import_search_results:
                    results = self.shodanAPI.search_cursor(pattern_value)
                    for result in results:
                        stix_entity_ip = json.loads(
                            stix2.IPv4Address(
                                type="ipv4-addr", value=result["ip_str"]
                            ).serialize()
                        )
                        stix_objects.append(stix_entity_ip)
                        rel = self._generate_stix_relationship(
                            stix_entity_ip["id"], "related-to", stix_entity["id"]
                        )
                        stix_objects.append(rel)
                        for threat in threats:
                            rel = self._generate_stix_relationship(
                                stix_entity_ip["id"], "related-to", threat["id"]
                            )
                            stix_objects.append(rel)

                        response = self.shodanAPI.host(result["ip_str"])

                        # Generate a stix bundle
                        bundle_objects = bundle_objects + self._generate_stix_bundle(
                            response, stix_objects, stix_entity_ip, score, True
                        )
                        number_processed = number_processed + 1

                # send stix2 bundle
                uniq_bundles_objects = list(
                    {obj["id"]: obj for obj in bundle_objects}.values()
                )
                bundle = self.helper.stix2_create_bundle(uniq_bundles_objects)
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                self.helper.log_info(
                    str(number_processed)
                    + " processed items, "
                    + str(len(bundles_sent))
                    + " generated bundle(s)"
                )
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"
            except shodan.APIError as e:
                # Handling specific errors for Shodan API
                raise ValueError(f"Shodan API Error : {str(e)}")
            except Exception as e:
                return self.helper.log_error(f"Unexpected Error occurred: {str(e)}")
        else:
            if stix_entity["type"] == "indicator":
                raise ValueError(
                    "Unsupported pattern type: " + stix_entity["pattern_type"]
                )
            else:
                raise ValueError("Unsupported type: " + stix_entity["type"])

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    ShodanInstance = ShodanConnector()
    ShodanInstance.start()
