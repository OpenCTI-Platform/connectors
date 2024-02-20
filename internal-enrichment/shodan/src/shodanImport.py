import os
from datetime import datetime

import shodan
import stix2
import yaml
from pycti import (
    STIX_EXT_OCTI_SCO,
    CustomObservableHostname,
    Identity,
    Indicator,
    Location,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
    get_config_variable,
)


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
            "SHODAN_MAX_TLP", ["shodan", "max_tlp"], config
        )
        self.create_indicators = get_config_variable(
            "SHODAN_CREATE_INDICATORS",
            ["shodan", "create_indicators"],
            config,
            False,
            True,
        )
        self.shodanAPI = shodan.Shodan(self.token)
        self.default_score = get_config_variable(
            "SHODAN_DEFAULT_SCORE", ["shodan", "default_score"]
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
        stix_organization_with_relationship.append(observable_to_organization)

        return stix_organization_with_relationship

    def _generate_stix_domain(self, data):
        stix_domains_with_relationship = []
        entity_domains = data["domains"]

        for entity_domain in entity_domains:
            # Generate Domain
            stix_domain = stix2.DomainName(
                type="domain-name",
                value=entity_domain,
                custom_properties={
                    "created_by_ref": self.shodan_identity["standard_id"],
                    "x_opencti_score": self.default_score,
                },
            )
            self.stix_objects.append(stix_domain)
            stix_domains_with_relationship.append(stix_domain)

            # Generate Relationship : observable -> "related-to" -> domain
            observable_to_domain = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_domain.id
            )
            self.stix_objects.append(observable_to_domain)
            stix_domains_with_relationship.append(observable_to_domain)

        return stix_domains_with_relationship

    def _generate_stix_hostname(self, data):
        stix_hostnames_with_relationship = []
        entity_hostnames = data["hostnames"]

        for entity_hostname in entity_hostnames:
            # Generate Hostname
            stix_hostname = CustomObservableHostname(
                value=entity_hostname,
                custom_properties={
                    "created_by_ref": self.shodan_identity["standard_id"],
                    "x_opencti_score": self.default_score,
                },
            )
            self.stix_objects.append(stix_hostname)
            stix_hostnames_with_relationship.append(stix_hostname)

            # Generate Relationship : observable -> "related-to -> hostname
            observable_to_hostname = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_hostname.id
            )
            self.stix_objects.append(observable_to_hostname)
            stix_hostnames_with_relationship.append(observable_to_hostname)

        return stix_hostnames_with_relationship

    def _generate_stix_asn(self, data):
        stix_asn_with_relationship = []

        if "asn" in data:
            # Generate Asn
            entity_asn = data["asn"]
            asn_number = int(data["asn"].replace("AS", ""))
            stix_asn = stix2.AutonomousSystem(
                type="autonomous-system",
                number=asn_number,
                name=entity_asn,
                custom_properties={
                    "created_by_ref": self.shodan_identity["standard_id"],
                    "x_opencti_score": self.default_score,
                },
            )
            self.stix_objects.append(stix_asn)
            stix_asn_with_relationship.append(stix_asn)

            # Generate Relationship : observable -> "belongs-to" -> Asn
            observable_to_asn = self._generate_stix_relationship(
                self.stix_entity["id"], "belongs-to", stix_asn.id
            )
            self.stix_objects.append(observable_to_asn)
            stix_asn_with_relationship.append(observable_to_asn)

        return stix_asn_with_relationship

    def _generate_stix_x509(self, data):
        stix_x509s_with_relationship = []

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
                        "created_by_ref": self.shodan_identity["standard_id"]
                    },
                )
                self.stix_objects.append(stix_x509)
                stix_x509s_with_relationship.append(stix_x509)

                # Generate Relationship : observable -> "related-to" -> x509
                observable_to_x509 = self._generate_stix_relationship(
                    self.stix_entity["id"], "related-to", stix_x509.id
                )
                self.stix_objects.append(observable_to_x509)
                stix_x509s_with_relationship.append(observable_to_x509)

        return stix_x509s_with_relationship

    def _generate_stix_location(self, data):
        stix_locations_with_relationship = []

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
        stix_locations_with_relationship.append(stix_city_location)

        # Generate Relationship : observable -> "located-at" -> city
        observable_to_city = self._generate_stix_relationship(
            self.stix_entity["id"], "located-at", stix_city_location.id
        )
        self.stix_objects.append(observable_to_city)
        stix_locations_with_relationship.append(observable_to_city)

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
        stix_locations_with_relationship.append(stix_country_location)

        # Generate Relationship : city -> "located-at" -> country
        city_to_country = self._generate_stix_relationship(
            stix_city_location.id, "located-at", stix_country_location.id
        )
        self.stix_objects.append(city_to_country)
        stix_locations_with_relationship.append(city_to_country)

        return stix_locations_with_relationship

    def _generate_stix_vulnerability(self, data):
        stix_vulnerability_with_relationship = []

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
                stix_vulnerability_with_relationship.append(stix_vulnerability)

                # Generate Relationship : observable -> "related-to" -> vulnerability
                observable_to_vulnerability = self._generate_stix_relationship(
                    self.stix_entity["id"], "related-to", stix_vulnerability.id
                )
                self.stix_objects.append(observable_to_vulnerability)
                stix_vulnerability_with_relationship.append(observable_to_vulnerability)

            return stix_vulnerability_with_relationship
        else:
            return []

    def _generate_stix_indicator(self, data, description, tags, external_reference):
        stix_indicator_with_relationship = []
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Generate Indicator
        stix_indicator = stix2.Indicator(
            id=Indicator.generate_id(data["ip_str"]),
            name=data["ip_str"],
            description=description,
            labels=tags,
            pattern=f"[ipv4-addr:value = '{data['ip_str']}']",
            created_by_ref=self.shodan_identity["standard_id"],
            external_references=[external_reference],
            valid_from=now,
            custom_properties={
                "pattern_type": "stix",
                "x_opencti_score": self.default_score,
                "x_opencti_main_observable_type": "IPv4-Addr",
                "detection": True,
            },
        )
        self.stix_objects.append(stix_indicator)
        stix_indicator_with_relationship.append(stix_indicator)

        # Generate Relationship : Indicator -> "based-on" -> Observable
        indicator_to_observable = self._generate_stix_relationship(
            stix_indicator.id, "based-on", self.stix_entity["id"]
        )
        self.stix_objects.append(indicator_to_observable)
        stix_indicator_with_relationship.append(indicator_to_observable)

        return stix_indicator_with_relationship

    def _upsert_stix_observable(self, data, description, labels, external_reference):
        # Upsert Observable
        stix_observable = stix2.IPv4Address(
            id=self.stix_entity["id"],
            type="ipv4-addr",
            value=self.stix_entity["value"],
            custom_properties={
                "x_opencti_external_references": [external_reference],
                "x_opencti_description": description,
                "x_opencti_score": self.default_score,
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

    def _generate_stix_bundle(self, data, stix_objects, stix_entity):
        self.helper.log_info(
            f"IPv4 : '{stix_entity['value']}', has been identified by Shodan and generation of the Stix bundle is in progress."
        )

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

        self._generate_stix_indicator(data, description, labels, external_reference)
        self._upsert_stix_observable(data, description, labels, external_reference)

        uniq_bundles_objects = list(
            {obj["id"]: obj for obj in self.stix_objects}.values()
        )

        self.helper.log_info(
            f"IPv4 : '{stix_entity['value']}', {len(uniq_bundles_objects)} Stix bundle(s) will be enriched."
        )
        return self.helper.stix2_create_bundle(uniq_bundles_objects)

    def _process_message(self, data):
        # OpenCTI entity information retrieval
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["opencti_entity"]

        """
        Extract TLP and we check if the variable "max_tlp" is less than 
        or equal to the markings access of the entity. 
        If this is true, we can send the data to connector for enrichment.
        """
        self._extract_and_check_markings(opencti_entity)

        # Extract Value from opencti entity data
        opencti_entity_value = stix_entity["value"]

        try:
            # Get Shodan API Response
            response = self.shodanAPI.host(opencti_entity_value)

            # Generate a stix bundle
            bundle = self._generate_stix_bundle(response, stix_objects, stix_entity)

            # send stix2 bundle
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return (
                "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
            )

        except shodan.APIError as e:
            # Handling specific errors for Shodan API
            raise ValueError(f"Shodan API Error : {str(e)}")

        except Exception as e:
            # Handling other unexpected exceptions
            return self.helper.log_error(f"Unexpected Error occured : {str(e)}")

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message, auto_resolution=True)


if __name__ == "__main__":
    ShodanInstance = ShodanConnector()
    ShodanInstance.start()
