import yaml
import os
import shodan
from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable


class ShodanConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.token = get_config_variable("SHODAN_TOKEN", ["shodan", "token"], config)
        self.max_tlp = get_config_variable(
            "SHODAN_MAX_TLP", ["shodan", "max_tlp"], config
        )
        self.shodanAPI = shodan.Shodan(self.token)

    def _generate_host_description(self, shodanHostResponse):
        # Generate Hostname Desc Block
        Hostnames = "Hostnames:"
        for host in shodanHostResponse["hostnames"]:
            Hostnames = Hostnames + f"\n  - {host}"

        # Generate Domain Desc Block
        Domains = "Domains:"
        for domain in shodanHostResponse["domains"]:
            Domains = Domains + f"\n  - {domain}"

        # Generate Services Desc Block
        Services = "Services:\n"
        for service in shodanHostResponse["data"]:
            serviceData = service["data"].strip()
            Services = (
                Services + f'\n**{str(service["port"])}:**\n```\n{serviceData}\n```'
            )

            if "opts" in service:
                print(service["opts"])
                if "heartbleed" in service["opts"]:
                    Services = (
                        Services + f'\nHEARTBLEED: {service["opts"]["heartbleed"]}'
                    )
            Services = Services + "\n------------------"

        # Create the description for the Observable
        Observable_Description = f"""
**ORG:** {shodanHostResponse["org"]}

**ISP:** {shodanHostResponse["isp"]}

**OS:** {str(shodanHostResponse["os"])}

--------------------------
{Hostnames}

--------------------------
{Domains}

--------------------------
{Services}
        """
        return Observable_Description

    def _generate_x509(self, shodanHostResponse):
        x509s = []

        for service in shodanHostResponse["data"]:
            if "ssl" in service:
                sslObject = service["ssl"]

                issued: datetime = datetime.strptime(
                    sslObject["cert"]["issued"], "%Y%m%d%H%M%SZ"
                )
                expires: datetime = datetime.strptime(
                    sslObject["cert"]["expires"], "%Y%m%d%H%M%SZ"
                )

                x509 = self.helper.api.stix_cyber_observable.create(
                    observableData={
                        "type": "x509-certificate",
                        "issuer": ", ".join(
                            (
                                f"{k}={v}"
                                for k, v in sslObject["cert"]["subject"].items()
                            )
                        ),
                        "validity_not_before": issued.isoformat().split(".")[0] + "Z",
                        "validity_not_after": expires.isoformat().split(".")[0] + "Z",
                        "subject": ", ".join(
                            (f"{k}={v}" for k, v in sslObject["cert"]["issuer"].items())
                        ),
                        "serial_number": ":".join(
                            [
                                str(sslObject["cert"]["serial"])[i : i + 2]
                                for i in range(
                                    0, len(str(sslObject["cert"]["serial"])), 2
                                )
                            ]
                        ),
                        # "version": str(sslObject["cert"]["version"]),
                        "hashes": {
                            "sha256": sslObject["cert"]["fingerprint"]["sha256"],
                            "sha1": sslObject["cert"]["fingerprint"]["sha1"],
                        },
                        "signature_algorithm": sslObject["cert"]["sig_alg"],
                        "subject_public_key_algorithm": sslObject["cert"]["pubkey"][
                            "type"
                        ],
                    },
                    update=True,
                )
                x509s.append(x509)
        return x509s

    def _generate_domains(self, shodanHostResponse):
        domains = []

        for domain in shodanHostResponse["domains"]:

            domainX = self.helper.api.stix_cyber_observable.create(
                observableData={
                    "type": "domain-name",
                    "value": domain,
                },
                update=True,
            )
            domains.append(domainX)
        return domains

    def _convert_shodan_to_stix(self, shodanHostResponse, observable):

        # --------------------------------------------------------------------
        #  Helpers
        # --------------------------------------------------------------------

        # Now
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        # Pull Tags via API
        tags = shodanHostResponse["tags"]

        # Create tags
        for tag in shodanHostResponse["tags"]:
            tag_shodan = self.helper.api.label.create(value=tag)
            self.helper.api.stix_cyber_observable.add_label(
                id=observable["id"], label_id=tag_shodan["id"]
            )

        # Create description
        Description = self._generate_host_description(shodanHostResponse)

        x509s = self._generate_x509(shodanHostResponse)
        domains = self._generate_domains(shodanHostResponse)

        # Create ASN Helper Object
        ASNumber = int(shodanHostResponse["asn"].replace("AS", ""))
        asn = self.helper.api.stix_cyber_observable.create(
            observableData={
                "type": "autonomous-system",
                "number": ASNumber,
                "name": shodanHostResponse["asn"],
            },
            update=True,
            objectLabel=tags,
        )

        # --------------------------------------------------------------------
        #  STIX Objects
        # --------------------------------------------------------------------

        # Create Indicator
        final_indicator = self.helper.api.indicator.create(
            name=shodanHostResponse["ip_str"],
            description=Description,
            pattern_type="stix",
            pattern=f"[ipv4-addr:value = '{shodanHostResponse['ip_str']}']",
            x_opencti_main_observable_type="IPv4-Addr",
            valid_from=now,
            update=True,
            objectLabel=tags,
            confidence=self.helper.connect_confidence_level,
            x_opencti_detection=True,
        )

        # Update the current observable
        final_observable = self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"], key="x_opencti_description", value=Description
        )
        for tag in tags:
            self.helper.api.stix_cyber_observable.add_label(
                id=observable["id"], label_name=tag
            )

        # --------------------------------------------------------------------
        #  Relationships
        # --------------------------------------------------------------------

        # Link Indicator to Observable
        self.helper.api.stix_core_relationship.create(
            fromId=final_indicator["id"],
            toId=observable["id"],
            relationship_type="based-on",
            update=True,
            confidence=self.helper.connect_confidence_level,
        )
        # Link ASN to Observable
        self.helper.api.stix_cyber_observable_relationship.create(
            fromId=final_observable["id"],
            toId=asn["id"],
            relationship_type="obs_belongs-to",
            update=True,
            confidence=self.helper.connect_confidence_level,
        )
        # Link x509 to Observable
        for x509 in x509s:
            self.helper.api.stix_core_relationship.create(
                fromId=observable["id"],
                toId=x509["id"],
                relationship_type="related-to",
                update=True,
                confidence=self.helper.connect_confidence_level,
            )

        # Link Domains to Observable
        for domain in domains:
            self.helper.api.stix_cyber_observable_relationship.create(
                fromId=domain["id"],
                toId=observable["id"],
                relationship_type="resolves-to",
                update=True,
                confidence=self.helper.connect_confidence_level,
            )

        # --------------------------------------------------------------------
        #  References
        # --------------------------------------------------------------------

        # Create external reference to shodan
        external_reference = self.helper.api.external_reference.create(
            source_name="Shodan",
            url="https://shodan.io/host/" + shodanHostResponse["ip_str"],
            description=f'[{shodanHostResponse["country_code"]}] [{shodanHostResponse["region_code"]} - {shodanHostResponse["city"]}] - {" ".join(shodanHostResponse["hostnames"])}',
        )

        self.helper.api.stix_cyber_observable.add_external_reference(
            id=final_observable["id"],
            external_reference_id=external_reference["id"],
        )

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        # Extract IP from entity data
        observable_value = observable["value"]

        # Get Shodan API Response
        try:
            response = self.shodanAPI.host(observable_value)
        except Exception as e:
            return str(e)

        # Process and send Shodan Data to OpenCTI
        self._convert_shodan_to_stix(response, observable)

        return "[SUCCESS] Shodan IP Found, data sent in"

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    ShodanInstance = ShodanConnector()
    ShodanInstance.start()
