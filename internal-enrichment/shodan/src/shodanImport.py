import os
from datetime import datetime, timedelta

import shodan
import yaml
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
        self.create_indicators = get_config_variable(
            "SHODAN_CREATE_INDICATORS",
            ["shodan", "create_indicators"],
            config,
            False,
            True,
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

    def _generate_vulns(self, shodanHostResponse):
        vulns = []

        if not "vulns" in shodanHostResponse:
            return []

        for vuln in shodanHostResponse["vulns"]:
            vulnX = self.helper.api.vulnerability.create(name=vuln)

            vulns.append(vulnX)
        return vulns

    def _generate_identity(self, shodanHostResponse):
        org = shodanHostResponse["org"]
        orgFound = False
        for orgX in self.helper.api.identity.list():  # Get Orgs and attampt match
            if orgX["entity_type"] == "Organization":
                orgX["name"] == org  # Match fuzzy name
                if orgX["name"] == org:
                    return orgX

        if not orgFound:
            orgX = self.helper.api.identity.create(
                type="Organization",
                name=org,
                Description=org,
            )
        return orgX

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
        vulns = self._generate_vulns(shodanHostResponse)
        org = self._generate_identity(shodanHostResponse)

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

        # Update the current observable
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"],
            input={"key": "x_opencti_description", "value": Description},
        )
        for tag in tags:
            self.helper.api.stix_cyber_observable.add_label(
                id=observable["id"], label_name=tag
            )

        # --------------------------------------------------------------------
        #  Relationships
        # --------------------------------------------------------------------

        # Link Observable to Identity
        self.helper.api.stix_core_relationship.create(
            fromId=observable["id"],
            toId=org["id"],
            relationship_type="related-to",
            update=True,
            confidence=self.helper.connect_confidence_level,
        )

        # Create Indicator
        if self.create_indicators:
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
            fromId=observable["id"],
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
                relationship_type="obs_resolves-to",
                update=True,
                confidence=self.helper.connect_confidence_level,
            )

        # Link Vulns to Observable
        VulnEOL = datetime.now() + timedelta(days=60)
        for vuln in vulns:
            self.helper.api.stix_core_relationship.create(
                fromId=observable["id"],
                toId=vuln["id"],
                relationship_type="related-to",
                update=True,
                start_time=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                stop_time=VulnEOL.strftime("%Y-%m-%dT%H:%M:%SZ"),
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
            id=observable["id"],
            external_reference_id=external_reference["id"],
        )

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, check the group of the connector user)"
            )
        TLPs = ["TLP:WHITE"]
        if "objectMarking" in observable:
            for marking_definition in observable["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    TLPs.append(marking_definition["definition"])

        for TLPx in TLPs:
            if not OpenCTIConnectorHelper.check_max_tlp(TLPx, self.max_tlp):
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
