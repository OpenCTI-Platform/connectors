from pycti import OpenCTIApiClient, OpenCTIStix2Utils, OpenCTIConnectorHelper, get_config_variable
from stix2 import Bundle, Identity, Vulnerability, Infrastructure, Relationship
from typing import Dict
import requests
import datetime
import time
import os
import yaml


class CisaKev:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.cisa_data_feed = get_config_variable("CISA_DATA_FEED", ["cisa", "cisa_data_feed"], config)
        self.cisa_interval = get_config_variable("CISA_INTERVAL", ["cisa", "interval"], config, True)
        self.update_existing_data = get_config_variable("CONNECTOR_UPDATE_EXISTING_DATA", ["connector", "update_existing_data"], config,)
        self.tlp_mark = get_config_variable("CONNECTOR_TLP", ["connector", "tlp"], config, True)cd 
        self.created_by_stix = None
        self.tlp_marking = None
        self.org = "Cybersecurity and Infrastructure Security Agency"

    def get_interval(self):
        return int(self.cve_interval) * 60 * 60 * 24

    # Get Identity info
    def set_created_by_stix(self, org: str) -> Dict:
        opencti_api_client = OpenCTIApiClient(self.opencti_url, self.opencti_api)
        if org is None:
            org = self.org
        self.helper.log_info(f"Checking CTI Service for {org}")
        created_by_stix = opencti_api_client.identity.read(filters={"key": "name", "values": [f"{org}"]})
        if created_by_stix is None:
            self.helper.log_info(f"{org} not found in CTI Service. Building new STIX Object")
            org_stix_id = OpenCTIStix2Utils.generate_random_stix_id("identity")
            org_stix = Identity(
                type="identity",
                id=f"{org_stix_id}",
                identity_class="vendor",
                name=f"{org}",
                description="The Cybersecurity and Infrastructure Security Agency is a United States federal agency, an operational component under Department of Homeland Security oversight. Its activities are a continuation of the National Protection and Programs Directorate.",
                created_by_ref=f"{org_stix_id}")
            self.created_by_stix = org_stix
        else:
            self.helper.log_info(f"{org} found in CTI Service")
            type = "identity"
            id = created_by_stix['standard_id']
            name = created_by_stix['name']
            description = created_by_stix['description']
            org_stix = Identity(
                type=f"{type}",
                id=f"{id}",
                name=f"{name}",
                description=f"{description}",
                identity_class="vendor")
            self.created_by_stix = org_stix

    def create_relationship_obj(self, source_ref: str, target_ref: str) -> Relationship:
        relationship_stix = Relationship(
            relationship_type="has",
            source_ref=source_ref,
            target_ref=target_ref
        )
        return relationship_stix

    def set_tlp_marking(self, tlp_mark):
        opencti_api_client = OpenCTIApiClient(self.opencti_url, self.opencti_api)
        if tlp_mark is None:
            tlp_mark = self.tlp_mark
        marking = opencti_api_client.marking_definition.read(filters={"key": "definition", "values": [f"{tlp_mark}"]})
        self.tlp_marking = marking

    def process_data(self):
        opencti_api_client = OpenCTIApiClient(self.opencti_url, self.opencti_api)
        helper = OpenCTIConnectorHelper(self.config)
        self.set_created_by_stix(org=self.org)
        self.set_tlp_marking(tlp_mark=self.tlp_mark)
        try:
            # Get the current timestamp and check
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info("Connector last run: " + datetime.datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S"))
            else:
                last_run = None
                self.helper.log_info("Connector has never run")
            # If the last_run is more than interval-1 day
            if last_run is None or (
                (timestamp - last_run)
                > ((int(self.opencti_interval) - 1) * 60 * 60 * 24)
            ):
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = "CISA KEV datasets run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
            try:
                response = requests.get(self.cisa_data_feed, allow_redirects=True)
                catalog = response.json()
                for vuln in catalog["vulnerabilities"]:
                    bundle = {}
                    stix_objects = []
                    vuln_cve = vuln["cveID"]
                    vendor_name = vuln['vendorProject']
                    product = vuln['product']
                    description = vuln['shortDescription']
                    vuln_date = vuln['dateAdded']
                    created = f"{vuln_date}T00:00:00.000Z"
                    created_by_id = self.created_by_stix['id']
                    product_name = f"{vendor_name} {product}"
                    marking_id = self.tlp_marking['standard_id']

                    # check for existing CVE
                    cti_vuln = opencti_api_client.vulnerability.read(filters={"key": "name", "values": [f"{vuln_cve}"]})
                    self.helper.log_info(f"{vuln_cve} Found")
                    if cti_vuln is None:
                        vuln_id = OpenCTIStix2Utils.generate_random_stix_id("vulnerability")
                        stix_vuln = Vulnerability(
                            type="vulnerability",
                            id=f"{vuln_id}",
                            name=f"{vuln_cve}",
                            description=f"{description}",
                            created_by_ref=self.created_by_stix['id'],
                            created=f"{created}",
                            object_marking_refs=[f"{marking_id}"])
                        stix_objects.append(stix_vuln)
                    else:
                        vuln_id = cti_vuln['standard_id']
                        stix_vuln = Vulnerability(
                            type="vulnerability",
                            id=f"{vuln_id}",
                            name=f"{vuln_cve}",
                            created_by_ref=f"{created_by_id}",
                            created=f"{created}",
                            object_marking_refs=[f"{marking_id}"])
                        stix_objects.append(stix_vuln)

                    # Check for existing vendor
                    self.helper.log_info(f"Checking CTI Service for {vendor_name}")
                    cti_vendor = opencti_api_client.identity.read(filters={"key": "name", "values": [f"{vendor_name}"]})
                    if cti_vendor is None:
                        vendor_id = OpenCTIStix2Utils.generate_random_stix_id("identity")
                        stix_org = Identity(
                            type="identity",
                            identity_class="vendor",
                            id=f"{vendor_id}",
                            name=f"{vendor_name}",
                            description="Software Vendor",
                            created=f"{created}",
                            created_by_ref=f"{created_by_id}")
                        stix_objects.append(stix_org)
                    else:
                        self.helper.log_info(f"{vendor_name} was not found in the CTI Service")
                        vendor_id = cti_vendor['standard_id']
                        created = cti_vendor['created']
                        vendor_name = cti_vendor['name']
                        vendor_description = cti_vendor['description']
                        stix_org = Identity(
                            type="identity",
                            identity_class="vendor",
                            id=f"{vendor_id}",
                            name=f"{vendor_name}",
                            description=f"{vendor_description}",
                            created=f"{created}",
                            created_by_ref=f"{created_by_id}")
                        stix_objects.append(stix_org)
                        self.helper.log_info(f"STIX Object created for {vendor_name}")
                    # Check for CTI Infrastructure
                    product_name = f"{vendor_name} {product}"
                    if vendor_name in product:
                        product_name = f"{product}"
                    cti_infra = opencti_api_client.infrastructure.read(filters={"key": "name", "values": [f"{product_name}"]})
                    if cti_infra is None:
                        infra_id = OpenCTIStix2Utils.generate_random_stix_id("infrastructure")
                        stix_infrastructure = Infrastructure(
                            type="infrastructure",
                            id=f"{infra_id}",
                            name=f"{product_name}",
                            created=f"{created}",
                            created_by_ref=f"{created_by_id}")
                        stix_objects.append(stix_infrastructure)
                    else:
                        infra_id = cti_infra['standard_id']
                        stix_infrastructure = Infrastructure(
                            type="infrastructure",
                            id=f"{infra_id}",
                            name=f"{product_name}",
                            created=f"{created}",
                            created_by_ref=f"{created_by_id}")
                        stix_objects.append(stix_infrastructure)
                    infra_vuln_relationship = Relationship(relationship_type='has', source_ref=f"{infra_id}", target_ref=f"{vuln_id}")
                    stix_objects.append(infra_vuln_relationship)
                    bundle = Bundle(self.created_by_stix, stix_vuln, stix_org, stix_infrastructure, infra_vuln_relationship).serialize()
                    timestamp = int(time.time())
                    now = datetime.datetime.utcfromtimestamp(timestamp)
                    friendly_name = "CISA-KEV run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = helper.api.work.initiate_work(
                        helper.connect_id, friendly_name
                    )
                    helper.send_stix2_bundle(
                        bundle,
                        work_id=work_id,
                    )
            except Exception as e:
                self.helper.log_error(str(e))
                message = "Connector successfully run, storing last_run as " + str(timestamp)
                self.helper.log_info(message)
                self.helper.set_state({"last_run": timestamp})
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info("Last_run stored, next run in: " + str(round(self.get_interval() / 60 / 60 / 24, 2)) + " days")
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info("Connector will not run, next run in: " + str(round(new_interval / 60 / 60 / 24, 2)) + " days")
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching CISA Known Exploited Vulnerabilities...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = CisaKev()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
