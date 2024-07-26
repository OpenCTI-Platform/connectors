import datetime
import json
import os
import sys
import time
from datetime import date, timedelta

import requests
import stix2
import yaml
from pycti import (
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class Cisco_SMA:
    """Cisco_SMA connector"""

    def __init__(self):
        """Initializer"""

        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config_file_path = config_file_path.replace("\\", "/")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.stix_domain = []

        # Extra config
        self.ioc_score = get_config_variable(
            "CISCO_SMA_IOC_SCORE",
            ["cisco_sma", "ioc_score"],
            config,
            isNumber=True,
            default=50,
        )

        self.cisco_sma_api_key = get_config_variable(
            "CISCO_SMA_API_KEY",
            ["cisco_sma", "api_key"],
            config,
        )
        self.cisco_sma_interval = get_config_variable(
            "CISCO_SMA_INTERVAL",
            ["cisco_sma", "interval"],
            config,
            isNumber=True,
            default=24,
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            default=False,
        )
        self.cisco_sma_url = get_config_variable(
            "CISCO_SMA_URL",
            ["cisco_sma", "url"],
            config,
            default="https://panacea.threatgrid.eu/api/v3/feeds/",
        )
        self.cisco_sma_autorun_registry = get_config_variable(
            "CISCO_SMA_AUTORUN_REGISTRY",
            ["cisco_sma", "autorun-registry"],
            config,
            default=False,
        )
        self.cisco_sma_banking_dns = get_config_variable(
            "CISCO_SMA_BANKING_DNS",
            ["cisco_sma", "banking-dns"],
            config,
            default=False,
        )
        self.cisco_sma_dga_dns = get_config_variable(
            "CISCO_SMA_DGA_DNS",
            ["cisco_sma", "dga-dns"],
            config,
            default=False,
        )
        self.cisco_sma_dll_hijacking_dns = get_config_variable(
            "CISCO_SMA_DLL_HIJACKING_DNS",
            ["cisco_sma", "dll-hijacking-dns"],
            config,
            default=False,
        )
        self.cisco_sma_doc_net_com_dns = get_config_variable(
            "CISCO_SMA_DOC_NET_COM_DNS",
            ["cisco_sma", "doc-net-com-dns"],
            config,
            default=False,
        )
        self.cisco_sma_downloaded_pe_dns = get_config_variable(
            "CISCO_SMA_DOWNLOADED_PE_DNS",
            ["cisco_sma", "downloaded-pe-dns"],
            config,
            default=False,
        )
        self.cisco_sma_dynamic_dns = get_config_variable(
            "CISCO_SMA_DYNAMIC_DNS",
            ["cisco_sma", "dynamic-dns"],
            config,
            default=False,
        )
        self.cisco_sma_irc_dns = get_config_variable(
            "CISCO_SMA_IRC_DNS",
            ["cisco_sma", "irc-dns"],
            config,
            default=False,
        )
        self.cisco_sma_modified_hosts_dns = get_config_variable(
            "CISCO_SMA_MODIFIED_HOSTS_DNS",
            ["cisco_sma", "modified-hosts-dns"],
            config,
            default=False,
        )
        self.cisco_sma_parked_dns = get_config_variable(
            "CISCO_SMA_PARKED_DNS",
            ["cisco_sma", "parked-dns"],
            config,
            default=False,
        )
        self.cisco_sma_public_ip_check_dns = get_config_variable(
            "CISCO_SMA_PUBLIC_IP_CHECK_DNS",
            ["cisco_sma", "public-ip-check-dns"],
            config,
            default=False,
        )
        self.cisco_sma_ransomware_dns = get_config_variable(
            "CISCO_SMA_RANSOMWARE_DNS",
            ["cisco_sma", "ransomware-dns"],
            config,
            default=True,
        )
        self.cisco_sma_rat_dns = get_config_variable(
            "CISCO_SMA_RAT_DNS",
            ["cisco_sma", "rat-dns"],
            config,
            default=True,
        )
        self.cisco_sma_scheduled_tasks = get_config_variable(
            "CISCO_SMA_SCHEDULED_TASKS",
            ["cisco_sma", "scheduled-tasks"],
            config,
            default=False,
        )
        self.cisco_sma_sinkholed_ip_dns = get_config_variable(
            "CISCO_SMA_SINKHOLED_IP_DNS",
            ["cisco_sma", "sinkholed-ip-dns"],
            config,
            default=False,
        )
        self.cisco_sma_stolen_cert_dns = get_config_variable(
            "CISCO_SMA_STOLEN_CERT_DNS",
            ["cisco_sma", "stolen-cert-dns"],
            config,
            default=False,
        )
        self.cisco_sma_marking = get_config_variable(
            "CISCO_SMA_MARKING",
            ["cisco_sma", "marking_definition"],
            config,
            default="TLP:AMBER",
        )

    def set_marking(self):
        if (
            self.cisco_sma_marking == "TLP:WHITE"
            or self.cisco_sma_marking == "TLP:CLEAR"
        ):
            marking = stix2.TLP_WHITE
        elif self.cisco_sma_marking == "TLP:GREEN":
            marking = stix2.TLP_GREEN
        elif self.cisco_sma_marking == "TLP:AMBER":
            marking = stix2.TLP_AMBER
        elif self.cisco_sma_marking == "TLP:RED":
            marking = stix2.TLP_RED
        else:
            marking = stix2.TLP_AMBER

        self.cisco_sma_marking = marking

    def cisco_sma_api_get(self):
        try:
            today_date = date.today()
            current_date = (today_date - timedelta(days=1)).strftime("%Y-%m-%d")
            cisco_sma_result = []
            true_attributes = [
                attr[1]
                for attr, value in [
                    (
                        ["cisco_sma", "autorun-registry"],
                        self.cisco_sma_autorun_registry,
                    ),
                    (["cisco_sma", "banking-dns"], self.cisco_sma_banking_dns),
                    (["cisco_sma", "dga-dns"], self.cisco_sma_dga_dns),
                    (
                        ["cisco_sma", "dll-hijacking-dns"],
                        self.cisco_sma_dll_hijacking_dns,
                    ),
                    (["cisco_sma", "doc-net-com-dns"], self.cisco_sma_doc_net_com_dns),
                    (
                        ["cisco_sma", "downloaded-pe-dns"],
                        self.cisco_sma_downloaded_pe_dns,
                    ),
                    (["cisco_sma", "dynamic-dns"], self.cisco_sma_dynamic_dns),
                    (["cisco_sma", "irc-dns"], self.cisco_sma_irc_dns),
                    (
                        ["cisco_sma", "modified-hosts-dns"],
                        self.cisco_sma_modified_hosts_dns,
                    ),
                    (["cisco_sma", "parked-dns"], self.cisco_sma_parked_dns),
                    (
                        ["cisco_sma", "public-ip-check-dns"],
                        self.cisco_sma_public_ip_check_dns,
                    ),
                    (["cisco_sma", "ransomware-dns"], self.cisco_sma_ransomware_dns),
                    (["cisco_sma", "rat-dns"], self.cisco_sma_rat_dns),
                    (["cisco_sma", "scheduled-tasks"], self.cisco_sma_scheduled_tasks),
                    (
                        ["cisco_sma", "sinkholed-ip-dns"],
                        self.cisco_sma_sinkholed_ip_dns,
                    ),
                    (["cisco_sma", "stolen-cert-dns"], self.cisco_sma_stolen_cert_dns),
                ]
                if value
            ]
            for category in true_attributes:
                url = f"{self.cisco_sma_url}{category}_{current_date}.json?api_key={self.cisco_sma_api_key}"
                response = requests.get(url, verify=False, timeout=(20000, 20000))
                r_json_raw = response.json()
                r_json = json.dumps(r_json_raw, indent=4)
                cisco_sma_result.append(r_json)
            return cisco_sma_result, true_attributes
        except Exception as e:
            self.helper.log_error(
                f"Error while getting intelligence from Cisco_SMA: {e}"
            )

    def create_stix_object(self, domain, description, label, identity_id):
        pattern = f"[domain-name:value = '{domain}']"
        observable_type = "Domain-Name"
        name = domain
        observable = stix2.DomainName(
            value=name,
            object_marking_refs=[self.cisco_sma_marking],
            custom_properties={
                "x_opencti_score": self.ioc_score,
                "x_opencti_description": description,
            },
        )
        self.stix_domain.append(observable)

        if pattern:
            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=name,
                pattern=pattern,
                pattern_type="stix",
                description=description,
                created_by_ref=identity_id,
                labels=label,
                object_marking_refs=[self.cisco_sma_marking],
                custom_properties={
                    "x_opencti_score": self.ioc_score,
                    "x_opencti_main_observable_type": observable_type,
                },
            )

            self.stix_domain.append(indicator)

            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", indicator["id"], observable["id"]
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=identity_id,
                object_marking_refs=[self.cisco_sma_marking],
            )
            self.stix_domain.append(relationship)

    def create_stix_bundle(self, data, true_attributes):
        identity_id = "identity--a798ea4a-e656-5a8b-989e-960419abb1fc"
        identity = stix2.Identity(
            id=identity_id,
            spec_version="2.1",
            name="Cisco SMA",
            confidence=100,
            identity_class="organization",
            type="identity",
            object_marking_refs=stix2.TLP_WHITE,
        )

        k = 0
        self.stix_domain.append(identity)
        for i in data:
            if len(i) > 2:
                json_data = json.loads(i)
                domain_list = [item["domain"] for item in json_data]
                description = [item["description"] for item in json_data][0]
                label = true_attributes[k]
                for domain in domain_list:
                    self.create_stix_object(domain, description, label, identity_id)
                k = k + 1
            else:
                k = k + 1

        bundle = stix2.Bundle(
            objects=self.stix_domain,
            allow_custom=True,
        )
        return bundle

    def opencti_bundle(self, work_id):
        data, true_attributes = self.cisco_sma_api_get()
        stix_bundle = self.create_stix_bundle(data, true_attributes)
        bundle_dict = json.loads(str(stix_bundle))
        bundle_dict = json.dumps(bundle_dict, indent=4)
        self.helper.send_stix2_bundle(
            bundle_dict, update=self.update_existing_data, work_id=work_id
        )

    def send_bundle(self, work_id, serialized_bundle: str):
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")

    def process_data(self):
        try:
            self.helper.log_info("Synchronizing with Cisco_SMA APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            friendly_name = "Cisco_SMA run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            if current_state is None:
                self.helper.set_state(
                    {"last_run": str(now.strftime("%Y-%m-%d %H:%M:%S"))}
                )
            current_state = self.helper.get_state()
            self.helper.log_info("Get IOC since " + current_state["last_run"])
            self.opencti_bundle(work_id)
            self.helper.set_state({"last_run": now.astimezone().isoformat()})
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching Cisco_SMA datasets...")
        self.set_marking()
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.cisco_sma_interval * 60 * 60)


if __name__ == "__main__":
    try:
        cisco_sma_Connector = Cisco_SMA()
        cisco_sma_Connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
