import datetime
import json
import os
import sys
import time

import requests
import stix2
import yaml
from pycti import (
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class Infoblox:
    """Infoblox connector"""

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

        # Extra config
        self.infoblox_api_key = get_config_variable(
            "INFOBLOX_API_KEY",
            ["infoblox", "api_key"],
            config,
        )
        self.infoblox_interval = get_config_variable(
            "INFOBLOX_INTERVAL",
            ["infoblox", "interval"],
            config,
            isNumber=True,
            default=12,
        )
        self.infoblox_ioc_limit = get_config_variable(
            "INFOBLOX_IOC_LIMIT",
            ["infoblox", "ioc_limit"],
            config,
            default="10000",
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            default=False,
        )
        self.infoblox_url = get_config_variable(
            "INFOBLOX_URL",
            ["infoblox", "url"],
            config,
            default="https://csp.infoblox.com/tide/api/data/threats",
        )
        self.infoblox_marking = get_config_variable(
            "INFOBLOX_MARKING",
            ["infoblox", "marking_definition"],
            config,
            default="TLP:AMBER",
        )

    def set_marking(self):
        if self.infoblox_marking == "TLP:WHITE" or self.infoblox_marking == "TLP:CLEAR":
            marking = stix2.TLP_WHITE
        elif self.infoblox_marking == "TLP:GREEN":
            marking = stix2.TLP_GREEN
        elif self.infoblox_marking == "TLP:AMBER":
            marking = stix2.TLP_AMBER
        elif self.infoblox_marking == "TLP:RED":
            marking = stix2.TLP_RED
        else:
            marking = stix2.TLP_AMBER

        self.infoblox_marking = marking

    def infoblox_api_get(self):
        try:
            headers = {"Authorization": "Token {}".format(self.infoblox_api_key)}
            ioc_types = ["ip", "url", "host"]
            infoblox_result = []
            for ioc_type in ioc_types:

                url = f"{self.infoblox_url}?type={ioc_type}&period={self.infoblox_interval}h&profile=IID&dga=false&up=true&rlimit={self.infoblox_ioc_limit}"
                response = requests.get(
                    url, headers=headers, verify=True, timeout=(80000, 80000)
                )
                r_json = response.json()
                r_json1 = json.dumps(r_json, indent=4)
                infoblox_result.append(r_json1)
            return infoblox_result
        except Exception as e:
            self.helper.log_error(
                f"Error while getting intelligence from Infoblox: {e}"
            )

    def create_stix_object(self, threat, identity_id):
        object_type = threat["type"]
        stix_objects = []

        description = threat["extended"].get("notes")
        if description is None:
            self.helper.log_debug(f"Missing 'notes' key in threat: {threat}")
            description = ""

        if object_type == "URL":
            pattern = f"[url:value = '{threat['url']}']"
            observable_type = "Url"
            name = threat["url"]
            observable = stix2.URL(
                value=name,
                object_marking_refs=[self.infoblox_marking],
                custom_properties={
                    "x_opencti_score": threat["threat_level"],
                    "x_opencti_description": description,
                },
            )
            stix_objects.append(observable)

        elif object_type == "HOST":
            pattern = f"[domain-name:value = '{threat['domain']}']"
            observable_type = "Domain-Name"
            name = threat["domain"]
            observable = stix2.DomainName(
                value=name,
                object_marking_refs=[self.infoblox_marking],
                custom_properties={
                    "x_opencti_score": threat["threat_level"],
                    "x_opencti_description": description,
                },
            )
            stix_objects.append(observable)

        elif object_type == "IP":
            pattern = f"[ipv4-addr:value = '{threat['ip']}']"
            observable_type = "IPv4-Addr"
            name = threat["ip"]
            observable = stix2.IPv4Address(
                value=name,
                object_marking_refs=[self.infoblox_marking],
                custom_properties={
                    "x_opencti_score": threat["threat_level"],
                    "x_opencti_description": description,
                },
            )
            stix_objects.append(observable)

        else:
            self.helper.log_error(object_type + " is not supported as an object type.")
            return None

        if pattern:
            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=name,
                pattern=pattern,
                pattern_type="stix",
                description=description,
                created_by_ref=identity_id,
                created=datetime.datetime.strptime(
                    threat["detected"], "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                modified=datetime.datetime.strptime(
                    threat["imported"], "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                labels=[threat["class"], threat["property"]],
                confidence=threat["confidence"],
                object_marking_refs=[self.infoblox_marking],
                custom_properties={
                    "x_opencti_score": threat["threat_level"],
                    "x_opencti_main_observable_type": observable_type,
                },
            )

            stix_objects.append(indicator)

            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", indicator["id"], observable["id"]
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=identity_id,
                object_marking_refs=[self.infoblox_marking],
            )

            stix_objects.append(relationship)

            return stix_objects
        return None

    def create_stix_bundle(self, var_url, var_ip, var_domain):
        urls = []
        ips = []
        domains = []
        if var_url != "":
            urls = var_url["threat"]
        if var_ip != "":
            ips = var_ip["threat"]
        if var_domain != "":
            domains = var_domain["threat"]
        identity_id = "identity--2998978f-8336-5dfc-93a2-2f3d2f79d0e3"
        identity = stix2.Identity(
            id=identity_id,
            spec_version="2.1",
            name="Infoblox",
            confidence=100,
            created="2024-06-20T11:37:44.236Z",
            modified="2024-06-20T11:37:44.351Z",
            identity_class="organization",
            type="identity",
            object_marking_refs=stix2.TLP_WHITE,
        )

        stix_objects = [identity]
        all_threats = urls + ips + domains
        for threat in all_threats:
            stix_object = self.create_stix_object(threat, identity_id)
            if stix_object:
                stix_objects.extend(stix_object)

        bundle = stix2.Bundle(
            objects=stix_objects,
            allow_custom=True,
        )
        return bundle, all_threats

    def opencti_bundle(self, work_id):
        info = self.infoblox_api_get()
        try:
            var_ip = json.loads(info[0])
            var_url = json.loads(info[1])
            var_domain = json.loads(info[2])
            stix_bundle, all_threats = self.create_stix_bundle(
                var_url, var_ip, var_domain
            )

            # Convert the bundle to a dictionary
            stix_bundle_dict = json.loads(stix_bundle.serialize())

            stix_bundle_dict = json.dumps(stix_bundle_dict, indent=4)
            self.helper.send_stix2_bundle(
                stix_bundle_dict, update=self.update_existing_data, work_id=work_id
            )
        except Exception as e:
            self.helper.log_error(str(e))

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
            self.helper.log_info("Synchronizing with Infoblox APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            friendly_name = "Infoblox run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
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
            time.sleep(self.infoblox_interval)
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching Infoblox datasets...")
        self.set_marking()
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.infoblox_interval * 60 * 60)


if __name__ == "__main__":
    try:
        infobloxConnector = Infoblox()
        infobloxConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
