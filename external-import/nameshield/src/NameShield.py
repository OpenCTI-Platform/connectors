# Import Done with isort
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
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class NameShield:
    """NameShield connector"""

    def __init__(self):
        """Initializer"""
        # ==============================================================
        # This part is common to all connectors, it loads the config file, and the parameters to local variables
        # ==============================================================
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
        # Auth Bearer
        self.nameshield_auth_bearer = get_config_variable(
            "NAMESHIELD_AUTH_BEARER",
            ["nameshield", "auth_bearer"],
            config,
        )
        #   server: 'api.nameshield.net'
        self.nameshield_server = get_config_variable(
            "NAMESHIELD_SERVER",
            ["nameshield", "server"],
            config,
        )
        #   api_version: 'v1'
        self.nameshield_api_version = get_config_variable(
            "NAMESHIELD_API_VERSION",
            ["nameshield", "api_version"],
            config,
        )
        #   api_endpoint: 'v1'
        self.nameshield_api_endpoint = get_config_variable(
            "NAMESHIELD_API_ENDPOINT",
            ["nameshield", "api_endpoint"],
            config,
        )
        # url_list: 'https://{server}/{api_endpoint}/{api_version}/domains'
        self.nameshield_url_list = get_config_variable(
            "NAMESHIELD_URL_LIST",
            ["nameshield", "url_list"],
            config,
            default="https://{server}/{api_endpoint}/{api_version}/domains",
        )
        # url_domain: 'https://{server}/{api_endpoint}/{api_version}/domains/{domain}'
        self.nameshield_url_domain = get_config_variable(
            "NAMESHIELD_URL_DOMAIN",
            ["nameshield", "url_domain"],
            config,
            default="https://{server}/{api_endpoint}/{api_version}/domains/{domain}",
        )
        #   interval: 168
        self.nameshield_interval = get_config_variable(
            "NAMESHIELD_INTERVAL",
            ["nameshield", "interval"],
            config,
            isNumber=True,
            default=168,
        )
        #   Domain Limit: 10000
        self.nameshield_ioc_limit = get_config_variable(
            "NAMESHIELD_DOMAIN_LIMIT",
            ["nameshield", "domain_limit"],
            config,
            isNumber=True,
            default=10000,
        )
        #   MArking: TLP:GREEN
        self.nameshield_marking = get_config_variable(
            "NAMESHIELD_MARKING",
            ["nameshield", "marking_definition"],
            config,
            default="TLP:GREEN",
        )
        # CONNECTOR_UPDATE_EXISTING_DATA
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            default=False,
        )
        # NAMESHIELD_LINK_TO_IDENTITIES
        self.nameshield_link_to_identities = get_config_variable(
            "NAMESHIELD_LINK_TO_IDENTITIES",
            ["nameshield", "link_to_identities"],
            config,
            default="",
        )

        self.helper.connector_logger.debug("NameShield connector initialized.")
        self.helper.connector_logger.debug(
            f"NameShield server: {self.nameshield_server}."
        )
        self.helper.connector_logger.debug(
            f"NameShield api_version: {self.nameshield_api_version}."
        )
        self.helper.connector_logger.debug(
            f"NameShield api_endpoint: {self.nameshield_api_endpoint}."
        )
        self.helper.connector_logger.debug(
            f"NameShield url_list: {self.nameshield_url_list}."
        )
        self.helper.connector_logger.debug(
            f"NameShield url_domain: {self.nameshield_url_domain}."
        )
        self.helper.connector_logger.debug(
            f"NameShield marking: {self.nameshield_marking}."
        )

    def set_marking(self):
        if (
            self.nameshield_marking == "TLP:WHITE"
            or self.nameshield_marking == "TLP:CLEAR"
        ):
            marking = stix2.TLP_WHITE
        elif self.nameshield_marking == "TLP:GREEN":
            marking = stix2.TLP_GREEN
        elif self.nameshield_marking == "TLP:AMBER":
            marking = stix2.TLP_AMBER
        elif self.nameshield_marking == "TLP:AMBER+STRICT":
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )
        elif self.nameshield_marking == "TLP:RED":
            marking = stix2.TLP_RED
        else:
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="TLP",
                definition={"TLP": "AMBER+STRICT"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )

        self.nameshield_marking = marking

    def make_url_dom_list(self):
        url = self.nameshield_url_list.format(
            server=self.nameshield_server,
            api_endpoint=self.nameshield_api_endpoint,
            api_version=self.nameshield_api_version,
        )
        self.helper.connector_logger.debug(f"NameShield url domain list:  {url}.")
        return url

    def make_url_dom(self, domain):
        url = self.nameshield_url_domain.format(
            server=self.nameshield_server,
            api_endpoint=self.nameshield_api_endpoint,
            api_version=self.nameshield_api_version,
            domain=domain,
        )
        self.helper.connector_logger.debug(f"NameShield url domain details:  {url}.")
        return url

    def nameshield_api_get_list(self):
        try:
            headers = {
                "Authorization": "Bearer {}".format(self.nameshield_auth_bearer),
                "ContentType": "application/json",
            }
            ioc_types = ["host"]
            nameshield_result = []
            for ioc_type in ioc_types:

                url = self.make_url_dom_list()
                response = requests.get(
                    url, headers=headers, verify=True, timeout=(80000, 80000)
                )
                self.helper.connector_logger.debug(
                    f"We get a response from NameShield API: {response.status_code}."
                )
                r_json = response.json()
                # print(r_json)
                if "errors" in r_json:
                    self.helper.connector_logger.error(
                        f"Error NameShield: {r_json['errors']['code']} {r_json['errors']['message']}"
                    )
                    self.helper.set_state(
                        {
                            "Error": f"Error NameShield: {r_json['errors']['code']} {r_json['errors']['message']}"
                        }
                    )
                    return None
                # Check is a message has arrived
                if "message" in r_json:
                    self.helper.connector_logger.error(
                        f"NameShield send a message : {r_json['message']}"
                    )
                # Check if data field is present
                if not "data" in r_json:
                    self.helper.connector_logger.error(
                        "NameShield response has no data field."
                    )
                    self.helper.set_state(
                        {
                            "Error": f"Error NameShield no data returned only thoses keys:  {str(",".join(r_json.keys()))}"
                        }
                    )
                    return None
                # We have to retreive details for each domain
                self.helper.connector_logger.debug(f"We get : {str(r_json.keys())}.")
                for domain_entry in r_json["data"][: self.nameshield_ioc_limit]:
                    domain_name = domain_entry["domain"]
                    if domain_name:
                        url_domain = self.make_url_dom(domain_name)
                        response_domain = requests.get(
                            url_domain,
                            headers=headers,
                            verify=True,
                            timeout=(80000, 80000),
                        )
                        domain_info = response_domain.json()
                        nameshield_result.append(domain_info["data"])
            return nameshield_result
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while getting intelligence from NameShield: {e}"
            )

    def create_stix_object(self, threat, identity_id):
        # TBD
        # Threat = nameshield_dom (only domain type for now)
        # identity_id = OCTI Identity ID for NameShield
        stix_objects = []
        # We generate STIX objects from each domain entry
        description = ""
        for one in threat.keys():
            value_loc = threat[one]
            description += str(one).rjust(25, " ") + " : " + str(value_loc) + "\n"
        description += "\n\nImported from NameShield API."
        # STIX: Domain-Name
        try:
            pattern = f"[domain-name:value = '{threat['unicode']}']"
            observable_type = "Domain-Name"
            name = threat["unicode"]
            observable = stix2.DomainName(
                value=name,
                object_marking_refs=[self.nameshield_marking],
                custom_properties={
                    "x_opencti_score": 80,
                    "x_opencti_description": description,
                    "created_by_ref": identity_id,
                },
            )
            stix_objects.append(observable)
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from threat: {threat}, error: {e}"
            )
            return None
        # STIX: Indicator
        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=name,
            pattern=pattern,
            pattern_type="stix",
            description=description,
            created_by_ref=identity_id,
            created=datetime.datetime.strptime(
                str(threat["nicCreationDate"]), "%Y-%m-%d"
            ),
            valid_until=datetime.datetime.strptime(
                str(threat["expirationDate"]), "%Y-%m-%d"
            ),
            modified=datetime.datetime.now(),
            labels=[threat["class"], threat["property"]],
            confidence=threat["confidence"],
            object_marking_refs=[self.nameshield_marking],
            custom_properties={
                "x_opencti_score": threat["threat_level"],
                "x_opencti_main_observable_type": observable_type,
            },
        )
        stix_objects.append(indicator)
        # STIX: Relationship Indicator --> Observable
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on", indicator["id"], observable["id"]
            ),
            relationship_type="based-on",
            source_ref=indicator["id"],
            target_ref=observable["id"],
            created_by_ref=identity_id,
            start_time=datetime.datetime.strptime(
                str(threat["nicCreationDate"]), "%Y-%m-%d"
            ),
            stop_time=datetime.datetime.strptime(
                str(threat["expirationDate"]), "%Y-%m-%d"
            ),
            object_marking_refs=[self.nameshield_marking],
        )
        stix_objects.append(relationship)

        # STIX: Relationships to Identities
        if len(self.nameshield_link_to_identities) > 20:
            try:
                identities_list = [
                    identity.strip()
                    for identity in self.nameshield_link_to_identities.split(",")
                ]
                for identity_id in identities_list:
                    relationship_identity = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "attributed-to", indicator["id"], identity_id
                        ),
                        relationship_type="attributed-to",
                        source_ref=indicator["id"],
                        target_ref=identity_id,
                        start_time=datetime.datetime.strptime(
                            str(threat["nicCreationDate"]), "%Y-%m-%d"
                        ),
                        stop_time=datetime.datetime.strptime(
                            str(threat["expirationDate"]), "%Y-%m-%d"
                        ),
                        created_by_ref=identity_id,
                        object_marking_refs=[self.nameshield_marking],
                    )
                    stix_objects.append(relationship_identity)
            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error while creating STIX object relation to : {self.nameshield_link_to_identities}, error: {e}"
                )

        # Return the list of STIX objects (for bundle creation)
        return stix_objects

    def create_stix_bundle(self, domain_list):

        if domain_list is None:
            self.helper.connector_logger.info("No NameShield domains returned.")
            return None, None

        identity_id = "identity--d810a42f-59f5-5409-bb3a-6839c5087806"
        identity = stix2.Identity(
            id=identity_id,
            spec_version="2.1",
            name="NameShield",
            confidence=100,
            created="2024-07-17T10:53:11.000Z",
            modified="2025-12-08T10:03:08.243Z",
            identity_class="organization",
            type="identity",
            object_marking_refs=stix2.TLP_WHITE,
        )

        stix_objects = [identity, self.nameshield_marking]
        for nameshield_dom in domain_list:
            stix_object = self.create_stix_object(nameshield_dom, identity_id)
            if stix_object:
                stix_objects.extend(stix_object)

        bundle = stix2.Bundle(
            objects=stix_objects,
            allow_custom=True,
        )
        return bundle, nameshield_dom

    def opencti_bundle(self, work_id):
        info = self.nameshield_api_get_list()
        try:
            stix_bundle, all_threats = self.create_stix_bundle(info)
            if stix_bundle is None:
                self.helper.connector_logger.debug(
                    "No STIX bundle created from NameShield data (None was return)."
                )
            else:
                # Convert the bundle to a dictionary
                stix_bundle_dict = json.loads(stix_bundle.serialize())

                stix_bundle_dict = json.dumps(stix_bundle_dict, indent=4)
                self.helper.send_stix2_bundle(
                    stix_bundle_dict, update=self.update_existing_data, work_id=work_id
                )
        except Exception as e:
            self.helper.connector_logger.error(str(e))

    def send_bundle(self, work_id, serialized_bundle: str):
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.connector_logger.error(f"Error while sending bundle: {e}")

    def process_data(self):
        try:
            self.helper.connector_logger.info("Synchronizing with NameShield APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            friendly_name = "NameShield run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            if current_state is None:
                self.helper.set_state(
                    {"last_run": str(now.strftime("%Y-%m-%d %H:%M:%S"))}
                )
            current_state = self.helper.get_state()
            self.helper.connector_logger.info(
                "Get infos since " + current_state["last_run"]
            )
            self.opencti_bundle(work_id)
            self.helper.set_state({"last_run": now.astimezone().isoformat()})
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)
            time.sleep(self.nameshield_interval)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(str(e))

    def run(self):
        self.helper.connector_logger.info("Fetching NameShield datasets...")
        self.set_marking()
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.nameshield_interval * 60 * 60)


if __name__ == "__main__":
    try:
        NameShieldConnector = NameShield()
        NameShieldConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
