import datetime
import json
import os
import sys
import time

import requests
import stix2
import yaml
from pycti import (
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class iCloudPrivateRelay:
    """iCloudPrivateRelay connector"""

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

        # CONNECTOR_UPDATE_EXISTING_DATA
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            default=False,
        )
        # Extra config
        # iCloud_vpn_endpoints_url = 'https://mask-api.icloud.com/egress-ip-ranges.csv'
        self.iCloud_vpn_endpoints_url = get_config_variable(
            "APPLEVPN_ENDPOINTS_URL",
            ["APPLEVPN", "endpoints_url"],
            config,
            default="https://mask-api.icloud.com/egress-ip-ranges.csv",
        )
        #iCloud_vpn_identity = 'identity--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' or ' Name of the Identity '
        self.iCloud_vpn_identity = get_config_variable(
            "APPLEVPN_IDENTITY",
            ["APPLEVPN", "identity"],
            config,
            default="Apple VPN",
        )
        #   iCloud_vpn_interval: 24
        self.iCloud_vpn_interval = get_config_variable(
            "APPLEVPN_INTERVAL",
            ["APPLEVPN", "interval"],
            config,
            isNumber=True,
            default=24,
        )
        #   iCloud_vpn_tags: Microsoft,Office,Cloud
        self.iCloud_vpn_tags = get_config_variable(
            "APPLEVPN_TAGS",
            ["APPLEVPN", "tags"],
            config,
            default="Apple,VPN,Cloud",
        )
        #   iCloud_vpn_interval: 24
        self.iCloud_vpn_chunksize = get_config_variable(
            "APPLEVPN_CHUNKSIZE",
            ["APPLEVPN", "chunksize"],
            config,
            isNumber=True,
            default=10000,
        )
        #   Marking: TLP:CLEAR
        self.iCloud_vpn_marking = get_config_variable(
            "APPLEVPN_MARKING",
            ["APPLEVPN", "marking_definition"],
            config,
            default="TLP:GREEN",
        )
        

        self.helper.connector_logger.debug("    Apple VPN connector initialized.")
        self.helper.connector_logger.debug(f"    Apple VPN iCloud_vpn_endpoints_url: {self.iCloud_vpn_endpoints_url}.")
        self.helper.connector_logger.debug(f"    Apple VPN iCloud_vpn_interval: {self.iCloud_vpn_interval}.")
        self.helper.connector_logger.debug(f"    Apple VPN iCloud_vpn_tags: {self.iCloud_vpn_tags}.")
        self.helper.connector_logger.debug(f"    Apple VPN iCloud_vpn_marking: {self.iCloud_vpn_marking}.")
        
        
    def set_marking(self):
        if self.iCloud_vpn_marking == "TLP:WHITE" or self.iCloud_vpn_marking == "TLP:CLEAR":
            marking = stix2.TLP_WHITE
        elif self.iCloud_vpn_marking == "TLP:GREEN":
            marking = stix2.TLP_GREEN
        elif self.iCloud_vpn_marking == "TLP:AMBER":
            marking = stix2.TLP_AMBER
        elif self.iCloud_vpn_marking == "TLP:AMBER+STRICT":
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )
        elif self.iCloud_vpn_marking == "TLP:RED":
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

        self.iCloud_vpn_marking = marking

    def VPNEndpoints_get_list(self):
        try:
            headers = {
                "User-Agent": "OpenCTI-iCloud_vpn-Connector",
                "ContentType": "application/json"
                }
            # Retrieve the list
            response = requests.get(
                self.iCloud_vpn_endpoints_url, headers=headers, verify=True, timeout=(80000, 80000)
            )
            self.helper.connector_logger.debug(f"We get a response from Microsoft Apple VPN API: {response.status_code}.")
            r_lines = response.text.splitlines()
            self.helper.connector_logger.debug(f"And we have {len(r_lines)} raw Apple VPN entries.")
            # Do we have a local last run file?
            if os.path.exists("last_AppleVPN_run.csv"):
                with open("last_AppleVPN_run.csv", "r") as f:
                    last_run_data = f.read().strip()
                self.helper.connector_logger.debug(f"We have a local last run data: {last_run_data}.")
                # We filter the lines based on last run data
                r_lines_filtered = []
                for line in r_lines:
                    if line > last_run_data:
                        r_lines_filtered.append(line)
                r_lines = r_lines_filtered
                self.helper.connector_logger.debug(f"After filtering, we have {len(r_lines)} new Apple VPN entries.")
            return r_lines
            
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while getting intelligence from Apple VPN: {e}"
            )
            self.helper.set_state({"Error": f"Error while parsing JSON response from Microsoft Apple VPN API: {e}"})
        return None

    def create_stix_object(self, AppleVPN_Element, identity_id):
        # TBD
        # AppleVPN_Element = One raw object from the API
        # identity_id = OCTI Identity ID to link it to
        
        # An object is like a csv: 
        # CIDR,CountryCode,RegionCode,City,
        
        # 172.224.226.0/27,GB,GB-EN,London,
        # 172.224.226.32/31,GB,GB-SC,Aberdeen,
        # 172.224.226.34/31,GB,GB-EN,Oxford,
        # 172.224.226.36/31,GB,GB-EN,Luton,
        # 172.224.226.38/31,GB,GB-NI,Belfast,
        # 172.224.226.40/31,GB,GB-SC,Dundee,
        # 172.224.226.42/31,GB,GB-EN,Brighton,
        # 172.224.226.44/31,GB,GB-EN,Leicester,
        # 172.224.226.46/31,GB,GB-EN,Liverpool,
        # 172.224.226.48/31,GB,GB-SC,Edinburgh,
        # 172.224.226.50/31,GB,GB-EN,Cambridge,
        # 172.224.226.52/31,GB,GB-EN,Bristol,
        # 172.224.226.54/31,GB,GB-EN,Maidstone,
        # 172.224.226.56/31,GB,GB-EN,Broomfield,
        # 172.224.226.58/31,GB,GB-EN,Egg Buckland,
        stix_objects = []
        

        CIDR = AppleVPN_Element.split(",")[0]
        CountryCode = AppleVPN_Element.split(",")[1]
        RegionCode = AppleVPN_Element.split(",")[2]
        City = AppleVPN_Element.split(",")[3]

        # self.helper.connector_logger.info(f"  Working on {CIDR} / {City} / {CountryCode} / {RegionCode}.")
        
        description  = "Apple iCloud privacy VPN goes thrue this element: \n"
        description += f"CIDR: {CIDR} \n"
        description += f"CountryCode: {CountryCode} \n"
        description += f"CIRegionCodeDR: {RegionCode} \n"
        description += f"City: {City} \n"
        
        # We create IPAdress object for the CIDR
        # STIX: IPv4/IPv6
        try:
            if ":" in CIDR:
                observable = stix2.IPv6Address(
                    value=CIDR,
                    object_marking_refs=[self.iCloud_vpn_marking],
                    custom_properties={
                        "x_opencti_score": 80,
                        "x_opencti_description": description,
                        "created_by_ref": identity_id,
                        "x_opencti_labels": self.iCloud_vpn_tags.split(","),
                    },
                )
            else:
                observable = stix2.IPv4Address(
                    value=CIDR,
                    object_marking_refs=[self.iCloud_vpn_marking],
                    custom_properties={
                        "x_opencti_score": 80,
                        "x_opencti_description": description,
                        "created_by_ref": identity_id,
                        "x_opencti_labels": self.iCloud_vpn_tags.split(","),
                    },
                )
            
            stix_objects.append(observable)
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from cidr: {CIDR}, error: {e}"
            )
        # We create a Country Identity based on CountryCode
        self.helper.connector_logger.debug(f"     > Output {CountryCode} is a country code, linking country.")
        try:
            country_obj = stix2.Location(
                # id=stix2.Location.generate_id(f"[location:value = '{CountryCode}']","Country"),
                country=CountryCode,
                custom_properties={"x_opencti_score": 50, },
            )
            stix_objects.append(country_obj)
            # STIX relationship between IP and Country
            relation_OC = stix2.Relationship(
                        id=StixCoreRelationship.generate_id("related-to", observable["id"], country_obj["id"]),
                        source_ref=observable["id"],
                        target_ref=country_obj["id"],
                        relationship_type="related-to",
                        created_by_ref=identity_id,
                        start_time = datetime.datetime.now(),
                        stop_time = datetime.datetime.now()+datetime.timedelta(hours=self.iCloud_vpn_interval),
                        object_marking_refs=[self.iCloud_vpn_marking],
                        description=f"Link between observable and country at {datetime.datetime.now().strftime("%Y-%m-%d")}. (Link ObsCountry)"
                    )
            stix_objects.append(relation_OC)
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from country: {CountryCode}, error: {e}"
            )
        # We create a Country Identity based on City
        self.helper.connector_logger.debug(f"     > Output {City} is a country code, linking country.")
        try:
            city_obj = stix2.Location(
                # id=stix2.Location.generate_id(f"[location:value = '{CountryCode}']","City"),
                country=CountryCode,
                region=RegionCode,
                city=City,
                custom_properties={"x_opencti_score": 50, },
            )
            stix_objects.append(country_obj)
            # STIX relationship between IP and City
            relation_OCi = stix2.Relationship(
                        id=StixCoreRelationship.generate_id("related-to", observable["id"], city_obj["id"]),
                        source_ref=observable["id"],
                        target_ref=city_obj["id"],
                        relationship_type="related-to",
                        created_by_ref=identity_id,
                        start_time = datetime.datetime.now(),
                        stop_time = datetime.datetime.now()+datetime.timedelta(hours=self.iCloud_vpn_interval),
                        object_marking_refs=[self.iCloud_vpn_marking],
                        description=f"Link between observable and city at {datetime.datetime.now().strftime("%Y-%m-%d")}. (Link ObsCity)"
                    )
            stix_objects.append(relation_OCi)
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while creating STIX object from city: {City} / {RegionCode} / {CountryCode}, error: {e}"
            )
        # Return the list of STIX objects (for bundle creation)
        return stix_objects

    def create_stix_bundle(self, AppleVPN_lines):
        
        if AppleVPN_lines is None:
            self.helper.connector_logger.error("No Apple VPN returned.")
            return None, None
        if self.iCloud_vpn_identity.startswith("identity--"):
            self.helper.connector_logger.info(f"We use the provided Identity ID for Microsoft Apple VPN: {self.iCloud_vpn_identity}.")
            identity_id = self.iCloud_vpn_identity    
        else:
            self.helper.connector_logger.info(f"We create: {self.iCloud_vpn_identity}.")
            
            identity = stix2.Identity(
                spec_version="2.1",
                name=f"{self.iCloud_vpn_identity}",
                confidence=75,
                created="2024-07-17T10:53:11.000Z",
                modified="2025-12-08T10:03:08.243Z",
                identity_class="organization",
                type="identity",
                object_marking_refs=self.iCloud_vpn_marking,
            )
            identity_id = identity['id']
            stix_objects = [identity]
        
        self.helper.connector_logger.info(f"We have: {len(AppleVPN_lines)} elements to create.")
        
        if len(AppleVPN_lines)> self.iCloud_vpn_chunksize:
            To_process_lines = AppleVPN_lines[:self.iCloud_vpn_chunksize]
            self.helper.connector_logger.info(f" We will process only {self.iCloud_vpn_chunksize} lines this run.")
        else:
            To_process_lines = AppleVPN_lines

        for one_AppleVPN_element in To_process_lines:
            stix_object = self.create_stix_object(one_AppleVPN_element, identity_id)
            if stix_object:
                stix_objects.extend(stix_object)
        
        if len(AppleVPN_lines)> self.iCloud_vpn_chunksize:
            # We append the last processed line to a local file
            with open("last_AppleVPN_run.csv", "w+") as f:
                f.write("\n".join(one_AppleVPN_element))
                f.close()
            self.helper.connector_logger.info(" We save the last processed lines for next run.")

        bundle = stix2.Bundle(
            objects=stix_objects,
            allow_custom=True,
        )
        return bundle, AppleVPN_lines

    def opencti_bundle(self, work_id):
        info = self.VPNEndpoints_get_list()
        try:
            stix_bundle , AppleVPN_lines = self.create_stix_bundle(info)
            if stix_bundle is None:
                self.helper.connector_logger.debug("No STIX bundle created from Apple VPN data (None was return).")
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
            self.helper.connector_logger.info("Synchronizing with     Apple VPN APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            friendly_name = "    Apple VPN run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
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
            time.sleep(30)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(str(e))

    def run(self):
        self.helper.connector_logger.info("Fetching     Apple VPN datasets...")
        self.set_marking()
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.iCloud_vpn_interval * 60 * 60)


if __name__ == "__main__":
    try:
        iCloudPrivateRelayConnector = iCloudPrivateRelay()
        iCloudPrivateRelayConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)