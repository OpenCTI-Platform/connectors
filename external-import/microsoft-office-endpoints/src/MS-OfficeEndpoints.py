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


class MOEndpoints:
    """MOEndpoints connector"""

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
        # o365_endpoints_url = 'https://endpoints.office.com/endpoints/worldwide?clientrequestid={clientrequestid}'
        self.o365_endpoints_url = get_config_variable(
            "O365_ENDPOINTS_URL",
            ["O365", "endpoints_url"],
            config,
        )
        #o365_identity = 'identity--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' or ' Name of the Identity '
        self.o365_identity = get_config_variable(
            "O365_IDENTITY",
            ["O365", "identity"],
            config,
            default="Microsoft Office Endpoints",
        )
        #   o365_interval: 24
        self.o365_interval = get_config_variable(
            "O365_INTERVAL",
            ["O365", "interval"],
            config,
            isNumber=True,
            default=24,
        )
        #   o365_tags: Microsoft,Office,Cloud
        self.o365_tags = get_config_variable(
            "O365_TAGS",
            ["O365", "tags"],
            config,
            default="Microsoft,Office,Cloud",
        )
        #   Marking: TLP:CLEAR
        self.o365_marking = get_config_variable(
            "O365_MARKING",
            ["O365", "marking_definition"],
            config,
            default="TLP:GREEN",
        )
        

        self.helper.connector_logger.debug("    Office Endpoints connector initialized.")
        self.helper.connector_logger.debug(f"    Office Endpoints O365_ENDPOINTS_URL: {self.o365_endpoints_url}.")
        self.helper.connector_logger.debug(f"    Office Endpoints o365_identity: {self.o365_identity}.")
        self.helper.connector_logger.debug(f"    Office Endpoints o365_interval: {self.o365_interval}.")
        self.helper.connector_logger.debug(f"    Office Endpoints o365_tags: {self.o365_tags}.")
        self.helper.connector_logger.debug(f"    Office Endpoints o365_marking: {self.o365_marking}.")
        
        
    def set_marking(self):
        if self.o365_marking == "TLP:WHITE" or self.o365_marking == "TLP:CLEAR":
            marking = stix2.TLP_WHITE
        elif self.o365_marking == "TLP:GREEN":
            marking = stix2.TLP_GREEN
        elif self.o365_marking == "TLP:AMBER":
            marking = stix2.TLP_AMBER
        elif self.o365_marking == "TLP:AMBER+STRICT":
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )
        elif self.o365_marking == "TLP:RED":
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

        self.o365_marking = marking

    def MOEndpoints_get_list(self):
        try:
            headers = {
                "User-Agent": "OpenCTI-Microsoft-Office-Endpoints-Connector",
                "ContentType": "application/json"
                }
            # Retrieve the list
            response = requests.get(
                self.o365_endpoints_url, headers=headers, verify=True, timeout=(80000, 80000)
            )
            self.helper.connector_logger.debug(f"We get a response from Microsoft Office Endpoints API: {response.status_code}.")
            r_json = response.json()
            self.helper.connector_logger.debug(f"And we have {len(r_json)} Office Endpoints entries.")
            return r_json
            
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while getting intelligence from Office Endpoints: {e}"
            )
            self.helper.set_state({"Error": f"Error while parsing JSON response from Microsoft Office Endpoints API: {e}"})
        return None

    def create_stix_object(self, O365_Element, identity_id):
        # TBD
        # O365_Element = One raw object from the API
        # identity_id = OCTI Identity ID to link it to
        
        # An object is like:
        #   {
        #     "id": 8,
        #     "serviceArea": "Exchange",
        #     "serviceAreaDisplayName": "Exchange Online",
        #     "urls": [
        #       "*.outlook.com",
        #       "autodiscover.*.onmicrosoft.com"
        #     ],
        #     "ips": [
        #       "40.92.0.0/15",
        #       "40.107.0.0/16",
        #       "2a01:111:f400::/48",
        #       "2a01:111:f403::/48"
        #     ],
        #     "tcpPorts": "80,443",
        #     "expressRoute": false,
        #     "category": "Default",
        #     "required": true
        #   },
        stix_objects = []
        description  = "Microsoft Office 365 Endpoint Details: \n"
        description += f"serviceArea: {O365_Element['serviceArea']} \n"
        description += f"serviceAreaDisplayName: {O365_Element['serviceAreaDisplayName']} \n"
        if 'tcpPorts' in O365_Element: description += f"It use TCP Ports: {O365_Element['tcpPorts']} \n"
        if 'udpPorts' in O365_Element:description +=  f"It use UDP Ports: {O365_Element['udpPorts']} \n"
        
        # We create an identity for the System
        
        self.helper.connector_logger.debug(f"    Office Endpoints identity: {O365_Element['serviceAreaDisplayName']}.")
        Serv_identity = stix2.Identity(
            spec_version="2.1",
            name=f"{O365_Element['serviceAreaDisplayName']}",
            confidence=75,
            created="2024-07-17T10:53:11.000Z",
            modified="2025-12-08T10:03:08.243Z",
            identity_class="system",
            type="identity",
            object_marking_refs=self.o365_marking,
            custom_properties={
                "x_opencti_score": 10,
                "x_opencti_labels": self.o365_tags.split(","),
            },
        )
        Serv_identity_id = Serv_identity['id']
        stix_objects.append(Serv_identity)
        # We have several elements to parse
        # - urls
        # - ips (v4/v6)
        # - tcpPorts
        if 'urls' in O365_Element:
            self.helper.connector_logger.debug(f"        - Urls {len(O365_Element['urls'])}.")
            for one_url in O365_Element['urls']:
                # STIX: Domain-Name
                try:
                    observable = stix2.DomainName(
                        value=one_url,
                        object_marking_refs=[self.o365_marking],
                        custom_properties={
                            "x_opencti_score": 80,
                            "x_opencti_description": description,
                            "created_by_ref": Serv_identity_id,
                            "x_opencti_labels": self.o365_tags.split(","),
                        },
                    )
                    stix_objects.append(observable)
                    # STIX: Relationship System --> Observable
                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", Serv_identity_id, observable["id"]
                        ),
                        relationship_type="related-to",
                        source_ref=Serv_identity_id,
                        target_ref=observable["id"],
                        created_by_ref=identity_id,
                        start_time = datetime.datetime.now(),
                        stop_time = datetime.datetime.now()+datetime.timedelta(hours=self.o365_interval),
                        object_marking_refs=[self.o365_marking],
                    )
                    stix_objects.append(relationship)
                except Exception as e:
                    self.helper.connector_logger.error(
                        f"Error while creating STIX object from url: {one_url}, error: {e}"
                    )
        if 'ips' in O365_Element:
            self.helper.connector_logger.debug(f"        - ips {len(O365_Element['ips'])}.")
            for one_ip in O365_Element['ips']:
                # STIX: IPv4/IPv6
                try:
                    if ":" in one_ip:
                        observable = stix2.IPv6Address(
                            value=one_ip,
                            object_marking_refs=[self.o365_marking],
                            custom_properties={
                                "x_opencti_score": 80,
                                "x_opencti_description": description,
                                "created_by_ref": Serv_identity_id,
                                "x_opencti_labels": self.o365_tags.split(","),
                            },
                        )
                    else:
                        observable = stix2.IPv4Address(
                            value=one_ip,
                            object_marking_refs=[self.o365_marking],
                            custom_properties={
                                "x_opencti_score": 80,
                                "x_opencti_description": description,
                                "created_by_ref": Serv_identity_id,
                                "x_opencti_labels": self.o365_tags.split(","),
                            },
                        )
                    
                    stix_objects.append(observable)
                    # STIX: Relationship System --> Observable
                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", Serv_identity_id, observable["id"]
                        ),
                        relationship_type="related-to",
                        source_ref=Serv_identity_id,
                        target_ref=observable["id"],
                        created_by_ref=identity_id,
                        start_time = datetime.datetime.now(),
                        stop_time = datetime.datetime.now()+datetime.timedelta(hours=self.o365_interval),
                        object_marking_refs=[self.o365_marking],
                    )
                    stix_objects.append(relationship)
                except Exception as e:
                    self.helper.connector_logger.error(
                        f"Error while creating STIX object from ip: {one_ip}, error: {e}"
                    )
        

        # Return the list of STIX objects (for bundle creation)
        return stix_objects

    def create_stix_bundle(self, O365_list):
        
        if O365_list is None:
            self.helper.connector_logger.error("No Ms Office Endpoints returned.")
            return None, None
        if self.o365_identity.startswith("identity--"):
            self.helper.connector_logger.info(f"We use the provided Identity ID for Microsoft Office Endpoints: {self.o365_identity}.")
            identity_id = self.o365_identity    
        else:
            self.helper.connector_logger.info(f"We create: {self.o365_identity}.")
            
            identity = stix2.Identity(
                spec_version="2.1",
                name=f"{self.o365_identity}",
                confidence=75,
                created="2024-07-17T10:53:11.000Z",
                modified="2025-12-08T10:03:08.243Z",
                identity_class="organization",
                type="identity",
                object_marking_refs=stix2.TLP_WHITE,
            )
            identity_id = identity['id']
            stix_objects = [identity, self.o365_marking]
            
        for one_O365_element in O365_list:
            stix_object = self.create_stix_object(one_O365_element, identity_id)
            if stix_object:
                stix_objects.extend(stix_object)

        bundle = stix2.Bundle(
            objects=stix_objects,
            allow_custom=True,
        )
        return bundle, O365_list

    def opencti_bundle(self, work_id):
        info = self.MOEndpoints_get_list()
        try:
            stix_bundle, O365_list = self.create_stix_bundle(info)
            if stix_bundle is None:
                self.helper.connector_logger.debug("No STIX bundle created from Office Endpoints data (None was return).")
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
            self.helper.connector_logger.info("Synchronizing with     Office Endpoints APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
            friendly_name = "    Office Endpoints run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
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
        self.helper.connector_logger.info("Fetching     Office Endpoints datasets...")
        self.set_marking()
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.o365_interval * 60 * 60)


if __name__ == "__main__":
    try:
        MOEndpointsConnector = MOEndpoints()
        MOEndpointsConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)