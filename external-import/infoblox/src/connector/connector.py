import json
import sys
from datetime import datetime, timezone

import requests
import stix2
from connector.settings import ConnectorSettings
from pycti import (
    Indicator,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class Infoblox:
    """Infoblox connector"""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """Initialize the connector with its configuration and helper."""
        self.config = config
        self.helper = helper
        self.marking = None
        self.set_marking()

    def set_marking(self):
        marking_definition = self.config.infoblox.marking_definition
        if marking_definition == "TLP:WHITE" or marking_definition == "TLP:CLEAR":
            marking = stix2.TLP_WHITE
        elif marking_definition == "TLP:GREEN":
            marking = stix2.TLP_GREEN
        elif marking_definition == "TLP:AMBER":
            marking = stix2.TLP_AMBER
        elif marking_definition == "TLP:AMBER+STRICT":
            marking = stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            )
        elif marking_definition == "TLP:RED":
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

        self.marking = marking

    def infoblox_api_get(self):
        try:
            headers = {
                "Authorization": "Token {}".format(
                    self.config.infoblox.api_key.get_secret_value()
                )
            }
            # The lookup period (in hours) is derived from the connector's duration period.
            period_hours = (
                int(self.config.connector.duration_period.total_seconds() // 3600) or 1
            )
            ioc_types = ["ip", "url", "host"]
            infoblox_result = []
            for ioc_type in ioc_types:

                url = (
                    f"{self.config.infoblox.url.rstrip('/')}?type={ioc_type}"
                    f"&period={period_hours}h&profile=IID&dga=false&up=true&"
                    f"rlimit={self.config.infoblox.ioc_limit}"
                )
                response = requests.get(
                    url, headers=headers, verify=True, timeout=(80000, 80000)
                )
                r_json = response.json()
                r_json1 = json.dumps(r_json, indent=4)
                infoblox_result.append(r_json1)
            return infoblox_result
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error while getting intelligence from Infoblox: {e}"
            )

    def create_stix_object(self, threat, identity_id):
        object_type = threat["type"]
        stix_objects = []

        description = threat["extended"].get("notes")
        if description is None:
            self.helper.connector_logger.debug(
                f"Missing 'notes' key in threat: {threat}"
            )
            description = ""

        if object_type == "URL":
            pattern = f"[url:value = '{threat['url']}']"
            observable_type = "Url"
            name = threat["url"]
            observable = stix2.URL(
                value=name,
                object_marking_refs=[self.marking],
                custom_properties={
                    "x_opencti_score": threat["threat_level"],
                    "x_opencti_description": description,
                    "created_by_ref": identity_id,
                },
            )
            stix_objects.append(observable)

        elif object_type == "HOST":
            pattern = f"[domain-name:value = '{threat['domain']}']"
            observable_type = "Domain-Name"
            name = threat["domain"]
            observable = stix2.DomainName(
                value=name,
                object_marking_refs=[self.marking],
                custom_properties={
                    "x_opencti_score": threat["threat_level"],
                    "x_opencti_description": description,
                    "created_by_ref": identity_id,
                },
            )
            stix_objects.append(observable)

        elif object_type == "IP":
            pattern = f"[ipv4-addr:value = '{threat['ip']}']"
            observable_type = "IPv4-Addr"
            name = threat["ip"]
            observable = stix2.IPv4Address(
                value=name,
                object_marking_refs=[self.marking],
                custom_properties={
                    "x_opencti_score": threat["threat_level"],
                    "x_opencti_description": description,
                    "created_by_ref": identity_id,
                },
            )
            stix_objects.append(observable)

        else:
            self.helper.connector_logger.error(
                object_type + " is not supported as an object type."
            )
            return None

        if pattern:
            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=name,
                pattern=pattern,
                pattern_type="stix",
                description=description,
                created_by_ref=identity_id,
                created=datetime.strptime(
                    threat["detected"], "%Y-%m-%dT%H:%M:%S.%fZ"
                ).replace(tzinfo=timezone.utc),
                modified=datetime.strptime(
                    threat["imported"], "%Y-%m-%dT%H:%M:%S.%fZ"
                ).replace(tzinfo=timezone.utc),
                labels=[threat["class"], threat["property"]],
                confidence=threat["confidence"],
                object_marking_refs=[self.marking],
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
                object_marking_refs=[self.marking],
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

        stix_objects = [identity, self.marking]
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
                stix_bundle_dict, update=False, work_id=work_id
            )
        except Exception as e:
            self.helper.connector_logger.error(str(e))

    def send_bundle(self, work_id, serialized_bundle: str):
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                update=False,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.connector_logger.error(f"Error while sending bundle: {e}")

    def process_message(self) -> None:
        """Connector main process to collect intelligence."""
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )
        try:
            self.helper.connector_logger.info("Synchronizing with Infoblox APIs...")
            now = datetime.now(tz=timezone.utc)
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
            self.helper.connector_logger.info(
                "Get IOC since " + current_state["last_run"]
            )
            self.opencti_bundle(work_id)
            self.helper.set_state({"last_run": now.isoformat()})
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """Run the main process encapsulated in the pycti scheduler."""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
