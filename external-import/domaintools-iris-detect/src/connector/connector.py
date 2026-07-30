import json
import sys
from datetime import datetime, timedelta, timezone

from client import DomainToolsClient
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class DomainToolsIrisDetectConnector:
    """
    Specifications of the external import connector:

    This class encapsulates the main actions, expected to be run by any connector of type `EXTERNAL_IMPORT`.
    This type of connector aim to fetch external data to create STIX bundle and send it to OpenCTI.
    The STIX bundle in the queue will be processed by OpenCTI workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes:
        config (ConnectorSettings):
            Store the connector's configuration. It defines how to connector will behave.
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
            _All connectors MUST use the connector helper with connector's configuration._
        client (TemplateClient):
            Provide methods to request the external API.
        converter_to_stix (ConnectorConverter):
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices:
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to schedule connector's runs frequency
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to OpenCTI
        - `self.helper.set_state()` is used to store persistent data in connector's state

    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `DomainToolsIrisDetectConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper
        self.monitor_id = self.config.domaintools.monitor_id
        self.preview = self.config.domaintools.preview
        self.store_iris_data = self.config.domaintools.store_iris_data

        self.client = DomainToolsClient(
            self.helper,
            base_url=self.config.domaintools.api_base_url,
            api_key=self.config.domaintools.api_key,
            # Pass any arguments necessary to the client
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.domaintools.tlp_level,
            # Pass any arguments necessary to the converter
        )

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        stix_objects = []

        # ===========================
        # === Add your code below ===
        # ===========================
        dt_parameters = {"preview": self.preview, "include_domain_data": True}

        if self.monitor_id:
            dt_parameters["monitor_id"] = self.monitor_id

        # Set last run date
        state = self.helper.get_state()
        if (state is not None) and ("last_run" in state):
            # overlap from last iocs poll
            temp_datetime = state["last_run"]
            dt_object = datetime.strptime(temp_datetime, "%Y-%m-%d %H:%M:%S")
            tmp = dt_object - timedelta(minutes=5)
            iris_detect_last_run_timestamp = tmp.strftime("%Y-%m-%dT%H:%M:%SZ")
            self.helper.connector_logger.info(
                f"Using last run time: {iris_detect_last_run_timestamp}"
            )
            dt_parameters["discovered_since"] = iris_detect_last_run_timestamp
        else:
            current_utc_time = datetime.now(timezone.utc)
            x_hour_ago_utc = current_utc_time - timedelta(hours=1)
            iris_detect_last_run_timestamp = x_hour_ago_utc.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            self.helper.connector_logger.info(
                f"Setting last run time to 1 hr ago: {iris_detect_last_run_timestamp}"
            )
            dt_parameters["discovered_since"] = iris_detect_last_run_timestamp

        # Get entities from external sources
        monitor_id_term, entities = self.client.get_entities(dt_parameters)
        self.helper.connector_logger.info(
            f"Successfully downloaded {len(entities)} records."
        )

        for entity in entities:
            domain = entity.get("domain")
            score = entity.get("risk_score")

            labels = ["Iris Detect"]

            for id in entity.get("monitor_ids", []):
                labels.append(f"monitor_id:{id}")
                labels.append(f"monitor_term:{monitor_id_term.get(id, 'unknown')}")

            risk_score_components = entity.get("risk_score_components", {})
            if "proximity" in risk_score_components:
                labels.append(f"proximity:{risk_score_components.get('proximity')}")
            if "threat_profile" in risk_score_components:
                threat_profile = risk_score_components.get("threat_profile", {})
                if "phishing" in threat_profile:
                    labels.append(f"phishing:{threat_profile.get('phishing')}")
                if "malware" in threat_profile:
                    labels.append(f"malware:{threat_profile.get('malware')}")
                if "spam" in threat_profile:
                    labels.append(f"spam:{threat_profile.get('spam')}")

            domain_obs = self.converter_to_stix.create_obs(domain, score, labels)
            if not domain_obs:
                continue
            stix_objects.append(domain_obs)

            ###### Note
            if self.store_iris_data:
                note_content = json.dumps(entity)
                note_abstract = "DomainTools Iris Data"

                note_obj_id = self.converter_to_stix.create_note_id(
                    note_content, note_abstract
                )

                stix_objects.append(
                    {
                        "type": "note",
                        "id": note_obj_id,
                        "content": note_content,
                        "abstract": note_abstract,
                        "created_by_ref": self.converter_to_stix.author["id"],
                        "object_marking_refs": [self.converter_to_stix.tlp_marking["id"]],
                        "object_refs": [domain_obs.id],
                    }
                )

            ###### IP
            stix_objects.extend(self._process_IP(domain_obs, entity.get("ip", [])))

            ###### MX
            stix_objects.extend(
                self._process_MX_NS(domain_obs, entity.get("mx", []), "MX")
            )

            ###### NS
            stix_objects.extend(
                self._process_MX_NS(domain_obs, entity.get("name_server", []), "NS")
            )

        # ===========================
        # === Add your code above ===
        # ===========================

        # Ensure consistent bundle by adding the author and TLP marking
        if len(stix_objects):
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects

    def _process_IP(self, _source, data):
        all_ip_object = []
        for ip_entity in data:
            ip = ip_entity.get("ip", "")
            ip_obs = self.converter_to_stix.create_obs(ip)

            if not ip_obs:
                continue

            all_ip_object.append(ip_obs)

            entity_relation = self.converter_to_stix.create_relationship(
                _source.id, "resolves-to", ip_obs.id
            )
            all_ip_object.append(entity_relation)

        return all_ip_object

    def _process_MX_NS(self, _source, data, data_type):
        all_ip_object = []
        for mx_entity in data:
            host = mx_entity.get("host", "")

            ### Note: some value point to itself
            if _source.value == host:
                continue

            host_obs = self.converter_to_stix.create_obs(host, labels=[data_type])

            if not host_obs:
                continue

            all_ip_object.append(host_obs)

            entity_relation = self.converter_to_stix.create_relationship(
                _source.id, "resolves-to", host_obs.id
            )
            all_ip_object.append(entity_relation)

        return all_ip_object

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "DomainTools Iris Detect"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            # ===========================
            # === Add your code below ===
            # ===========================
            stix_objects = self._collect_intelligence()

            ### May move this into _collect_intelligence method to help with batching
            if len(stix_objects):
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": str(len(bundles_sent))},
                )
            # ===========================
            # === Add your code above ===
            # ===========================

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.fromtimestamp(
                current_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
            )

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
        """
        Start the connector, schedule its runs and trigger the first run.
        It allows you to schedule the process to run at a certain interval.
        This specific scheduler from the `OpenCTIConnectorHelper` will also check the queue size of a connector.
        If `CONNECTOR_QUEUE_THRESHOLD` is set, and if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)

        Example:
            - If `CONNECTOR_DURATION_PERIOD=PT5M`, then the connector is running every 5 minutes.
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
