import sys
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper

from .client_api import FlowtriqClient
from .converter_to_stix import ConverterToStix
from .settings import ConnectorSettings

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _parse_timestamp(ts: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp string into a timezone-aware datetime."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


class ConnectorFlowtriq:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aims to fetch external data to create STIX bundles and send them
    in a RabbitMQ queue. The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (ConnectorSettings())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConverterToStix(helper, config))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """
        self.config = config
        self.helper = helper
        self.client = FlowtriqClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def _meets_severity_threshold(self, severity: str) -> bool:
        """
        Check if an incident's severity meets the configured minimum threshold.
        """
        min_sev = self.config.flowtriq.min_severity
        if not min_sev:
            return True
        try:
            min_idx = SEVERITY_ORDER.index(min_sev)
            sev_idx = SEVERITY_ORDER.index(severity)
            return sev_idx >= min_idx
        except ValueError:
            return True

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from Flowtriq and convert into STIX objects.
        :return: List of STIX objects
        """
        stix_objects = []

        incidents = self.client.get_all_incidents(
            max_total=self.config.flowtriq.import_limit
        )

        if not incidents:
            self.helper.connector_logger.info(
                "[CONNECTOR] No incidents returned from Flowtriq API"
            )
            return stix_objects

        self.helper.connector_logger.info(
            "[CONNECTOR] Fetched incidents from Flowtriq",
            {"count": len(incidents)},
        )

        # Filter by severity threshold and timestamp
        current_state = self.helper.get_state()
        last_incident_time = None
        if current_state and "last_incident_time" in current_state:
            last_incident_time = current_state["last_incident_time"]
        last_incident_dt = _parse_timestamp(last_incident_time)

        processed = 0
        skipped_severity = 0
        skipped_seen = 0
        newest_incident_dt = last_incident_dt
        newest_incident_raw = last_incident_time

        for incident in incidents:
            severity = incident.get("severity", "medium")
            started_at = incident.get("started_at")
            started_dt = _parse_timestamp(started_at)

            # Skip incidents already processed (by parsed datetime comparison)
            if last_incident_dt and started_dt:
                if started_dt <= last_incident_dt:
                    skipped_seen += 1
                    continue

            # Apply severity filter
            if not self._meets_severity_threshold(severity):
                skipped_severity += 1
                continue

            # Fetch extended detail for source IPs if available
            incident_uuid = incident.get("uuid")
            if incident_uuid:
                detail = self.client.get_incident_detail(incident_uuid)
                if detail:
                    # Merge extended fields into the incident
                    incident.update(
                        {
                            k: v
                            for k, v in detail.items()
                            if k not in incident or incident[k] is None
                        }
                    )

            objects = self.converter_to_stix.create_incident_observable(incident)
            if objects:
                stix_objects.extend(objects)
                processed += 1

                # Track the newest incident timestamp for dedup state
                if started_dt:
                    if not newest_incident_dt or started_dt > newest_incident_dt:
                        newest_incident_dt = started_dt
                        newest_incident_raw = started_at

        # Persist the newest incident timestamp for next run deduplication
        if newest_incident_raw and newest_incident_raw != last_incident_time:
            state = self.helper.get_state() or {}
            state["last_incident_time"] = newest_incident_raw
            self.helper.set_state(state)

        self.helper.connector_logger.info(
            "[CONNECTOR] Incident processing summary",
            {
                "processed": processed,
                "skipped_already_seen": skipped_seen,
                "skipped_severity": skipped_severity,
            },
        )

        if stix_objects:
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects

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
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run", {"last_run_datetime": last_run}
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            friendly_name = "Connector Flowtriq DDoS Incidents"
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            stix_objects = self._collect_intelligence()

            if stix_objects:
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

            # Update state
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
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at certain intervals.
        This specific scheduler from the pycti connector helper will also check the queue size
        of a connector. If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size
        exceeds the queue threshold, the connector's main process will not run until the queue
        is ingested and reduced sufficiently, allowing it to restart during the next scheduler
        check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format.
        Example: `CONNECTOR_DURATION_PERIOD=PT1H` => Will run the process every hour.
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
