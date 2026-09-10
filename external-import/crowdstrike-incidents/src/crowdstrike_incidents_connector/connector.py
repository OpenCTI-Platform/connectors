import itertools
import sys
from datetime import datetime

from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient, CrowdstrikeApiError
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix


class CrowdstrikeIncidentsConnector:
    # Persist the state cursor every N advances rather than on every alert,
    # to avoid one platform round-trip per alert on a large run
    STATE_FLUSH_EVERY = 100

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)

    def _convert_alert(self, alert: dict) -> list:
        """
        Convert a single alert into a self-contained list of STIX 2.1 objects,
        ready to be published as its own bundle.
        :param alert: Alert entity returned by /alerts/entities/alerts/v2
        :return: List of STIX 2.1 objects, empty when the alert is unusable
        """
        stix_incident = self.converter_to_stix.create_incident(alert)
        if stix_incident is None:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Unable to build the incident for the alert",
                {"composite_id": alert.get("composite_id")},
            )
            return []

        # The author is repeated in every bundle so `created_by_ref` never dangles
        return [
            self.converter_to_stix.author,
            stix_incident,
            *self._convert_alert_context(alert, stix_incident),
        ]

    def _convert_alert_context(self, alert: dict, stix_incident) -> list:
        """
        Convert the context of an alert (attack pattern, host, observables) and
        link every object to the incident through explicit relationships.
        :param alert: Alert entity returned by /alerts/entities/alerts/v2
        :param stix_incident: Incident the objects are related to
        :return: List of STIX 2.1 objects and relationships
        """
        stix_objects = []

        def relate(stix_object, relationship_type="related-to", to_incident=True):
            """Append an object and its relationship to the incident"""
            if stix_object is None:
                return None
            stix_objects.append(stix_object)
            if to_incident:
                relationship = self.converter_to_stix.create_relationship(
                    source_id=stix_incident.id,
                    target_id=stix_object.id,
                    relationship_type=relationship_type,
                )
                if relationship:
                    stix_objects.append(relationship)
            return stix_object

        # MITRE technique, only when the id belongs to the ATT&CK referential
        relate(
            self.converter_to_stix.create_mitre_attack_pattern(
                alert.get("technique"), alert.get("technique_id")
            ),
            relationship_type="uses",
        )

        # The impacted host: the incident targets the system
        device = alert.get("device") or {}
        hostname = device.get("hostname")
        stix_system = None
        if hostname:
            stix_system = relate(
                self.converter_to_stix.create_system(hostname),
                relationship_type="targets",
            )
            stix_obs_hostname = relate(
                self.converter_to_stix.create_custom_observable_hostname(hostname)
            )
            if stix_system and stix_obs_hostname:
                stix_objects.append(
                    self.converter_to_stix.create_relationship(
                        source_id=stix_obs_hostname.id,
                        target_id=stix_system.id,
                        relationship_type="related-to",
                    )
                )

        for ip_field in ("local_ip", "external_ip"):
            ip_value = device.get(ip_field)
            if not ip_value:
                continue
            stix_obs_ip = relate(self.converter_to_stix.create_ip_observable(ip_value))
            if stix_obs_ip and stix_system:
                stix_objects.append(
                    self.converter_to_stix.create_relationship(
                        source_id=stix_obs_ip.id,
                        target_id=stix_system.id,
                        relationship_type="related-to",
                    )
                )

        # The Directory is not related to the incident: it is reachable through
        # the File that nests it with `parent_directory_ref`
        stix_directory = self.converter_to_stix.create_directory_observable(alert)
        stix_file = self.converter_to_stix.create_file_observable(
            alert, directory_id=stix_directory.id if stix_directory else None
        )
        if stix_file:
            relate(stix_file)
            if stix_directory:
                stix_objects.append(stix_directory)

        if alert.get("user_name"):
            relate(self.converter_to_stix.create_user_account(alert.get("user_name")))

        return [stix_object for stix_object in stix_objects if stix_object is not None]

    def _publish_alerts(self, work_id, since=None) -> tuple:
        """
        Stream the alerts, publish each one in its own bundle as soon as it is
        converted, and move the state cursor forward along the way.

        The cursor is a watermark on `updated_timestamp`: it is only advanced
        past a timestamp once every alert carrying it has been published, and it
        stops advancing as soon as one alert fails. A run interrupted halfway
        therefore resumes exactly where it stopped, without skipping an alert.

        :param work_id: Id of the work the bundles are attached to
        :param since: ISO-8601 timestamp, only alerts updated after it are collected
        :return: Tuple (cursor to store in the state, number of published alerts)
        """
        cursor = since
        pending_timestamp = None
        cursor_frozen = False
        published = 0
        unpublished_since_flush = 0

        for alert in itertools.chain.from_iterable(
                self.client.iter_alerts(since=since)
        ):
            timestamp = alert.get("updated_timestamp")

            # Every alert carrying `pending_timestamp` has been published, the
            # watermark can safely move up to it
            if (
                    not cursor_frozen
                    and pending_timestamp is not None
                    and timestamp != pending_timestamp
            ):
                cursor = pending_timestamp
                unpublished_since_flush += 1

            stix_objects = self._convert_alert(alert)
            if not stix_objects:
                cursor_frozen = True
                continue

            try:
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(bundle, work_id=work_id)
                published += 1
                pending_timestamp = timestamp
            except Exception as err:
                # Do not let the watermark move past an alert that never reached
                # the queue: the next run has to pick it up again
                cursor_frozen = True
                self.helper.connector_logger.error(
                    "[CONNECTOR] Unable to publish the alert, the state cursor "
                    "stops moving forward for this run",
                    {"composite_id": alert.get("composite_id"), "error": str(err)},
                )
                continue

            if unpublished_since_flush >= self.STATE_FLUSH_EVERY:
                self._store_alert_cursor(cursor)
                unpublished_since_flush = 0

        # The stream is exhausted: the last published timestamp is complete
        if not cursor_frozen and pending_timestamp is not None:
            cursor = pending_timestamp

        self.helper.connector_logger.info(
            "[CONNECTOR] Alerts published",
            {
                "published": published,
                "cursor": cursor,
                "cursor_frozen_by_a_failure": cursor_frozen,
            },
        )
        return cursor, published

    def _store_alert_cursor(self, cursor) -> None:
        """
        Persist the alert watermark in the connector state, keeping the rest of
        the state untouched
        :param cursor: ISO-8601 timestamp of the last fully published alerts
        :return: None
        """
        if not cursor:
            return
        current_state = self.helper.get_state() or {}
        current_state["last_alert_timestamp"] = cursor
        self.helper.set_state(current_state)
        self.helper.connector_logger.debug(
            "[CONNECTOR] State cursor updated", {"last_alert_timestamp": cursor}
        )

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        work_id = None
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

            # Alerts are collected incrementally on their `updated_timestamp`
            last_alert_timestamp = (current_state or {}).get(
                "last_alert_timestamp"
            ) or self.config.import_start_date

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "CrowdStrike Incidents"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Alerts are converted and published one by one, the state cursor
            # moving forward as they reach the queue
            new_last_alert_timestamp, published = self._publish_alerts(
                work_id, since=last_alert_timestamp
            )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.utcfromtimestamp(current_timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            if new_last_alert_timestamp:
                current_state["last_alert_timestamp"] = new_last_alert_timestamp
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, "
                f"{published} alert(s) published, storing last_run as "
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
        except CrowdstrikeApiError as err:
            # The CrowdStrike API returned an error response (already logged in
            # the client): stop this run cleanly and mark the work in error.
            self._terminate_work_in_error(work_id, str(err))
        except Exception as err:
            self.helper.connector_logger.error(str(err))
            self._terminate_work_in_error(work_id, str(err))

    def _terminate_work_in_error(self, work_id, message: str) -> None:
        """
        Close the current work in error so the run does not stay pending
        :param work_id: Id of the work to close, may be None
        :param message: Error message reported on the work
        :return: None
        """
        if work_id is None:
            return
        try:
            self.helper.api.work.to_processed(work_id, message, in_error=True)
        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] Unable to close the work in error", {"error": str(err)}
            )

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
