import datetime
import mimetypes
import sys

import pytz
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .misp_converter_to_stix import MISPConverterToStix


class FlashpointConnector:

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)
        self.misp_converter_to_stix = MISPConverterToStix(self.helper, self.config)

    def _send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        """
        :param work_id:
        :param serialized_bundle:
        :return:
        """
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                work_id=work_id,
            )
        except Exception as ex:
            self.helper.log_error(f"An error occurred while sending STIX bundle: {ex}")

    def _import_reports(self, start_date):
        """
        :return:
        """
        now = datetime.datetime.now(datetime.UTC)

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = "Flashpoint Reports run @ " + now.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Initiate a new work for reports ingestion
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        reports = []
        try:
            reports = self.client.get_reports(start_date)
        except Exception as err:
            message = f"An error occurred while fetching reports, error: {err}"
            self.helper.connector_logger.error(message)

        self.helper.connector_logger.info(f"Going to ingest: {len(reports)} reports")
        for report in reports:
            try:
                stix_report_objects = self.converter_to_stix.convert_flashpoint_report(
                    report
                )
                bundle = self.helper.stix2_create_bundle(stix_report_objects)
                self._send_bundle(work_id=work_id, serialized_bundle=bundle)
            except Exception as err:
                message = f"An error occurred while converting report.id: {str(report.get("id", ""))}, error: {err}"
                self.helper.connector_logger.error(message)

        message = "End of import of reports"
        self.helper.api.work.to_processed(work_id, message)

    def _import_communities(self, start_date):
        """
        :param start_date:
        :return:
        """
        now = datetime.datetime.now(datetime.UTC)

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = "Flashpoint Communities Search run @ " + now.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        # Initiate a new work for reports ingestion
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        for query in self.config.communities_queries:
            results = []
            try:
                results = self.client.communities_search(query, start_date)
            except Exception as err:
                message = (
                    f"An error occurred while searching in communities, error: {err}"
                )
                self.helper.connector_logger.error(message)
            for result in results:
                try:
                    stix_objects = self.converter_to_stix.convert_communities_search(
                        result
                    )
                    bundle = self.helper.stix2_create_bundle(stix_objects)
                    self.helper.send_stix2_bundle(
                        bundle,
                        work_id=work_id,
                    )
                except Exception as err:
                    message = f"An error occurred while converting document.id: {str(result.get("id", ""))}, error: {err}"
                    self.helper.connector_logger.error(message)

        message = "End of import of communities search"
        self.helper.api.work.to_processed(work_id, message)

    def _import_misp_feed(self):
        """
        :return:
        """
        try:
            now = datetime.datetime.now(datetime.UTC)

            friendly_name = (
                "Flashpoint MISP Feed run @ " + now.astimezone(pytz.UTC).isoformat()
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            if (
                current_state is not None
                and "misp_last_run" in current_state
                and "misp_last_event_timestamp" in current_state
                and "misp_last_event" in current_state
            ):
                last_run = parse(current_state["misp_last_run"])
                last_event = parse(current_state["misp_last_event"])
                last_event_timestamp = current_state["misp_last_event_timestamp"]
                self.helper.log_info(
                    "Connector MISP Feed last run: "
                    + last_run.astimezone(pytz.UTC).isoformat()
                )
                self.helper.log_info(
                    "Connector MISP Feed latest event: "
                    + last_event.astimezone(pytz.UTC).isoformat()
                )
            elif current_state is not None and "misp_last_run" in current_state:
                last_run = parse(current_state["misp_last_run"])
                last_event = last_run
                last_event_timestamp = int(last_event.timestamp())
                self.helper.log_info(
                    "Connector MISP Feed last run: "
                    + last_run.astimezone(pytz.UTC).isoformat()
                )
                self.helper.log_info(
                    "Connector MISP Feed latest event: "
                    + last_event.astimezone(pytz.UTC).isoformat()
                )
            else:
                if self.config.import_start_date is not None:
                    last_event = parse(self.config.import_start_date)
                    last_event_timestamp = int(last_event.timestamp())
                else:
                    last_event_timestamp = int(now.timestamp())
                self.helper.log_info("Connector MISP Feed has never run")

            number_events = 0
            try:
                manifest_data = self.client.get_misp_feed_manifest()
                items = []
                for key, value in manifest_data.items():
                    value["timestamp"] = int(value["timestamp"])
                    items.append({**value, "event_key": key})
                items = sorted(items, key=lambda d: d["timestamp"])
                for item in items:
                    if item["timestamp"] > last_event_timestamp:
                        last_event_timestamp = item["timestamp"]
                        self.helper.log_info(
                            "Processing MISP event "
                            + item["info"]
                            + " (date="
                            + item["date"]
                            + ", modified="
                            + datetime.datetime.fromtimestamp(
                                last_event_timestamp, datetime.UTC
                            )
                            .astimezone(pytz.UTC)
                            .isoformat()
                            + ")"
                        )

                        misp_event = self.client.get_misp_event_file(
                            item["event_key"] + ".json"
                        )
                        bundle = self.misp_converter_to_stix.convert_misp_event_to_stix(
                            misp_event
                        )
                        self.helper.log_info("Sending event STIX2 bundle...")
                        self._send_bundle(work_id, bundle)
                        number_events = number_events + 1
                        message = (
                            "Event processed, storing state (misp_last_run="
                            + now.astimezone(pytz.utc).isoformat()
                            + ", misp_last_event="
                            + datetime.datetime.utcfromtimestamp(last_event_timestamp)
                            .astimezone(pytz.UTC)
                            .isoformat()
                            + ", misp_last_event_timestamp="
                            + str(last_event_timestamp)
                        )
                        current_state = self.helper.get_state()
                        if current_state is None:
                            self.helper.set_state(
                                {
                                    "misp_last_run": now.astimezone(
                                        pytz.utc
                                    ).isoformat(),
                                    "misp_last_event": datetime.datetime.utcfromtimestamp(
                                        last_event_timestamp
                                    )
                                    .astimezone(pytz.UTC)
                                    .isoformat(),
                                    "misp_last_event_timestamp": last_event_timestamp,
                                }
                            )
                        else:
                            current_state["misp_last_run"] = now.astimezone(
                                pytz.utc
                            ).isoformat()
                            current_state["misp_last_event"] = (
                                datetime.datetime.utcfromtimestamp(last_event_timestamp)
                                .astimezone(pytz.UTC)
                                .isoformat()
                            )
                            current_state["misp_last_event_timestamp"] = (
                                last_event_timestamp
                            )
                            self.helper.set_state(current_state)
                        self.helper.log_info(message)
            except Exception as e:
                self.helper.log_error(str(e))

            # Store the current timestamp as a last run
            message = (
                "Connector successfully run ("
                + str(number_events)
                + " events have been processed), storing state (misp_last_run="
                + now.astimezone(pytz.utc).isoformat()
                + ", misp_last_event="
                + datetime.datetime.utcfromtimestamp(last_event_timestamp)
                .astimezone(pytz.UTC)
                .isoformat()
                + ", misp_last_event_timestamp="
                + str(last_event_timestamp)
                + ")"
            )
            self.helper.log_info(message)
            self.helper.api.work.to_processed(work_id, message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(err)

    def _import_alerts(self, start_date):
        """
        :return:
        """
        now = datetime.datetime.now(datetime.UTC)

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = "Flashpoint Alerts run @ " + now.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Initiate a new work for reports ingestion
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        alerts = []
        try:
            alerts = self.client.get_alerts(start_date)
        except Exception as err:
            message = f"An error occurred while fetching alerts, error: {err}"
            self.helper.connector_logger.error(message)

        self.helper.connector_logger.info(f"Going to ingest: {len(alerts)} alerts")
        for alert in alerts:
            try:
                # common useful alert information
                if alert.get("source", None) is None:
                    self.helper.log_warning(
                        "Invalid alert data format, alert doesn't contains a 'source' field, skipping it"
                    )
                    continue

                else:
                    processed_alert = {}
                    processed_alert["alert_id"] = str(alert.get("id"))
                    processed_alert["channel_type"] = (
                        alert.get("resource", {}).get("site", {}).get("title", "")
                    )
                    processed_alert["channel_name"] = (
                        alert.get("resource", {}).get("title")
                        if "title" in alert.get("resource", {})
                        else processed_alert["channel_type"]
                    )
                    processed_alert["author"] = (
                        alert.get("resource", {})
                        .get("site_actor", {})
                        .get("names", {})
                        .get("handle", "")
                    )
                    processed_alert["created_at"] = alert.get("created_at", "")
                    processed_alert["alert_status"] = (
                        alert.get("status")
                        if alert.get("status") is not None
                        else "None"
                    )
                    processed_alert["alert_source"] = alert.get("source")
                    processed_alert["alert_reason"] = alert.get("reason", {}).get(
                        "name", ""
                    )
                    processed_alert["highlight_text"] = alert.get("highlight_text", "")
                    processed_alert["document_id"] = alert.get("resource", {}).get("id")
                    processed_alert["flashpoint_url"] = (
                        "https://app.flashpoint.io/search/context/"
                        + alert.get("source")
                        + "/"
                        + alert.get("resource", {}).get("id")
                    )

                    if alert.get("source") == "communities":
                        alert_document = self.client.get_communities_doc(
                            alert.get("resource").get("id")
                        )
                        processed_alert["channel_aliases"] = alert_document.get(
                            "results"
                        ).get("site_actor_alias", [])
                        processed_alert["channel_ref"] = alert_document.get(
                            "results"
                        ).get("container_external_uri", None)
                        stix_alert_objects = self.converter_to_stix.alert_to_incident(
                            alert=processed_alert,
                            create_related_entities=self.config.alert_create_related_entities,
                        )

                    elif alert.get("source") == "media":
                        alert_document = self.client.get_media_doc(
                            alert.get("resource").get("id")
                        )
                        if alert_document.get("storage_uri", None):
                            media_content, media_type = self.client.get_media(
                                alert_document.get("storage_uri")
                            )
                            if media_content:
                                guess_file_extension = mimetypes.guess_extension(
                                    media_type
                                )
                                processed_alert["media_content"] = media_content
                                processed_alert["media_type"] = media_type
                                processed_alert["media_name"] = (
                                    alert_document.get("media_id")
                                    + guess_file_extension
                                )

                        stix_alert_objects = self.converter_to_stix.alert_to_incident(
                            alert=processed_alert,
                            create_related_entities=self.config.alert_create_related_entities,
                        )

                    elif alert.get("source").startswith("data_exposure"):
                        processed_alert["channel_type"] = alert.get("resource", {}).get(
                            "source"
                        )
                        processed_alert["channel_name"] = alert.get("resource", {}).get(
                            "repo"
                        )
                        processed_alert["author"] = alert.get("resource", {}).get(
                            "owner"
                        )
                        processed_alert["flashpoint_url"] = alert.get(
                            "resource", {}
                        ).get("url")
                        stix_alert_objects = self.converter_to_stix.alert_to_incident(
                            alert=processed_alert,
                            create_related_entities=self.config.alert_create_related_entities,
                        )

                    else:
                        self.helper.log_warning(
                            f"Unable to process alert data source format: {alert.get("source")}, skipping it"
                        )
                        continue

                    # pushing STIX alert
                    bundle = self.helper.stix2_create_bundle(stix_alert_objects)
                    self._send_bundle(work_id=work_id, serialized_bundle=bundle)

            except Exception as err:
                message = f"An error occurred while converting alert.id: {str(alert.get("id", ""))}, error: {err}"
                self.helper.connector_logger.error(message)

        message = "End of import of alerts"
        self.helper.api.work.to_processed(work_id, message)

    def process_data(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.datetime.now()
            current_state_datetime = now.astimezone(pytz.UTC).isoformat()

            current_timestamp = int(datetime.datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                if current_state is None:
                    self.helper.set_state(
                        {
                            "last_run": parse(self.config.import_start_date)
                            .astimezone(pytz.UTC)
                            .isoformat()
                        }
                    )
                else:
                    if "last_run" not in current_state:
                        current_state["last_run"] = (
                            parse(self.config.import_start_date)
                            .astimezone(pytz.UTC)
                            .isoformat()
                        )
                        self.helper.set_state(current_state)

            current_state = self.helper.get_state()

            self.helper.connector_logger.info(
                "Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence

            if self.config.import_alerts:
                start_date = parse(current_state["last_run"]).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                )
                self.helper.connector_logger.info(
                    f"Import Alerts enable, "
                    f"going to fetch Alerts since: {start_date}"
                )
                self._import_alerts(start_date)

            if self.config.import_reports:
                start_date = current_state["last_run"]
                self.helper.connector_logger.info(
                    f"Import Reports enable, "
                    f"going to fetch Reports since: {start_date}"
                )
                self._import_reports(start_date)

            if self.config.import_indicators:
                start_date = current_state["last_run"]
                self.helper.connector_logger.info(
                    f"Import Indicators enable, "
                    f"going to fetch Indicators since: {start_date}"
                )
                self._import_misp_feed()

            if self.config.import_communities:
                start_date = parse(current_state["last_run"]).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                self.helper.connector_logger.info(
                    f"Import Communities Data enable, "
                    f"going to fetch Communities Data since: {start_date}"
                )
                self._import_communities(start_date)

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()

            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(current_state_datetime)
            )
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
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """

        if self.config.duration_period:
            self.helper.schedule_iso(
                message_callback=self.process_data,
                duration_period=self.config.duration_period,
            )
        else:
            self.helper.log_warning(
                "'interval' option is deprecated.Please use 'duration_period' instead"
            )
            self.helper.schedule_unit(
                message_callback=self.process_data,
                duration_period=self.config.flashpoint_interval,
                time_unit=self.helper.TimeUnit.MINUTES,
            )
