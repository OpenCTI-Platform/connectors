import mimetypes
import sys
from datetime import datetime, timedelta, timezone

from flashpoint_client import FlashpointClient, FlashpointClientError
from pycti import OpenCTIConnectorHelper
from stix2.exceptions import STIXError

from .config_loader import ConfigLoader
from .converter_to_stix import ConverterToStix
from .indicator_converter_to_stix import IndicatorConverterToStix


class FlashpointConnector:

    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """
        self.config = config
        self.helper = helper

        self.client = FlashpointClient(
            api_base_url="https://api.flashpoint.io",
            api_key=self.config.flashpoint.api_key.get_secret_value(),
        )
        self.converter_to_stix = ConverterToStix(self.helper)
        self.indicator_converter_to_stix = IndicatorConverterToStix(
            helper=self.helper,
            tlp_definition=self.config.flashpoint.indicator_tlp,
        )

    @staticmethod
    def _parse_iso_datetime(value: str | None) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _get_state(self) -> dict:
        """
        Get the state of the connector.
        :return: The state of the connector.
        """
        return self.helper.get_state() or {}

    def _set_state(self, state: dict) -> None:
        """
        Set the state of the connector.
        :param state: The state to set.
        """
        self.helper.set_state(state)
        self.helper.force_ping()  # force update on OpenCTI

    @staticmethod
    def _deduplicate_stix_objects(stix_objects: list) -> list:
        deduplicated_stix_objects = []
        seen_ids: set[str] = set()

        for stix_object in stix_objects:
            object_id = getattr(stix_object, "id", None)
            if isinstance(object_id, str):
                if object_id in seen_ids:
                    continue
                seen_ids.add(object_id)

            deduplicated_stix_objects.append(stix_object)

        return deduplicated_stix_objects

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

    def _import_reports(self, start_date: datetime) -> None:
        """
        :return:
        """
        now = datetime.now(tz=timezone.utc)

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = "Flashpoint Reports run @ " + now.isoformat(timespec="seconds")

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
                    report, self.config.flashpoint.guess_relationships_from_reports
                )
                bundle = self.helper.stix2_create_bundle(stix_report_objects)
                self._send_bundle(work_id=work_id, serialized_bundle=bundle)
            except Exception as err:
                message = f"An error occurred while converting report.id: {str(report.get('id', ''))}, error: {err}"
                self.helper.connector_logger.error(message)

        message = "End of import of reports"
        self.helper.api.work.to_processed(work_id, message)

    def _import_communities(self, start_date: datetime) -> None:
        """
        :param start_date:
        :return:
        """
        now = datetime.now(tz=timezone.utc)

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = "Flashpoint Communities Search run @ " + now.isoformat(
            timespec="seconds"
        )

        # Initiate a new work for reports ingestion
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        for query in self.config.flashpoint.communities_queries:
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
                    self.helper.send_stix2_bundle(bundle, work_id=work_id)
                except Exception as err:
                    message = f"An error occurred while converting document.id: {str(result.get('id', ''))}, error: {err}"
                    self.helper.connector_logger.error(message)

        message = "End of import of communities search"
        self.helper.api.work.to_processed(work_id, message)

    def _import_indicators(self) -> None:
        """
        :return:
        """
        try:
            now = datetime.now(tz=timezone.utc)

            friendly_name = "Flashpoint Indicators run @ " + now.isoformat(
                timespec="seconds"
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self._get_state()

            start_date = self.config.flashpoint.import_start_date
            query_since = start_date
            if "indicators_last_modified" in current_state:
                parsed = self._parse_iso_datetime(
                    current_state["indicators_last_modified"]
                )
                if parsed is not None:
                    start_date = parsed
                    query_since = parsed - timedelta(seconds=1)

            self.helper.connector_logger.info(
                "Fetching indicators from Flashpoint v2 endpoint",
                {"since": query_since.isoformat(timespec="seconds")},
            )

            number_indicators = 0
            max_modified = start_date
            try:
                for page_number, indicators_page in enumerate(
                    self.client.iter_indicators_pages(query_since), start=1
                ):
                    page_stix_objects = []
                    page_indicators_count = 0

                    self.helper.connector_logger.info(
                        "Indicators page fetched",
                        {
                            "page": page_number,
                            "count": len(indicators_page),
                        },
                    )

                    for indicator in indicators_page:
                        stix_objects = (
                            self.indicator_converter_to_stix.convert_indicator_to_stix(
                                indicator
                            )
                        )
                        if len(stix_objects) == 0:
                            continue

                        page_stix_objects.extend(stix_objects)
                        page_indicators_count += 1
                        number_indicators += 1

                        indicator_modified = self._parse_iso_datetime(
                            indicator.get("modified_at")
                        )

                        if (
                            indicator_modified is not None
                            and indicator_modified > max_modified
                        ):
                            max_modified = indicator_modified

                    if len(page_stix_objects) > 0:
                        page_stix_objects = self._deduplicate_stix_objects(
                            page_stix_objects
                        )
                        self.helper.connector_logger.info(
                            "Sending indicators bundle for page",
                            {
                                "page": page_number,
                                "indicators_count": page_indicators_count,
                                "stix_objects_count": len(page_stix_objects),
                            },
                        )
                        bundle = self.helper.stix2_create_bundle(page_stix_objects)
                        self._send_bundle(work_id=work_id, serialized_bundle=bundle)
            except Exception as e:
                self.helper.log_error(str(e))

            current_state["indicators_last_run"] = now.isoformat()
            current_state["indicators_last_modified"] = max_modified.isoformat()
            current_state.pop("indicators_last_seen", None)
            self._set_state(current_state)

            message = (
                "Connector successfully run ("
                + str(number_indicators)
                + " indicators have been processed), storing state "
                + "(indicators_last_run="
                + current_state["indicators_last_run"]
                + ", indicators_last_modified="
                + current_state["indicators_last_modified"]
                + ")"
            )
            self.helper.connector_logger.info(message)
            self.helper.api.work.to_processed(work_id, message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(err)

    def _import_alerts(self, start_date: datetime) -> None:
        """
        :return:
        """
        now = datetime.now(tz=timezone.utc)

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = "Flashpoint Alerts run @ " + now.isoformat(timespec="seconds")

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
                            create_related_entities=self.config.flashpoint.alert_create_related_entities,
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
                            create_related_entities=self.config.flashpoint.alert_create_related_entities,
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
                            create_related_entities=self.config.flashpoint.alert_create_related_entities,
                        )

                    else:
                        self.helper.log_warning(
                            f"Unable to process alert data source format: {alert.get('source')}, skipping it"
                        )
                        continue

                    # pushing STIX alert
                    bundle = self.helper.stix2_create_bundle(stix_alert_objects)
                    self._send_bundle(work_id=work_id, serialized_bundle=bundle)

            except Exception as err:
                message = f"An error occurred while converting alert.id: {str(alert.get('id', ''))}, error: {err}"
                self.helper.connector_logger.error(message)

        message = "End of import of alerts"
        self.helper.api.work.to_processed(work_id, message)

    def _import_ccm_alerts(self, start_date: datetime, fresh_only: bool) -> None:
        """
        Import STIX objects extracted from Compromised Credential Sightings (aka CCM Alerts) from Flashpoint.
        :param start_date: The date from which to start fetching alerts.
        :param fresh_only: If True, only fetch fresh alerts.
        """
        self.helper.connector_logger.info(
            "Going to ingest CCM alerts", {"since": start_date}
        )

        # Initiate a new work for reports ingestion
        now = datetime.now(timezone.utc)
        work_id = self.helper.api.work.initiate_work(
            connector_id=self.helper.connect_id,
            friendly_name="Flashpoint CCM Alerts run @ " + now.isoformat(),
        )
        # Flag to indicate if an error occurred during the process
        # This will be used to mark the work as processed or in error
        in_error = False

        try:
            compromised_credential_sightings = (
                self.client.get_compromised_credential_sightings(
                    since=start_date,
                    fresh_only=fresh_only,
                )
            )
            for compromised_credential_sighting in compromised_credential_sightings:
                try:
                    stix_objects = self.converter_to_stix.convert_ccm_alert_to_incident(
                        alert=compromised_credential_sighting
                    )

                    bundle = self.helper.stix2_create_bundle(stix_objects)
                    bundles_sent = self.helper.send_stix2_bundle(
                        bundle=bundle,
                        work_id=work_id,
                    )

                    self.helper.connector_logger.info(
                        "CCM alerts STIX bundle sent to OpenCTI",
                        {"bundles_count": len(bundles_sent)},
                    )
                except STIXError as err:
                    self.helper.connector_logger.error(
                        "An error occurred while converting CCM alert, skipping it...",
                        {
                            "ccm_alert_id": compromised_credential_sighting.fpid,
                            "error": str(err),
                        },
                    )

            message = "CCM alerts import completed"
            self.helper.connector_logger.info(message)
        except FlashpointClientError as err:
            in_error = True
            message = "An error occurred while fetching CCM alerts"
            self.helper.connector_logger.error(message, {"error": str(err)})
        finally:
            self.helper.api.work.to_processed(work_id, message, in_error)

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
            now = datetime.now(tz=timezone.utc)
            now_iso = now.isoformat(timespec="seconds")

            current_state = self._get_state()
            last_run = (
                datetime.fromisoformat(current_state["last_run"])
                if "last_run" in current_state
                else None
            )

            self.helper.connector_logger.info(
                "Connector last run",
                {"last_run": last_run or "Never"},
            )
            self.helper.connector_logger.info(
                "Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            start_date = last_run or self.config.flashpoint.import_start_date

            if self.config.flashpoint.import_alerts:
                self.helper.connector_logger.info(
                    "Import Alerts enabled, going to fetch Alerts since:",
                    {"since": start_date},
                )
                self._import_alerts(start_date)

            if self.config.flashpoint.import_reports:
                self.helper.connector_logger.info(
                    "Import Reports enabled, going to fetch Reports since:",
                    {"since": start_date},
                )
                self._import_reports(start_date)

            if self.config.flashpoint.import_indicators:
                self.helper.connector_logger.info(
                    "Import Indicators enabled, going to fetch Indicators since:",
                    {"since": last_run or self.config.flashpoint.import_start_date},
                )
                # start date is calculated inside self._import_indicators()
                self._import_indicators()
                # connector's state is updated inside self._import_indicators()

            if self.config.flashpoint.import_communities:
                self.helper.connector_logger.info(
                    "Import Communities Data enabled, going to fetch Communities Data since:",
                    {"since": start_date},
                )
                self._import_communities(start_date)

            if self.config.flashpoint.import_ccm_alerts:
                self.helper.connector_logger.info(
                    "Import CCM Alerts enabled, "
                    f"going to fetch CCM Alerts since: {start_date.isoformat(timespec='seconds')}"
                )
                self._import_ccm_alerts(
                    start_date=start_date,
                    fresh_only=self.config.flashpoint.fresh_ccm_alerts_only,
                )

            # Store the current datetime as last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_datetime": now_iso},
            )

            # need to retrieve the current state as it can be updated in the 'import_indicators' function
            current_state = self._get_state()

            current_state["last_run"] = now_iso
            self._set_state(current_state)

            self.helper.connector_logger.info(
                "Connector successfully run, storing connector's state: ",
                {"connector_name": self.helper.connect_name, "state": current_state},
            )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped...",
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
        self.helper.schedule_process(
            message_callback=self.process_data,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
