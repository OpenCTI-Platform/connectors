import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from recorded_future_asi_client import RecordedFutureAsiClient
from recorded_future_asi_client.api_client import (
    HttpRetrySettings,
    RecordedFutureAsiClientConfig,
)


class RecordedFutureAsiConnector:
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
        client (RecordedFutureAsiClient):
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
        Initialize `RecordedFutureAsiConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.client = RecordedFutureAsiClient(
            self.helper,
            RecordedFutureAsiClientConfig(
                base_url=self.config.recorded_future_asi.api_base_url,
                api_key=self.config.recorded_future_asi.api_key.get_secret_value(),
                api_v1_base_url=self.config.recorded_future_asi.api_v1_base_url,
                retry=HttpRetrySettings(
                    max_attempts=self.config.recorded_future_asi.retry_max_attempts,
                    initial_seconds=self.config.recorded_future_asi.retry_initial_seconds,
                    max_seconds=self.config.recorded_future_asi.retry_max_seconds,
                ),
            ),
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.recorded_future_asi.tlp_level,
            project_id=self.config.recorded_future_asi.project_id,
            portal_base_url=self.config.recorded_future_asi.portal_base_url,
        )

    @staticmethod
    def _is_initial_sync(state: dict | None) -> bool:
        """Return True until the first full v2 exposure list cycle completes."""
        return state is None or "last_fetch_time" not in state

    def _exposure_filters(self) -> dict[str, str]:
        recorded_future_asi = self.config.recorded_future_asi
        if recorded_future_asi.filter_severity_min is not None:
            return {"filter_severity_min": recorded_future_asi.filter_severity_min}
        if recorded_future_asi.filter_severity_exact is not None:
            return {"filter_severity_exact": recorded_future_asi.filter_severity_exact}
        return {}

    def _effective_sync_mode(self, initial_sync: bool) -> dict[str, bool | int | str]:
        """Return configured sync mode fields for observability logging."""
        recorded_future_asi = self.config.recorded_future_asi
        if recorded_future_asi.filter_severity_min is not None:
            severity_filter = f"min:{recorded_future_asi.filter_severity_min}"
        elif recorded_future_asi.filter_severity_exact is not None:
            severity_filter = f"exact:{recorded_future_asi.filter_severity_exact}"
        else:
            severity_filter = "none"

        run_limit = recorded_future_asi.run_limit
        return {
            "initial_sync": initial_sync,
            "run_limit": run_limit if run_limit is not None else "unlimited",
            "severity_filter": severity_filter,
        }

    def _collect_initial_intelligence(
        self,
        exposures_cursor: str | None = None,
    ) -> tuple[list, str | None]:
        """
        Collect intelligence from the v2 exposures list during initial sync.

        :param exposures_cursor: Optional pagination cursor when run_limit is set.
        :return: Tuple of STIX objects and optional next cursor for the next batch.
        """
        stix_objects = []
        next_cursor: str | None = None

        filters = self._exposure_filters()

        if self.config.recorded_future_asi.run_limit is None:
            exposures = self.client.list_exposures(
                project_id=self.config.recorded_future_asi.project_id,
                limit=self.config.recorded_future_asi.page_limit,
                **filters,
            )
        else:
            exposures, next_cursor = self.client.list_exposures_batch(
                project_id=self.config.recorded_future_asi.project_id,
                page_limit=self.config.recorded_future_asi.page_limit,
                run_limit=self.config.recorded_future_asi.run_limit,
                cursor=exposures_cursor,
                **filters,
            )
            self.helper.connector_logger.info(
                "[CONNECTOR] Fetched exposure batch from ASI API",
                {
                    "run_limit": self.config.recorded_future_asi.run_limit,
                    "imported_count": len(exposures),
                    "has_next_cursor": next_cursor is not None,
                },
            )

        self.helper.connector_logger.info(
            "[CONNECTOR] Fetched exposures from ASI API",
            {"exposure_count": len(exposures)},
        )

        for exposure in exposures or []:
            signature = exposure["signature"]
            signature_id = signature["id"]

            assets_data = self.client.get_exposure_assets(
                project_id=self.config.recorded_future_asi.project_id,
                signature_id=signature_id,
                limit=self.config.recorded_future_asi.page_limit,
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Fetched exposure assets from ASI API",
                {
                    "signature_id": signature_id,
                    "asset_count": len(assets_data.get("asset_exposures") or []),
                },
            )

            sdk_objects = self.converter_to_stix.build_exposure_objects(
                exposure,
                assets_data,
            )
            stix_objects.extend(obj.to_stix2_object() for obj in sdk_objects)

        if stix_objects:
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return (
            stix_objects,
            next_cursor if self.config.recorded_future_asi.run_limit else None,
        )

    def _collect_incremental_intelligence(
        self,
        state: dict,
    ) -> list:
        """
        Collect exposure deltas from v1 history activity during incremental sync.

        Added rules are enriched via v2 get_exposure_assets. Removed rules emit an
        incident-only cleared update without asset re-fetch.
        """
        stix_objects: list = []

        added_rules, removed_rules = self.client.get_exposure_history(
            project_id=self.config.recorded_future_asi.project_id,
            start=state["last_fetch_time"],
        )

        self.helper.connector_logger.info(
            "[CONNECTOR] Fetched exposure history from ASI API",
            {
                "added_count": len(added_rules),
                "removed_count": len(removed_rules),
            },
        )

        removed_ids = {rule_id for rule in removed_rules if (rule_id := rule.get("id"))}
        severity_filters = {
            "filter_severity_min": self.config.recorded_future_asi.filter_severity_min,
            "filter_severity_exact": (
                self.config.recorded_future_asi.filter_severity_exact
            ),
        }

        for rule in added_rules:
            if not ConverterToStix.rule_matches_severity_filter(
                rule,
                **severity_filters,
            ):
                self.helper.connector_logger.info(
                    "[CONNECTOR] Skipping added history rule outside severity filter",
                    {
                        "signature_id": rule.get("id"),
                        "classification": rule.get("classification"),
                    },
                )
                continue

            rule_id = rule.get("id")
            if not rule_id:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] Skipping added history rule without id",
                    {"rule_name": rule.get("name")},
                )
                continue
            if rule_id in removed_ids:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Skipping added history rule also present in removed_rules",
                    {"signature_id": rule_id},
                )
                continue

            exposure_summary = ConverterToStix.history_rule_to_exposure_summary(rule)
            signature = exposure_summary["signature"]
            signature_id = signature["id"]

            assets_data = self.client.get_exposure_assets(
                project_id=self.config.recorded_future_asi.project_id,
                signature_id=signature_id,
                limit=self.config.recorded_future_asi.page_limit,
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Fetched exposure assets for added history rule",
                {
                    "signature_id": signature_id,
                    "asset_count": len(assets_data.get("asset_exposures") or []),
                },
            )

            sdk_objects = self.converter_to_stix.build_exposure_objects(
                exposure_summary,
                assets_data,
            )
            stix_objects.extend(obj.to_stix2_object() for obj in sdk_objects)

        for rule in removed_rules:
            if not ConverterToStix.rule_matches_severity_filter(
                rule,
                **severity_filters,
            ):
                self.helper.connector_logger.info(
                    "[CONNECTOR] Skipping removed history rule outside severity filter",
                    {
                        "signature_id": rule.get("id"),
                        "classification": rule.get("classification"),
                    },
                )
                continue

            rule_id = rule.get("id")
            if not rule_id:
                continue

            cleared_incident = self.converter_to_stix.build_cleared_incident(rule)
            stix_objects.append(cleared_incident.to_stix2_object())

        if stix_objects:
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects

    def _persist_sync_state(
        self,
        now: datetime,
        *,
        advance_fetch_time: bool,
        exposures_cursor: str | None | bool,
    ) -> str:
        """Update connector state after a successful run."""
        current_timestamp = int(datetime.timestamp(now))
        self.helper.connector_logger.debug(
            "Getting current state and update it with last run of the connector",
            {"current_timestamp": current_timestamp},
        )
        current_state = self.helper.get_state() or {}
        current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
        last_run_datetime = datetime.fromtimestamp(
            current_timestamp, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        current_state["last_run"] = current_state_datetime
        current_state.pop("known_exposures", None)

        if advance_fetch_time:
            current_state["last_fetch_time"] = current_timestamp

        if exposures_cursor is not False:
            if exposures_cursor:
                current_state["exposures_cursor"] = exposures_cursor
            else:
                current_state.pop("exposures_cursor", None)

        self.helper.set_state(current_state)
        return last_run_datetime

    def _log_last_run_status(self, current_state: dict) -> None:
        """Log whether the connector has run before."""
        if "last_run" in current_state:
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector last run",
                {"last_run_datetime": current_state["last_run"]},
            )
            return

        self.helper.connector_logger.info("[CONNECTOR] Connector has never run...")

    def _initiate_stix_import_work(self) -> str:
        """Create an OpenCTI work item for a non-empty STIX import."""
        friendly_name = "Recorded Future ASI Exposures Import"
        return self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

    def _deliver_stix_bundle(self, stix_objects: list, work_id: str) -> None:
        """Build and send a STIX bundle for an existing work item."""
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

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        work_id: str | None = None
        try:
            self.converter_to_stix.reset_entity_caches()

            # Get the current state
            now = datetime.now(timezone.utc)
            current_state = self.helper.get_state() or {}
            self._log_last_run_status(current_state)

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            initial_sync = self._is_initial_sync(current_state)
            self.helper.connector_logger.info(
                "[CONNECTOR] Effective sync mode",
                self._effective_sync_mode(initial_sync),
            )
            next_cursor: str | None = None

            if initial_sync:
                exposures_cursor = None
                if self.config.recorded_future_asi.run_limit is not None:
                    exposures_cursor = current_state.get("exposures_cursor")

                stix_objects, next_cursor = self._collect_initial_intelligence(
                    exposures_cursor,
                )
                initial_cycle_complete = next_cursor is None
            else:
                stix_objects = self._collect_incremental_intelligence(current_state)
                initial_cycle_complete = False

            if stix_objects:
                work_id = self._initiate_stix_import_work()
                self._deliver_stix_bundle(stix_objects, work_id)

            self.helper.connector_logger.info(
                "[CONNECTOR] Collection complete",
                {"stix_object_count": len(stix_objects)},
            )

            # Persist state after a successful collection cycle, even when no bundle is sent.
            if self.config.recorded_future_asi.run_limit is not None and initial_sync:
                exposures_cursor_to_store: str | None | bool = next_cursor
            else:
                exposures_cursor_to_store = False

            last_run_datetime = self._persist_sync_state(
                now,
                advance_fetch_time=not initial_sync or initial_cycle_complete,
                exposures_cursor=exposures_cursor_to_store,
            )

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
            )

            if work_id is not None:
                self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            if work_id is not None:
                self.helper.api.work.to_processed(
                    work_id,
                    "[CONNECTOR] Connector stopped",
                    in_error=True,
                )
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))
            if work_id is not None:
                self.helper.api.work.to_processed(work_id, str(err), in_error=True)

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
            - If `CONNECTOR_RUN_LIMIT=50`, then the connector will process a maximum of 50 exposures per run.
            - If `CONNECTOR_DURATION_PERIOD=PT1H`, then the connector is running every hour.

        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
