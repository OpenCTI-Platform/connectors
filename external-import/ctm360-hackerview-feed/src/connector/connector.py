import threading
from datetime import datetime, timezone

from connector.case_status_tracker import CaseStatusTracker
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from ctm360_hv_client.api_client import CTM360HvClient
from pycti import OpenCTIConnectorHelper


class CTM360HackerViewConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = CTM360HvClient(
            helper=self.helper,
            base_url=str(config.ctm360_hackerview_feed.api_base_url),
            api_key=config.ctm360_hackerview_feed.api_key.get_secret_value(),
        )
        self.converter = ConverterToStix(self.helper)

        self._interval = config.connector.duration_period.total_seconds()
        self._import_issues = config.ctm360_hackerview_feed.import_issues
        self._import_resolved_issues = (
            config.ctm360_hackerview_feed.import_resolved_issues
        )
        self._import_domain_assets = config.ctm360_hackerview_feed.import_domain_assets
        self._import_host_assets = config.ctm360_hackerview_feed.import_host_assets
        self._import_ip_assets = config.ctm360_hackerview_feed.import_ip_assets

        self._lock = threading.Lock()
        self._enable_tracking = config.ctm360_hackerview_feed.enable_status_tracking
        self._tracker = None

    def run(self):
        if self._enable_tracking:
            self._tracker = CaseStatusTracker(
                helper=self.helper,
                client=self.client,
                poll_interval=int(
                    self.config.ctm360_hackerview_feed.status_poll_interval.total_seconds()
                ),
                lock=self._lock,
            )
            self._tracker.start()

        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector schedule",
            {"interval_seconds": self._interval},
        )

        try:
            self.helper.schedule_process(
                message_callback=self._callback,
                duration_period=self._interval,
            )
        finally:
            if self._tracker:
                self._tracker.stop()

    def _callback(self):
        # Ping inside the scheduled callback so connectivity is re-checked every
        # run and a transient API outage does not kill the connector process.
        try:
            self.client.ping()
            self.helper.connector_logger.info("[CONNECTOR] API connection verified")
        except Exception as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] API ping failed — skipping this run",
                {"error": str(exc)},
            )
            return

        try:
            self._import_data()
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Stopping")
            raise
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Import cycle failed", {"error": str(e)}
            )

    def _import_data(self):
        with self._lock:
            state = self.helper.get_state() or {}
        last_run = state.get("last_run", None)
        now = datetime.now(timezone.utc)

        # Reset so a category that is disabled or fails this cycle cannot leak
        # CaseIncidents collected on a previous run into the tracker.
        self.converter.issue_case_metadata = []

        all_objects = []
        errors = []
        categories_attempted = 0

        try:
            if self._import_issues:
                categories_attempted += 1
                try:
                    data = self.client.get_issues(first_seen=last_run)
                    objects = self.converter.issues_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Issues processed",
                        {"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"issues: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Issues fetch failed", {"error": str(e)}
                    )

            if self._import_resolved_issues:
                categories_attempted += 1
                try:
                    data = self.client.get_resolved_issues(from_date=last_run)
                    objects = self.converter.resolved_issues_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Resolved issues processed",
                        {"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"resolved_issues: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Resolved issues fetch failed",
                        {"error": str(e)},
                    )

            if self._import_domain_assets:
                categories_attempted += 1
                try:
                    data = self.client.get_domain_assets()
                    objects = self.converter.domain_assets_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Domain assets processed",
                        {"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"domain_assets: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Domain assets fetch failed",
                        {"error": str(e)},
                    )

            if self._import_host_assets:
                categories_attempted += 1
                try:
                    data = self.client.get_host_assets()
                    objects = self.converter.host_assets_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Host assets processed",
                        {"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"host_assets: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Host assets fetch failed",
                        {"error": str(e)},
                    )

            if self._import_ip_assets:
                categories_attempted += 1
                try:
                    data = self.client.get_ip_assets()
                    objects = self.converter.ip_assets_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] IP assets processed",
                        {"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"ip_assets: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] IP assets fetch failed", {"error": str(e)}
                    )

            if len(errors) == categories_attempted and categories_attempted > 0:
                raise ValueError(
                    f"All {categories_attempted} categories failed: {'; '.join(errors)}"
                )

            # Only create a Work when there is actually a bundle to ingest.
            work_id = None
            if all_objects:
                friendly_name = (
                    f"CTM360-HackerView import @ {now.strftime('%Y-%m-%dT%H:%M:%SZ')}"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                bundle = self.helper.stix2_create_bundle(all_objects)
                self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                msg = f"Imported {len(all_objects)} objects"
            else:
                msg = "No new data to import"

            # CaseIncidents are produced by the converter and shipped in the
            # bundle above (CustomObjectCaseIncident with deterministic ids), so
            # they are deduplicated by the OpenCTI worker. Register them with the
            # status tracker — keyed by the deterministic case id — so later
            # HackerView status changes can be reflected without any API create.
            case_metadata = self.converter.issue_case_metadata
            if case_metadata:
                msg += f", {len(case_metadata)} case(s) in bundle"
                if self._tracker:
                    self._tracker.register_cases(case_metadata)

            if errors:
                msg += f" (partial: {len(errors)} categories failed)"

            self.helper.connector_logger.info("[CONNECTOR] Import done", {"msg": msg})
            if work_id:
                self.helper.api.work.to_processed(work_id, msg)

            # Merge into existing state under the shared lock so the status
            # tracker's tracked_cases are not wiped and writes do not race.
            with self._lock:
                new_state = self.helper.get_state() or {}
                new_state["last_run"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
                self.helper.set_state(new_state)

        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Import failed", {"error": str(e)}
            )
            raise
