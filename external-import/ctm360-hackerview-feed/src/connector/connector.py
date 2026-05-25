import sys
import threading
import time
from datetime import datetime, timezone

from connector.case_status_tracker import CaseStatusTracker
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from ctm360_hv_client.api_client import CTM360HvClient
from pycti import OpenCTIConnectorHelper

HV_SOURCE_NAME = "CTM360-HackerView"


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
        self._author_opencti_id = None

    def _resolve_author_id(self) -> str:
        """Create or retrieve the HackerView Identity in OpenCTI and return its internal ID."""
        try:
            result = self.helper.api.identity.create(
                type="Organization",
                name="HackerView",
                description="CTM360 External Attack Surface Management platform",
            )
            return result.get("id", "") if result else ""
        except Exception as e:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Failed to resolve author identity", {"error": str(e)}
            )
            return ""

    def run(self):
        try:
            self.client.ping()
            self.helper.connector_logger.info("[CONNECTOR] API connection verified")
        except Exception as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] API ping failed — stopping", {"error": str(exc)}
            )
            sys.exit(1)

        self._author_opencti_id = self._resolve_author_id()
        if self._author_opencti_id:
            self.helper.connector_logger.info(
                "[CONNECTOR] Author identity resolved",
                {"id": self._author_opencti_id},
            )

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
            "[CONNECTOR] Starting import loop",
            {"interval_seconds": self._interval},
        )

        self.helper.schedule_process(
            message_callback=self._callback,
            duration_period=self._interval,
        )

    def _callback(self):
        try:
            self._import_data()
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Stopping")
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] Import cycle failed", {"error": str(e)}
            )

    def _import_data(self):
        state = self.helper.get_state() or {}
        last_run = state.get("last_run", None)
        now = datetime.now(timezone.utc)

        friendly_name = (
            f"CTM360-HackerView import @ {now.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        work_id = self.helper.api.work.initiate_work(
            self.config.connector.id, friendly_name
        )

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
                error_msg = (
                    f"All {categories_attempted} categories failed: {'; '.join(errors)}"
                )
                self.helper.api.work.to_processed(work_id, error_msg, in_error=True)
                raise ValueError(error_msg)

            if all_objects:
                bundle = self.helper.stix2_create_bundle(all_objects)
                self.helper.send_stix2_bundle(
                    bundle,
                    update=True,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                msg = f"Imported {len(all_objects)} objects"
            else:
                msg = "No new data to import"

            # Create CaseIncidents for HackerView issues
            case_count = self._create_case_incidents(self.converter.issue_case_metadata)
            if case_count > 0:
                msg += f", {case_count} case(s) created"

            if errors:
                msg += f" (partial: {len(errors)} categories failed)"

            self.helper.connector_logger.info("[CONNECTOR] Import done", {"msg": msg})
            self.helper.api.work.to_processed(work_id, msg)
            self.helper.set_state({"last_run": now.strftime("%Y-%m-%dT%H:%M:%SZ")})

        except Exception as e:
            if "All" not in str(e):
                self.helper.connector_logger.error(
                    "[CONNECTOR] Import failed", {"error": str(e)}
                )
                self.helper.api.work.to_processed(work_id, str(e), in_error=True)
            raise

    def _create_case_incidents(self, case_metadata: list) -> int:
        """Create CaseIncident objects in OpenCTI for each HackerView issue."""
        if not case_metadata:
            return 0
        created = 0
        for meta in case_metadata:
            try:
                self._create_case_incident(meta)
                created += 1
            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Failed to create CaseIncident",
                    {"ticket_id": meta.get("ticket_id"), "error": str(e)},
                )
        self.helper.connector_logger.info(
            "[CONNECTOR] CaseIncidents created",
            {"created": created, "total": len(case_metadata)},
        )
        return created

    def _create_case_incident(self, meta: dict):
        """Create a single CaseIncident in OpenCTI via pycti API."""
        ticket_id = meta["ticket_id"]

        # Create ExternalReference first, then pass its ID
        ext_ref_kwargs = {
            "source_name": HV_SOURCE_NAME,
            "external_id": ticket_id,
        }
        if meta.get("hackerview_link"):
            ext_ref_kwargs["url"] = meta["hackerview_link"]

        ext_ref_result = self.helper.api.external_reference.create(**ext_ref_kwargs)
        ext_ref_id = ext_ref_result.get("id") if ext_ref_result else None
        ext_refs = [ext_ref_id] if ext_ref_id else []

        create_kwargs = {
            "name": meta["name"],
            "description": meta["description"],
            "severity": meta["severity"],
            "priority": meta["priority"],
            "created": meta["created"],
            "externalReferences": ext_refs,
            "objects": meta.get("linked_stix_ids", []),
        }
        if self._author_opencti_id:
            create_kwargs["createdBy"] = self._author_opencti_id

        result = self.helper.api.case_incident.create(**create_kwargs)

        case_id = result.get("id", "") if result else ""
        if case_id:
            self.helper.connector_logger.info(
                "[CONNECTOR] CaseIncident created",
                {"case_id": case_id, "ticket_id": ticket_id, "name": meta["name"]},
            )
            # Add labels individually
            for label in meta.get("labels", []):
                try:
                    self.helper.api.stix_domain_object.add_label(
                        id=case_id, label_name=label
                    )
                except Exception as e:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Failed to add label",
                        {"case_id": case_id, "label": label, "error": str(e)},
                    )
            # Register with status tracker
            if self._tracker:
                self._tracker.register_case(
                    ticket_id=ticket_id,
                    case_incident_id=case_id,
                    initial_status="unknown",
                )
            # Set response types
            resp_types = meta.get("response_types", [])
            if resp_types:
                try:
                    self.helper.api.stix_domain_object.update_field(
                        id=case_id,
                        input={"key": "response_types", "value": resp_types},
                    )
                except Exception as e:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] Failed to set response_types",
                        {"case_id": case_id, "error": str(e)},
                    )
