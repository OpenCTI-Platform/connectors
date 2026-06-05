import sys
import threading
import time
from datetime import datetime, timezone

from connector.case_status_tracker import CaseStatusTracker
from connector.converter_to_stix import ConverterToStix
from ctm360_cbs_client.api_client import CTM360CbsClient
from pycti import OpenCTIConnectorHelper

CBS_SOURCE_NAME = "CTM360-CyberBlindSpot"


class CTM360CyberBlindSpotConnector:
    def __init__(self, config, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = CTM360CbsClient(
            helper=self.helper,
            base_url=str(config.ctm360_cbs.api_base_url),
            api_key=config.ctm360_cbs.api_key.get_secret_value(),
        )
        self.converter = ConverterToStix(self.helper)
        self._lock = threading.Lock()
        self._enable_tracking = config.ctm360_cbs.enable_status_tracking
        self._tracker = None
        self._interval = config.ctm360_cbs.import_interval
        self._import_incidents = config.ctm360_cbs.import_incidents
        self._import_malware_logs = config.ctm360_cbs.import_malware_logs
        self._import_breached_creds = config.ctm360_cbs.import_breached_credentials
        self._import_card_leaks = config.ctm360_cbs.import_card_leaks
        self._import_domain_protection = config.ctm360_cbs.import_domain_protection
        self._author_opencti_id = None

    def _resolve_author_id(self) -> str:
        """Create or retrieve the CyberBlindSpot Identity in OpenCTI and return its internal ID."""
        try:
            result = self.helper.api.identity.create(
                type="Organization",
                name="CyberBlindSpot",
                description="CTM360 Digital Risk Protection platform",
            )
            return result.get("id", "") if result else ""
        except Exception as e:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Failed to resolve author identity", meta={"error": str(e)}
            )
            return ""

    def run(self):
        try:
            self.client.ping()
            self.helper.connector_logger.info("[CONNECTOR] API connection verified")
        except Exception as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] API ping failed — stopping", meta={"error": str(exc)}
            )
            sys.exit(1)

        self._author_opencti_id = self._resolve_author_id()
        if self._author_opencti_id:
            self.helper.connector_logger.info(
                "[CONNECTOR] Author identity resolved",
                meta={"id": self._author_opencti_id},
            )

        if self._enable_tracking:
            self._tracker = CaseStatusTracker(
                helper=self.helper,
                client=self.client,
                poll_interval=self.config.ctm360_cbs.status_poll_interval,
                lock=self._lock,
            )
            self._tracker.start()

        self.helper.connector_logger.info(
            "[CONNECTOR] Starting import loop",
            meta={"interval_seconds": self._interval},
        )
        while True:
            try:
                self._import_data()
            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("[CONNECTOR] Stopping")
                break
            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Import cycle failed", meta={"error": str(e)}
                )
            time.sleep(self._interval)

    def _import_data(self):
        state = self.helper.get_state() or {}
        last_run = state.get("last_run", None)
        now = datetime.now(timezone.utc)

        friendly_name = (
            f"CTM360-CyberBlindSpot import @ {now.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        all_objects = []
        errors = []
        categories_attempted = 0
        # Tracks whether the total-failure path already marked the work item as
        # errored, so the except block doesn't report it a second time (and so
        # the decision no longer depends on the wording of the exception).
        work_marked_in_error = False

        try:
            if self._import_incidents:
                categories_attempted += 1
                try:
                    data = self.client.get_incidents(date_from=last_run)
                    objects = self.converter.incidents_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Incidents processed",
                        meta={"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"incidents: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Incidents fetch failed", meta={"error": str(e)}
                    )

            if self._import_malware_logs:
                categories_attempted += 1
                try:
                    data = self.client.get_malware_logs(date_from=last_run)
                    objects = self.converter.malware_logs_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Malware logs processed",
                        meta={"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"malware_logs: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Malware logs fetch failed", meta={"error": str(e)}
                    )

            if self._import_breached_creds:
                categories_attempted += 1
                try:
                    data = self.client.get_breached_credentials(date_from=last_run)
                    objects = self.converter.breached_credentials_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Breached credentials processed",
                        meta={"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"breached_credentials: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Breached credentials fetch failed",
                        meta={"error": str(e)},
                    )

            if self._import_card_leaks:
                categories_attempted += 1
                try:
                    data = self.client.get_card_leaks(date_from=last_run)
                    objects = self.converter.card_leaks_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Card leaks processed",
                        meta={"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"card_leaks: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Card leaks fetch failed", meta={"error": str(e)}
                    )

            if self._import_domain_protection:
                categories_attempted += 1
                try:
                    data = self.client.get_domain_protection(date_from=last_run)
                    objects = self.converter.domain_protection_to_stix(data)
                    all_objects.extend(objects)
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Domain protection processed",
                        meta={"count": len(data), "stix_objects": len(objects)},
                    )
                except Exception as e:
                    errors.append(f"domain_protection: {e}")
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Domain protection fetch failed",
                        meta={"error": str(e)},
                    )

            if len(errors) == categories_attempted and categories_attempted > 0:
                error_msg = (
                    f"All {categories_attempted} categories failed: {'; '.join(errors)}"
                )
                work_marked_in_error = True
                self.helper.api.work.to_processed(work_id, error_msg, in_error=True)
                raise ValueError(error_msg)

            # Every category converter prepends the shared author Identity
            # (and the same observable can surface in more than one category),
            # so concatenating the per-category outputs repeats objects that
            # share a STIX id. De-duplicate by id before bundling to avoid
            # shipping the same object multiple times.
            seen_ids = set()
            deduped_objects = []
            for obj in all_objects:
                obj_id = getattr(obj, "id", None)
                if obj_id is not None and obj_id in seen_ids:
                    continue
                if obj_id is not None:
                    seen_ids.add(obj_id)
                deduped_objects.append(obj)

            # Because every converter prepends the author Identity, a cycle
            # where all endpoints returned no data still yields an author-only
            # list. Treat a bundle that carries nothing but the author as "no
            # data" and skip sending it, so the connector does not create a
            # noisy author-only work item every cycle.
            author_id = getattr(self.converter.author, "id", None)
            content_objects = [
                obj for obj in deduped_objects if getattr(obj, "id", None) != author_id
            ]
            if content_objects:
                all_objects = deduped_objects
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

            # Create CaseIncidents for CBS incidents
            case_count = self._create_case_incidents(
                self.converter.incident_case_metadata
            )
            if case_count > 0:
                msg += f", {case_count} case(s) created"

            if errors:
                msg += f" (partial: {len(errors)} categories failed)"

            self.helper.connector_logger.info(
                "[CONNECTOR] Import done", meta={"msg": msg}
            )
            self.helper.api.work.to_processed(work_id, msg)
            # Preserve other state keys (e.g. tracked_cases written by the status
            # tracker) and update under the shared lock to avoid races.
            with self._lock:
                state = self.helper.get_state() or {}
                state["last_run"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
                self.helper.set_state(state)

        except Exception as e:
            if not work_marked_in_error:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Import failed", meta={"error": str(e)}
                )
                self.helper.api.work.to_processed(work_id, str(e), in_error=True)
            raise

    def _create_case_incidents(self, case_metadata: list) -> int:
        """Create CaseIncident objects in OpenCTI for each CBS incident."""
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
                    meta={"ticket_id": meta.get("ticket_id"), "error": str(e)},
                )
        self.helper.connector_logger.info(
            "[CONNECTOR] CaseIncidents created",
            meta={"created": created, "total": len(case_metadata)},
        )
        return created

    def _create_case_incident(self, meta: dict):
        """Create a single CaseIncident in OpenCTI via pycti API."""
        ticket_id = meta["ticket_id"]

        # Create ExternalReference first, then pass its ID
        ext_ref_result = self.helper.api.external_reference.create(
            source_name=CBS_SOURCE_NAME,
            external_id=ticket_id,
        )
        ext_ref_id = ext_ref_result.get("id") if ext_ref_result else None
        ext_refs = [ext_ref_id] if ext_ref_id else []

        create_kwargs = {
            "name": meta["name"],
            "description": meta["description"],
            "severity": meta["severity"],
            "priority": meta["priority"],
            "created": meta["created"],
            "externalReferences": ext_refs,
        }
        if self._author_opencti_id:
            create_kwargs["createdBy"] = self._author_opencti_id

        result = self.helper.api.case_incident.create(**create_kwargs)

        case_id = result.get("id", "") if result else ""
        if case_id:
            self.helper.connector_logger.info(
                "[CONNECTOR] CaseIncident created",
                meta={"case_id": case_id, "ticket_id": ticket_id, "name": meta["name"]},
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
                        meta={"case_id": case_id, "label": label, "error": str(e)},
                    )
            # Register with status tracker, seeding the last-known status from
            # the incident metadata (matching the `status:<value>` label already
            # applied) so the first poll cycle does not re-add an existing label.
            if self._tracker:
                self._tracker.register_case(
                    ticket_id=ticket_id,
                    case_incident_id=case_id,
                    initial_status=meta.get("status", "unknown"),
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
                        meta={"case_id": case_id, "error": str(e)},
                    )
