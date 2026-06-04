"""Background daemon thread that polls CBS API for incident status changes.

When a CaseIncident is created from a CBS incident, the tracker registers
it for polling. On each cycle, it checks the current status from the CBS
API and updates the CaseIncident label in OpenCTI if the status changed.
"""

import threading
from datetime import datetime, timezone

from ctm360_cbs_client.api_client import CTM360CbsClient
from pycti import OpenCTIConnectorHelper

TERMINAL_STATUSES = {"resolved", "closed", "completed", "rejected", "false_positive"}


class CaseStatusTracker:
    """Polls CBS API for status changes on tracked CaseIncidents."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: CTM360CbsClient,
        poll_interval: int,
        lock: threading.Lock,
    ):
        self.helper = helper
        self.client = client
        self.poll_interval = poll_interval
        self.lock = lock
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(
            target=self._poll_loop, name="cbs-status-tracker", daemon=True
        )
        self._thread.start()
        self.helper.connector_logger.info(
            "[STATUS-TRACKER] Background polling started",
            meta={"poll_interval": self.poll_interval},
        )

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)

    def register_case(
        self,
        ticket_id: str,
        case_incident_id: str,
        initial_status: str = "unknown",
    ):
        """Register a CaseIncident for status tracking."""
        with self.lock:
            state = self.helper.get_state() or {}
            tracked = state.get("tracked_cases", {})
            tracked[ticket_id] = {
                "case_incident_id": case_incident_id,
                "last_known_status": initial_status,
                "registered_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
            state["tracked_cases"] = tracked
            self.helper.set_state(state)

    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                self._check_all_cases()
            except Exception as e:
                self.helper.connector_logger.error(
                    "[STATUS-TRACKER] Poll cycle error", meta={"error": str(e)}
                )
            self._stop_event.wait(self.poll_interval)

    def _check_all_cases(self):
        with self.lock:
            state = self.helper.get_state() or {}
            tracked = dict(state.get("tracked_cases", {}))

        if not tracked:
            return

        self.helper.connector_logger.info(
            "[STATUS-TRACKER] Checking tracked cases",
            meta={"count": len(tracked)},
        )

        for ticket_id, info in tracked.items():
            try:
                self._check_single_case(ticket_id, info)
            except Exception as e:
                self.helper.connector_logger.error(
                    "[STATUS-TRACKER] Failed to check case",
                    meta={"ticket_id": ticket_id, "error": str(e)},
                )

    def _check_single_case(self, ticket_id: str, info: dict):
        incident_data = self.client.get_incident(ticket_id)
        if not incident_data:
            return

        current_status = str(incident_data.get("status", "unknown")).lower()
        last_status = info.get("last_known_status", "unknown")

        if current_status == last_status:
            return

        self.helper.connector_logger.info(
            "[STATUS-TRACKER] Status change detected",
            meta={
                "ticket_id": ticket_id,
                "old_status": last_status,
                "new_status": current_status,
            },
        )

        case_incident_id = info.get("case_incident_id", "")
        self._update_case_label(case_incident_id, current_status, last_status)

        with self.lock:
            state = self.helper.get_state() or {}
            tracked = state.get("tracked_cases", {})

            if current_status in TERMINAL_STATUSES:
                tracked.pop(ticket_id, None)
            else:
                if ticket_id in tracked:
                    tracked[ticket_id]["last_known_status"] = current_status

            state["tracked_cases"] = tracked
            self.helper.set_state(state)

    def _update_case_label(
        self, case_incident_id: str, new_status: str, old_status: str
    ):
        if not case_incident_id:
            return
        try:
            old_label = f"status:{old_status}"
            try:
                self.helper.api.stix_domain_object.remove_label(
                    id=case_incident_id, label_name=old_label
                )
            except Exception:
                pass

            new_label = f"status:{new_status}"
            self.helper.api.stix_domain_object.add_label(
                id=case_incident_id, label_name=new_label
            )
            self.helper.connector_logger.info(
                "[STATUS-TRACKER] Updated case label",
                meta={"case_id": case_incident_id, "label": new_label},
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "[STATUS-TRACKER] Failed to update case label",
                meta={"case_id": case_incident_id, "error": str(e)},
            )
