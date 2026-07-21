"""Background daemon thread that polls HackerView API for issue status changes.

CaseIncidents themselves are created through the STIX bundle (see
``ConverterToStix``) with deterministic ids; this tracker only reflects *later*
status changes onto an already-ingested case. The connector registers each case
by its deterministic id, and on every cycle the tracker checks the current
status from the HackerView API and updates the case label in OpenCTI when it
changes (a label mutation on an existing object, never a creation).
"""

import threading
from datetime import datetime, timezone

from ctm360_hv_client.api_client import CTM360HvClient
from pycti import OpenCTIConnectorHelper

TERMINAL_STATUSES = {"resolved", "closed", "completed", "fixed", "false_positive"}


class CaseStatusTracker:
    """Polls HackerView API for status changes on tracked CaseIncidents."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: CTM360HvClient,
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
            target=self._poll_loop, name="hv-status-tracker", daemon=True
        )
        self._thread.start()
        self.helper.connector_logger.info(
            "[STATUS-TRACKER] Background polling started",
            {"poll_interval": self.poll_interval},
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
        """Register a single bundle-created CaseIncident for status tracking."""
        self.register_cases(
            [
                {
                    "ticket_id": ticket_id,
                    "case_incident_id": case_incident_id,
                    "initial_status": initial_status,
                }
            ]
        )

    def register_cases(self, cases: list):
        """Register CaseIncidents (created in the bundle) for status tracking.

        Each entry must carry the ticket_id and the deterministic
        ``case_incident_id`` shipped in the bundle. Existing tracked entries are
        preserved so the tracker does not lose the last known status. Done in a
        single state read-modify-write under the shared lock.
        """
        if not cases:
            return
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock:
            state = self.helper.get_state() or {}
            tracked = state.get("tracked_cases", {})
            for case in cases:
                ticket_id = case["ticket_id"]
                existing = tracked.get(ticket_id, {})
                tracked[ticket_id] = {
                    "case_incident_id": case["case_incident_id"],
                    "last_known_status": existing.get(
                        "last_known_status", case.get("initial_status", "unknown")
                    ),
                    "registered_at": existing.get("registered_at", now),
                }
            state["tracked_cases"] = tracked
            self.helper.set_state(state)

    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                self._check_all_cases()
            except Exception as e:
                self.helper.connector_logger.error(
                    "[STATUS-TRACKER] Poll cycle error", {"error": str(e)}
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
            {"count": len(tracked)},
        )

        for ticket_id, info in tracked.items():
            try:
                self._check_single_case(ticket_id, info)
            except Exception as e:
                self.helper.connector_logger.error(
                    "[STATUS-TRACKER] Failed to check case",
                    {"ticket_id": ticket_id, "error": str(e)},
                )

    def _check_single_case(self, ticket_id: str, info: dict):
        issue_data = self.client.get_issue(ticket_id)
        if not issue_data:
            return

        # HackerView issues have both "status" and "progress_status"
        current_status = str(issue_data.get("status", "unknown")).lower()
        progress = str(issue_data.get("progress_status", "")).lower()
        last_status = info.get("last_known_status", "unknown")

        # Combine status + progress for a more detailed label
        effective_status = (
            f"{current_status}:{progress}" if progress else current_status
        )

        if effective_status == last_status:
            return

        self.helper.connector_logger.info(
            "[STATUS-TRACKER] Status change detected",
            {
                "ticket_id": ticket_id,
                "old_status": last_status,
                "new_status": effective_status,
            },
        )

        case_incident_id = info.get("case_incident_id", "")
        self._update_case_label(case_incident_id, effective_status, last_status)

        with self.lock:
            state = self.helper.get_state() or {}
            tracked = state.get("tracked_cases", {})

            if current_status in TERMINAL_STATUSES:
                tracked.pop(ticket_id, None)
            else:
                if ticket_id in tracked:
                    tracked[ticket_id]["last_known_status"] = effective_status

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
                {"case_id": case_incident_id, "label": new_label},
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "[STATUS-TRACKER] Failed to update case label",
                {"case_id": case_incident_id, "error": str(e)},
            )
