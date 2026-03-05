"""
Elastic Security Incidents External Import Connector

This connector imports alerts and cases from Elastic Security into OpenCTI.
"""

import sys
from datetime import datetime, timedelta, timezone
from typing import List

import stix2
from pycti import OpenCTIConnectorHelper

from .client_api import ElasticApiClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix


class ElasticSecurityIncidentsConnector:
    """
    External import connector for Elastic Security incidents and cases

    This connector fetches alerts and cases from Elastic Security and converts them
    to STIX bundles for import into OpenCTI.
    """

    def __init__(self):
        """Initialize the connector with necessary configurations"""

        # Load configuration and create helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ElasticApiClient(self.helper, self.config)
        self.tlp_marking = stix2.TLP_AMBER  # Default marking
        self.converter_to_stix = ConverterToStix(
            self.helper, self.config, self.tlp_marking
        )

        # Test connection on startup
        if not self.client.test_connection():
            raise ConnectionError("Failed to connect to Elastic Security")

    def _get_last_run_time(self) -> datetime:
        """
        Get the last run timestamp from connector's state

        :return: Last run datetime
        """
        state = self.helper.get_state()

        if state and "last_run" in state:
            # If we have a state, always use it for incremental updates
            last_run = state["last_run"]
            state_last_run = datetime.fromisoformat(
                last_run.replace("Z", "+00:00") if "Z" in last_run else last_run
            )
            # Add timezone if missing
            if state_last_run.tzinfo is None:
                state_last_run = state_last_run.replace(tzinfo=timezone.utc)

            self.helper.connector_logger.info(
                "Using last_run from state for incremental update",
                {"last_run": state_last_run.isoformat()},
            )
            return state_last_run

        # No state - this is the first run
        # Use configured start date or default to 7 days ago
        if self.config.import_start_date:
            start_date = datetime.fromisoformat(
                self.config.import_start_date.replace("Z", "+00:00")
            )
            self.helper.connector_logger.info(
                "First run - using import_start_date from config",
                {"start_date": start_date.isoformat()},
            )
            return start_date

        default_start = datetime.now(timezone.utc) - timedelta(days=7)
        self.helper.connector_logger.info(
            "First run - using default start date (7 days ago)",
            {"start_date": default_start.isoformat()},
        )
        return default_start

    def _set_last_run_time(self, last_run: datetime) -> None:
        """
        Set the last run timestamp in connector's state

        :param last_run: Last run datetime
        """
        state = self.helper.get_state() or {}
        state["last_run"] = last_run.isoformat()
        self.helper.set_state(state)

    def _process_alert(self, alert: dict) -> List[object]:
        """
        Process an Elastic alert and convert to STIX objects

        :param alert: Alert data from Elastic
        :return: List of STIX objects
        """
        stix_objects = []

        try:
            # Create incident from alert
            stix_incident = self.converter_to_stix.create_incident(alert)
            if stix_incident:
                stix_objects.append(stix_incident)

                # Create investigation note if rule note exists
                investigation_note = self.converter_to_stix.create_investigation_note(
                    alert, stix_incident.id
                )
                if investigation_note:
                    stix_objects.append(investigation_note)

                # Extract observables from alert
                observables = self.converter_to_stix.extract_observables_from_alert(
                    alert
                )
                for observable in observables:
                    stix_objects.append(observable)

                    # Create relationship between observable and incident
                    relationship = self.converter_to_stix.create_relationship(
                        source_id=observable.id,
                        target_id=stix_incident.id,
                        relationship_type="related-to",
                    )
                    stix_objects.append(relationship)

                # Extract MITRE techniques if present
                threat_info = alert.get("kibana.alert.rule.threat", [])
                techniques = []
                for threat in threat_info:
                    if isinstance(threat, dict):
                        techniques.extend(threat.get("technique", []))

                for technique in techniques:
                    attack_pattern = self.converter_to_stix.create_attack_pattern(
                        technique
                    )
                    if attack_pattern:
                        stix_objects.append(attack_pattern)

                        # Create relationship between incident and technique
                        relationship = self.converter_to_stix.create_relationship(
                            source_id=stix_incident.id,
                            target_id=attack_pattern.id,
                            relationship_type="uses",
                        )
                        stix_objects.append(relationship)

                # Create system identity if host information is present
                host_name = alert.get("host.name", "")
                if host_name:
                    host_info = {"name": host_name}
                    system_identity = self.converter_to_stix.create_identity_system(
                        host_info
                    )
                    if system_identity:
                        stix_objects.append(system_identity)

                        # Create relationship between incident and system
                        relationship = self.converter_to_stix.create_relationship(
                            source_id=stix_incident.id,
                            target_id=system_identity.id,
                            relationship_type="targets",
                        )
                        stix_objects.append(relationship)

                self.helper.connector_logger.debug(
                    f"Processed alert into {len(stix_objects)} STIX objects",
                    {
                        "alert_id": alert.get("kibana.alert.uuid", "unknown"),
                        "rule_name": alert.get("kibana.alert.rule.name", "unknown"),
                    },
                )

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error processing alert: {str(e)}", {"alert": alert}
            )

        return stix_objects

    def _process_case(self, case: dict) -> List[object]:
        """
        Process an Elastic case and convert to STIX objects

        :param case: Case data from Elastic
        :return: List of STIX objects
        """
        stix_objects = []
        related_object_refs = []
        seen_refs = set()  # Track unique refs to avoid duplicates

        try:
            # Process related alerts
            case_alerts = case.get("alerts", [])
            self.helper.connector_logger.debug(
                f"Processing case with {len(case_alerts)} alerts",
                {"case_id": case.get("id"), "case_title": case.get("title")},
            )

            for alert in case_alerts:
                alert_objects = self._process_alert(alert)
                stix_objects.extend(alert_objects)

                # Track entity references for case knowledge graph (excludes investigation notes)
                for obj in alert_objects:
                    obj_id = getattr(obj, "id", None)
                    if obj_id and obj_id not in seen_refs:
                        # Skip investigation notes (belong to incidents only)
                        if (
                            hasattr(obj, "type")
                            and obj.type == "note"
                            and hasattr(obj, "abstract")
                        ):
                            if obj.abstract and obj.abstract.startswith(
                                "Investigation Guide"
                            ):
                                continue
                        related_object_refs.append(obj_id)
                        seen_refs.add(obj_id)

            # Generate predictive case ID
            from pycti import CaseIncident

            case_name = case.get("title", "Elastic Security Case")
            # Try both camelCase and snake_case field names
            case_created_at = (
                case.get("createdAt")
                or case.get("created_at")
                or datetime.now(timezone.utc).isoformat()
            )
            # Ensure consistent format for predictive ID generation
            if case_created_at and "+00:00" in case_created_at:
                case_created_at = case_created_at.replace("+00:00", "Z")
            elif (
                case_created_at
                and "Z" not in case_created_at
                and "+" not in case_created_at
            ):
                case_created_at = case_created_at + "Z"

            case_stix_id = CaseIncident.generate_id(case_name, case_created_at)

            # Process case comments as Notes (before creating the case)
            for comment in case.get("comments", []):
                comment_note = self.converter_to_stix.create_case_comment_note(
                    case_stix_id, comment
                )
                if comment_note:
                    stix_objects.append(comment_note)
                    # Add comment to object_refs
                    if comment_note.id not in seen_refs:
                        related_object_refs.append(comment_note.id)
                        seen_refs.add(comment_note.id)

            # Process case observables
            observables = case.get("observables", [])
            if not observables:
                # Try alternate field names
                observables = case.get("artifacts", []) or case.get("indicators", [])

            for observable_data in observables:
                observable = self.converter_to_stix.create_case_observable(
                    observable_data
                )
                if observable:
                    stix_objects.append(observable)
                    # Add observable to object_refs
                    if observable.id not in seen_refs:
                        related_object_refs.append(observable.id)
                        seen_refs.add(observable.id)

            # Process similar cases as relationships (without importing them)
            similar_cases = case.get("similarCases", [])
            if not similar_cases:
                similar_cases = case.get("similar_cases", [])

            for similar_case in similar_cases:
                similar_case_id = similar_case.get("id", "")
                similar_case_title = similar_case.get("title", "Similar Case")
                if similar_case_id:
                    # Generate predictive ID for the similar case (without importing it)
                    # Use original creation date from similar case
                    # Try both camelCase and snake_case field names for similar cases
                    similar_case_created = (
                        similar_case.get("createdAt")
                        or similar_case.get("created_at")
                        or datetime.now(timezone.utc).isoformat()
                    )
                    if similar_case_created and "+00:00" in similar_case_created:
                        similar_case_created = similar_case_created.replace(
                            "+00:00", "Z"
                        )
                    elif (
                        similar_case_created
                        and "Z" not in similar_case_created
                        and "+" not in similar_case_created
                    ):
                        similar_case_created = similar_case_created + "Z"

                    similar_case_stix_id = CaseIncident.generate_id(
                        similar_case_title, similar_case_created
                    )

                    # Create related-to relationship
                    relationship = self.converter_to_stix.create_relationship(
                        source_id=case_stix_id,
                        target_id=similar_case_stix_id,
                        relationship_type="related-to",
                    )
                    if relationship:
                        stix_objects.append(relationship)

            # Create case incident ONCE with all collected object_refs
            stix_case = self.converter_to_stix.create_case_incident(
                case, related_object_refs
            )
            if stix_case:
                stix_objects.append(stix_case)

                self.helper.connector_logger.info(
                    f"Processed case into {len(stix_objects)} STIX objects",
                    {
                        "case_id": case.get("id"),
                        "alerts": len(case_alerts),
                        "comments": len(case.get("comments", [])),
                        "observables": len(case.get("observables", [])),
                    },
                )

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error processing case: {str(e)}", {"case_id": case.get("id")}
            )

        return stix_objects

    def process_message(self):
        """
        Main process to collect incidents and cases from Elastic Security
        """
        self.helper.connector_logger.info(
            "Starting Elastic Security Incidents connector",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get time range for import
            last_run = self._get_last_run_time()
            current_time = datetime.now(timezone.utc)

            self.helper.connector_logger.info(
                "Fetching data from Elastic Security",
                {
                    "start_time": last_run.isoformat(),
                    "end_time": current_time.isoformat(),
                },
            )

            stix_objects = []

            # Import alerts if configured
            if self.config.import_alerts:
                alerts = self.client.get_alerts(
                    start_time=last_run.isoformat(),
                    end_time=current_time.isoformat(),
                )

                self.helper.connector_logger.info(
                    f"Processing {len(alerts)} alerts from Elastic"
                )

                for alert in alerts:
                    alert_objects = self._process_alert(alert)
                    stix_objects.extend(alert_objects)

            # Import cases if configured
            if self.config.import_cases:
                cases = self.client.get_cases(
                    start_time=last_run.isoformat(),
                    end_time=current_time.isoformat(),
                )

                self.helper.connector_logger.info(
                    f"Processing {len(cases)} cases from Elastic"
                )

                for case in cases:
                    case_objects = self._process_case(case)
                    stix_objects.extend(case_objects)

            # Send data to OpenCTI if we have objects
            if stix_objects:
                # Initiate work
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, self.helper.connect_name
                )

                # Add author and TLP marking
                stix_objects = [
                    self.converter_to_stix.author,
                    self.tlp_marking,
                ] + stix_objects

                # Create and send bundle
                stix_bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(
                    stix_bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

                # Mark work as processed
                message = (
                    f"Imported {len(stix_objects) - 2} objects from Elastic Security"
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.connector_logger.info(message)
            else:
                self.helper.connector_logger.info(
                    "No new data to import from Elastic Security"
                )

            # Update last run time
            self._set_last_run_time(current_time)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped", {"connector_name": self.helper.connect_name}
            )
            sys.exit(0)
        except Exception as e:
            self.helper.connector_logger.error(
                f"Error in connector execution: {str(e)}"
            )

    def run(self) -> None:
        """
        Run the connector on a schedule
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
