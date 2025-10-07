import importlib
import json
import os
import sys
import time
from datetime import timedelta
from typing import Any

from models import ConfigLoader
from pycti import OpenCTIConnectorHelper

from .api import OFFSET_PAGINATION, MandiantAPI
from .constants import (
    BATCH_REPORT_SIZE,
    DEFAULT_TLP_MARKING_DEFINITION,
    STATE_END,
    STATE_LAST_RUN,
    STATE_OFFSET,
    STATE_START,
    STATEMENT_MARKINGS,
    TLP_MARKING_DEFINITION_MAPPING,
)
from .errors import StateError
from .utils import Timestamp


class Mandiant:
    def __init__(self):
        # Load configuration using the new config loader
        self.config = ConfigLoader()

        # Initialize OpenCTI helper with the configuration
        self.helper = OpenCTIConnectorHelper(self.config.model_dump_pycti())

        # Extract configuration values from the loaded config
        self.duration_period = self.config.connector.duration_period

        # Mandiant API credentials
        self.mandiant_api_v4_key_id = self.config.mandiant.api_v4_key_id
        self.mandiant_api_v4_key_secret = (
            self.config.mandiant.api_v4_key_secret.get_secret_value()
        )

        # Import date settings
        self.mandiant_import_start_date = self.config.mandiant.import_start_date
        self.mandiant_indicator_import_start_date = (
            self.config.mandiant.indicator_import_start_date
        )
        self.mandiant_import_period = self.config.mandiant.import_period

        # Processing options
        self.mandiant_create_notes = self.config.mandiant.create_notes
        self.mandiant_remove_statement_marking = (
            self.config.mandiant.remove_statement_marking
        )

        # Marking definition
        self.mandiant_marking = self.config.mandiant.marking_definition
        self._convert_tlp_to_marking_definition()

        # Build collections list based on what's enabled
        self.mandiant_collections = []

        if self.config.mandiant.import_actors:
            self.mandiant_collections.append("actors")
        self.mandiant_actors_interval = timedelta(
            hours=self.config.mandiant.import_actors_interval
        )
        self.mandiant_import_actors_aliases = self.config.mandiant.import_actors_aliases

        if self.config.mandiant.import_reports:
            self.mandiant_collections.append("reports")
        self.mandiant_reports_interval = timedelta(
            hours=self.config.mandiant.import_reports_interval
        )

        if self.config.mandiant.import_malwares:
            self.mandiant_collections.append("malwares")
        self.mandiant_malwares_interval = timedelta(
            hours=self.config.mandiant.import_malwares_interval
        )
        self.mandiant_import_malwares_aliases = (
            self.config.mandiant.import_malwares_aliases
        )

        if self.config.mandiant.import_campaigns:
            self.mandiant_collections.append("campaigns")
        self.mandiant_campaigns_interval = timedelta(
            hours=self.config.mandiant.import_campaigns_interval
        )

        # When importing indicators, import full campaigns (campaign details and related entities)
        self.import_indicators_with_full_campaigns = (
            self.config.mandiant.import_indicators_with_full_campaigns
        )

        if self.config.mandiant.import_indicators:
            self.mandiant_collections.append("indicators")
        self.mandiant_indicators_interval = timedelta(
            hours=self.config.mandiant.import_indicators_interval
        )

        if self.config.mandiant.import_vulnerabilities:
            self.mandiant_collections.append("vulnerabilities")
        self.mandiant_vulnerabilities_interval = timedelta(
            hours=self.config.mandiant.import_vulnerabilities_interval
        )

        # Build report types dictionary
        self.mandiant_report_types = {}

        if self.config.mandiant.actor_profile_report:
            self.mandiant_report_types["Actor Profile"] = (
                self.config.mandiant.actor_profile_report_type
            )

        if self.config.mandiant.country_profile_report:
            self.mandiant_report_types["Country Profile"] = (
                self.config.mandiant.country_profile_report_type
            )

        if self.config.mandiant.event_coverage_implication_report:
            self.mandiant_report_types["Event Coverage/Implication"] = (
                self.config.mandiant.event_coverage_implication_report_type
            )

        if self.config.mandiant.executive_perspective_report:
            self.mandiant_report_types["Executive Perspective"] = (
                self.config.mandiant.executive_perspective_report_type
            )

        if self.config.mandiant.ics_security_roundup_report:
            self.mandiant_report_types["ICS Security Roundup"] = (
                self.config.mandiant.ics_security_roundup_report_type
            )

        if self.config.mandiant.industry_reporting_report:
            self.mandiant_report_types["Industry Reporting"] = (
                self.config.mandiant.industry_reporting_report_type
            )

        if self.config.mandiant.malware_profile_report:
            self.mandiant_report_types["Malware Profile"] = (
                self.config.mandiant.malware_profile_report_type
            )

        if self.config.mandiant.network_activity_report:
            self.mandiant_report_types["Network Activity Reports"] = (
                self.config.mandiant.network_activity_report_type
            )

        if self.config.mandiant.patch_report:
            self.mandiant_report_types["Patch Report"] = (
                self.config.mandiant.patch_report_type
            )

        if self.config.mandiant.ttp_deep_dive_report:
            self.mandiant_report_types["TTP Deep Dive"] = (
                self.config.mandiant.ttp_deep_dive_report_type
            )

        if self.config.mandiant.threat_activity_alert_report:
            self.mandiant_report_types["Threat Activity Alert"] = (
                self.config.mandiant.threat_activity_alert_report_type
            )

        if self.config.mandiant.threat_activity_report:
            self.mandiant_report_types["Threat Activity Report"] = (
                self.config.mandiant.threat_activity_report_type
            )

        if self.config.mandiant.trends_and_forecasting_report:
            self.mandiant_report_types["Trends and Forecasting"] = (
                self.config.mandiant.trends_and_forecasting_report_type
            )

        if self.config.mandiant.vulnerability_report:
            self.mandiant_report_types["Vulnerability Report"] = (
                self.config.mandiant.vulnerability_report_type
            )

        # Vulnerability-specific settings
        self.mandiant_import_software_cpe = (
            self.config.mandiant.vulnerability_import_software_cpe
        )
        self.vulnerability_max_cpe_relationship = (
            self.config.mandiant.vulnerability_max_cpe_relationship
        )

        if self.config.mandiant.weekly_vulnerability_exploitation_report:
            self.mandiant_report_types["Weekly Vulnerability Exploitation Report"] = (
                self.config.mandiant.weekly_vulnerability_exploitation_report_type
            )

        if self.config.mandiant.news_analysis_report:
            self.mandiant_report_types["News Analysis"] = (
                self.config.mandiant.news_analysis_report_type
            )

        # Relationship guessing configuration
        self.guess_relationships_reports = (
            self.config.mandiant.guess_relationships_reports
        )

        allowed_report_types = [
            "All",
            "None",
            "Actor Profile",
            "Country Profile",
            "Event Coverage/Implication",
            "Executive Perspective",
            "ICS Security Roundup",
            "Industry Reporting",
            "Malware Profile",
            "Network Activity Reports",
            "Patch Report",
            "TTP Deep Dive",
            "Threat Activity Alert",
            "Threat Activity Report",
            "Trends and Forecasting",
            "Vulnerability Report",
            "Weekly Vulnerability Exploitation Report",
            "News Analysis",
        ]

        reports_value = self.guess_relationships_reports.strip()

        requested = {rt.strip() for rt in reports_value.split(",")}
        if "None" in requested:
            self.helper.connector_logger.info("Relationship guessing disabled.")
            self.guess_relationships_reports = []
        elif "All" in requested:
            self.helper.connector_logger.info(
                "Relationship guessing enabled for ALL report types."
            )
            self.guess_relationships_reports = ["all"]
        else:
            valid = [
                self.mandiant_report_types[rt]
                for rt in requested
                if rt in allowed_report_types and rt in self.mandiant_report_types
            ]

            if not valid:
                fallback_keys = [
                    "Actor Profile",
                    "Malware Profile",
                    "Vulnerability Report",
                ]
                valid = [
                    self.mandiant_report_types[k]
                    for k in fallback_keys
                    if k in self.mandiant_report_types
                ]

                if valid:
                    self.helper.connector_logger.warning(
                        "No valid report types found for relationship guessing. "
                        f"Using default values: {', '.join(valid)}"
                    )
                else:
                    self.helper.connector_logger.info("Relationship guessing disabled.")

            else:
                self.helper.connector_logger.info(
                    f"Relationship guessing enabled for: {', '.join(valid)}"
                )
            self.guess_relationships_reports = valid

        # Initialize the API client
        self.mandiant_api_client = MandiantAPI(
            self.helper,
            self.mandiant_api_v4_key_id,
            self.mandiant_api_v4_key_secret,
        )

    def _convert_tlp_to_marking_definition(self) -> None:
        """Convert TLP marking to lowercase."""
        mapping = TLP_MARKING_DEFINITION_MAPPING.get(self.mandiant_marking.upper())
        if not mapping:
            self.helper.connector_logger.warning(
                f"Invalid marking '{self.mandiant_marking}'. Using default 'AMBER+STRICT'"
            )
            self.mandiant_marking = DEFAULT_TLP_MARKING_DEFINITION
        else:
            self.mandiant_marking = mapping

    def run(self):
        """Main entry point for the connector."""
        self.helper.connector_logger.info("[CONNECTOR] Starting Mandiant connector...")

        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.run_once()
        else:
            while True:
                try:
                    self.run_once()
                except StateError as e:
                    self.helper.connector_logger.error(
                        f"[CONNECTOR] State error: {e}", {"state": e.state}
                    )
                    # State related errors might be transient, so we continue
                    pass
                except Exception as err:
                    self.helper.connector_logger.error(
                        f"[CONNECTOR] Fatal error: {err}"
                    )
                    # For non-state errors, we re-raise to let the system handle it
                    raise
                finally:
                    # Sleep for the configured period before next run
                    if self.duration_period:
                        sleep_duration = self._parse_duration(self.duration_period)
                        self.helper.connector_logger.info(
                            f"[CONNECTOR] Sleeping for {sleep_duration} seconds..."
                        )
                        time.sleep(sleep_duration)

    def _parse_duration(self, duration_str: str) -> int:
        """Parse ISO 8601 duration format to seconds."""
        # Simple parser for PT5M format
        if duration_str.startswith("PT"):
            duration_str = duration_str[2:]
            if duration_str.endswith("M"):
                return int(duration_str[:-1]) * 60
            elif duration_str.endswith("H"):
                return int(duration_str[:-1]) * 3600
            elif duration_str.endswith("S"):
                return int(duration_str[:-1])
        # Default to 5 minutes if unable to parse
        return 300

    def run_once(self):
        """Run one iteration of the connector."""
        try:
            for collection_name in self.mandiant_collections:
                # Dynamically import and run collection processors
                # Use the actual module name (actors.py, not actor.py)
                module = importlib.import_module(f"connector.{collection_name}")
                importer = getattr(module, f"{collection_name.capitalize()}Importer")

                # Get interval for this collection
                interval = getattr(self, f"mandiant_{collection_name}_interval")

                # Initialize and run importer
                importer_instance = importer(
                    self.helper,
                    self.mandiant_api_client,
                    self.mandiant_marking,
                    collection_name,
                    interval,
                )

                # Add collection-specific settings
                if collection_name == "actors" and self.mandiant_import_actors_aliases:
                    importer_instance.import_aliases = True
                elif (
                    collection_name == "malwares"
                    and self.mandiant_import_malwares_aliases
                ):
                    importer_instance.import_aliases = True
                elif collection_name == "reports":
                    importer_instance.report_types = self.mandiant_report_types
                    importer_instance.guess_relationships_reports = (
                        self.guess_relationships_reports
                    )
                    importer_instance.create_notes = self.mandiant_create_notes
                    importer_instance.remove_statement_marking = (
                        self.mandiant_remove_statement_marking
                    )
                elif collection_name == "indicators":
                    importer_instance.import_with_full_campaigns = (
                        self.import_indicators_with_full_campaigns
                    )
                elif collection_name == "vulnerabilities":
                    importer_instance.import_software_cpe = (
                        self.mandiant_import_software_cpe
                    )
                    importer_instance.max_cpe_relationship = (
                        self.vulnerability_max_cpe_relationship
                    )

                # Set start dates
                if collection_name == "indicators":
                    importer_instance.import_start_date = (
                        self.mandiant_indicator_import_start_date
                    )
                else:
                    importer_instance.import_start_date = (
                        self.mandiant_import_start_date
                    )

                importer_instance.import_period = self.mandiant_import_period

                # Run the importer
                importer_instance.run()

        except Exception as err:
            self.helper.connector_logger.error(f"[CONNECTOR] Error in run_once: {err}")
            raise

    # Keep all the original methods that are referenced in the collection modules
    def _get_state(self) -> dict[str, Any]:
        """Retrieve the stored state of the connector."""
        return self.helper.get_state() or {}

    def _set_state(self, state: dict[str, Any]) -> None:
        """Store the state of the connector."""
        self.helper.set_state(state)

    def get_interval(self, collection: str) -> timedelta:
        """Get the interval for a specific collection."""
        return getattr(self, f"mandiant_{collection}_interval")

    def initiate_work(self, friendly_name: str) -> str:
        """Create a work entry for tracking."""
        return self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

    def work_to_processed(
        self, work_id: str, message: str, in_error: bool = False
    ) -> None:
        """Mark a work entry as processed."""
        return self.helper.api.work.to_processed(work_id, message, in_error)

    def send_bundle(self, bundle: dict[str, Any], work_id: str = None) -> None:
        """Send a STIX bundle to OpenCTI."""
        serialized_bundle = json.dumps(bundle)
        self.helper.send_stix2_bundle(
            serialized_bundle,
            entities_types=self.helper.connect_scope,
            update=True,
            work_id=work_id,
        )
