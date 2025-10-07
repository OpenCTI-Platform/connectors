import time
from datetime import timedelta, timezone
from typing import Any

from models import ConfigLoader

from pycti import OpenCTIConnectorHelper
from .api import MandiantAPI
from .constants import (
    BATCH_REPORT_SIZE,
    DEFAULT_TLP_MARKING_DEFINITION,
    STATE_LAST_RUN,
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
        self.api = MandiantAPI(
            self.helper,
            self.mandiant_api_v4_key_id,
            self.mandiant_api_v4_key_secret,
        )

    def _convert_tlp_to_marking_definition(self) -> None:
        """Convert TLP marking to proper format."""
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
            self._run()
            self.helper.force_ping()
        else:
            while True:
                try:
                    timestamp = Timestamp.now()
                    current_state = self._get_state()

                    self.helper.connector_logger.info(
                        "[CONNECTOR] Running connector...", {"state": current_state}
                    )

                    self._run()

                    # Update state
                    current_state[STATE_LAST_RUN] = timestamp.iso_format
                    self._set_state(current_state)

                    # Sleep
                    if self.duration_period:
                        sleep_duration = self._parse_duration(self.duration_period)
                        self.helper.connector_logger.info(
                            f"[CONNECTOR] Sleeping for {sleep_duration} seconds..."
                        )
                        time.sleep(sleep_duration)

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
                    raise

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

    def _run(self):
        """Run all collections."""
        for collection in self.mandiant_collections:
            try:
                self._run_collection(collection)
            except Exception as e:
                self.helper.connector_logger.error(
                    f"Error processing collection {collection}: {e}"
                )
                # Continue with other collections
                continue

    def _run_collection(self, collection: str):
        """Run a specific collection."""
        self.helper.connector_logger.info(f"[{collection.upper()}] Starting collection")

        # Get collection-specific settings
        start_date_field = (
            "mandiant_indicator_import_start_date"
            if collection == "indicators"
            else "mandiant_import_start_date"
        )
        start_date = getattr(self, start_date_field)
        interval = getattr(self, f"mandiant_{collection}_interval")

        # Get current state for this collection
        state_key = f"{collection}_state"
        current_state = self._get_state()
        collection_state = current_state.get(state_key, {})

        # Determine time range
        if collection_state.get(STATE_LAST_RUN):
            start_timestamp = Timestamp.from_iso(collection_state[STATE_LAST_RUN])
        else:
            # Convert date string to datetime then to Timestamp
            from datetime import datetime

            date_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            start_timestamp = Timestamp(date_dt)

        end_timestamp = Timestamp.now()

        # Check if we should run based on interval
        if collection_state.get(STATE_LAST_RUN):
            last_run = Timestamp.from_iso(collection_state[STATE_LAST_RUN])
            if (end_timestamp.value - last_run.value) < interval:
                self.helper.connector_logger.info(
                    f"[{collection.upper()}] Skipping run - interval not reached"
                )
                return

        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"{collection.upper()} run @ {end_timestamp.iso_format}",
        )

        try:
            # Process collection
            if collection == "actors":
                self._process_actors(start_timestamp, end_timestamp, work_id)
            elif collection == "reports":
                self._process_reports(start_timestamp, end_timestamp, work_id)
            elif collection == "malwares":
                self._process_malwares(start_timestamp, end_timestamp, work_id)
            elif collection == "campaigns":
                self._process_campaigns(start_timestamp, end_timestamp, work_id)
            elif collection == "indicators":
                self._process_indicators(start_timestamp, end_timestamp, work_id)
            elif collection == "vulnerabilities":
                self._process_vulnerabilities(start_timestamp, end_timestamp, work_id)

            # Update state
            collection_state[STATE_LAST_RUN] = end_timestamp.iso_format
            current_state[state_key] = collection_state
            self._set_state(current_state)

            message = f"[{collection.upper()}] Collection completed"
            self.helper.api.work.to_processed(work_id, message)

        except Exception as e:
            self.helper.api.work.to_processed(work_id, str(e), in_error=True)
            raise

    def _process_actors(self, start_timestamp, end_timestamp, work_id):
        """Process actors collection."""
        from . import actors

        offset = 0
        while True:
            response = self.api.actors(
                limit=100,
                offset=offset,
            )

            if not response or not response.get("actors"):
                break

            for actor in response["actors"]:
                try:
                    actors.process(self, actor)
                except Exception as e:
                    self.helper.connector_logger.error(
                        f"Error processing actor {actor.get('id')}: {e}"
                    )

            if not response.get("next"):
                break
            offset += 100

    def _process_reports(self, start_timestamp, end_timestamp, work_id):
        """Process reports collection."""
        from . import reports

        offset = 0
        while True:
            response = self.api.reports(
                start_epoch=start_timestamp.unix_format,
                end_epoch=end_timestamp.unix_format,
                limit=BATCH_REPORT_SIZE,
                offset=offset,
            )

            if not response or not response.get("reports"):
                break

            for report in response["reports"]:
                try:
                    if report.get("report_type") in self.mandiant_report_types.values():
                        reports.process(self, report)
                except Exception as e:
                    self.helper.connector_logger.error(
                        f"Error processing report {report.get('id')}: {e}"
                    )

            if not response.get("next"):
                break
            offset += BATCH_REPORT_SIZE

    def _process_malwares(self, start_timestamp, end_timestamp, work_id):
        """Process malwares collection."""
        from . import malwares

        offset = 0
        while True:
            response = self.api.malwares(
                limit=100,
                offset=offset,
            )

            if not response or not response.get("malware"):
                break

            for malware in response["malware"]:
                try:
                    malwares.process(self, malware)
                except Exception as e:
                    self.helper.connector_logger.error(
                        f"Error processing malware {malware.get('id')}: {e}"
                    )

            if not response.get("next"):
                break
            offset += 100

    def _process_campaigns(self, start_timestamp, end_timestamp, work_id):
        """Process campaigns collection."""
        from . import campaigns

        offset = 0
        while True:
            response = self.api.campaigns(
                limit=100,
                offset=offset,
            )

            if not response or not response.get("campaigns"):
                break

            for campaign in response["campaigns"]:
                try:
                    campaigns.process(self, campaign)
                except Exception as e:
                    self.helper.connector_logger.error(
                        f"Error processing campaign {campaign.get('id')}: {e}"
                    )

            if not response.get("next"):
                break
            offset += 100

    def _process_indicators(self, start_timestamp, end_timestamp, work_id):
        """Process indicators collection."""
        from . import indicators

        # Note: indicators API returns paginated results
        response = self.api.indicators(
            start_epoch=start_timestamp.unix_format,
            end_epoch=end_timestamp.unix_format,
            limit=1000,
        )
        
        if response and response.get("indicators"):
            for indicator in response["indicators"]:
                try:
                    indicators.process(
                        self, indicator, self.import_indicators_with_full_campaigns
                    )
                except Exception as e:
                    self.helper.connector_logger.error(
                        f"Error processing indicator {indicator.get('id')}: {e}"
                    )
            
            # Note: The indicators API doesn't support pagination with offset
            # All results are returned in the single response

    def _process_vulnerabilities(self, start_timestamp, end_timestamp, work_id):
        """Process vulnerabilities collection."""
        from . import vulnerabilities

        # Note: vulnerabilities API returns paginated results
        response = self.api.vulnerabilities(
            start_epoch=start_timestamp.unix_format,
            end_epoch=end_timestamp.unix_format,
            limit=100,
        )
        
        if response and response.get("vulnerability"):
            for vulnerability in response["vulnerability"]:
                try:
                    vulnerabilities.process(
                        self,
                        vulnerability,
                        self.mandiant_import_software_cpe,
                        self.vulnerability_max_cpe_relationship,
                    )
                except Exception as e:
                    self.helper.connector_logger.error(
                        f"Error processing vulnerability {vulnerability.get('id')}: {e}"
                    )
            
            # Note: The vulnerabilities API doesn't support pagination with offset
            # Results are limited by the limit parameter

    def _get_state(self) -> dict[str, Any]:
        """Retrieve the stored state of the connector."""
        return self.helper.get_state() or {}

    def _set_state(self, state: dict[str, Any]) -> None:
        """Store the state of the connector."""
        self.helper.set_state(state)
