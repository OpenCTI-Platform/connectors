"""OpenCTI DataDog External Import Connector"""

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from pycti import OpenCTIConnectorHelper, get_config_variable

from lib.client import DataDogClient
from lib.converter import StixConverter
from lib.importer import DataImporter

# Configuration is loaded from environment variables only
config: dict = {}


class DataDogConnector:
    """External import connector for DataDog"""

    def __init__(self):
        """Initialize the connector with configuration"""
        self.helper = OpenCTIConnectorHelper(config)

        # Load connector configuration
        self.api_token = get_config_variable(
            "DATADOG_TOKEN",
            ["datadog", "token"],
            config,
        )

        self.app_key = get_config_variable(
            "DATADOG_APP_KEY",
            ["datadog", "app_key"],
            config,
        )

        self.api_base_url = get_config_variable(
            "DATADOG_API_BASE_URL",
            ["datadog", "api_base_url"],
            config,
            False,
            "https://api.datadog.com",
        )

        self.app_base_url = get_config_variable(
            "DATADOG_APP_BASE_URL",
            ["datadog", "app_base_url"],
            config,
            False,
            "https://app.datadoghq.com",
        )

        self.import_interval = get_config_variable(
            "DATADOG_IMPORT_INTERVAL", ["datadog", "import_interval"], config, True, 60
        )

        self.import_start_date = get_config_variable(
            "DATADOG_IMPORT_START_DATE",
            ["datadog", "import_start_date"],
            config,
            False,
            None,
        )

        self.max_tlp = get_config_variable(
            "DATADOG_MAX_TLP", ["datadog", "max_tlp"], config, False, "TLP:AMBER"
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        # Alert Configuration
        self.import_alerts = get_config_variable(
            "DATADOG_IMPORT_ALERTS", ["datadog", "import_alerts"], config, False, True
        )

        self.create_incident_response_cases = get_config_variable(
            "DATADOG_CREATE_INCIDENT_RESPONSE_CASES",
            ["datadog", "create_incident_response_cases"],
            config,
            False,
            True,  # Default to True - create cases by default
        )

        # Ensure boolean type (in case it's read as string from config)
        if isinstance(self.create_incident_response_cases, str):
            self.create_incident_response_cases = (
                self.create_incident_response_cases.lower() in ["true", "1", "yes"]
            )

        self.helper.log_info(
            f"Config: create_incident_response_cases = {self.create_incident_response_cases} (type: {type(self.create_incident_response_cases).__name__})"
        )

        # Alert filtering
        self.alert_priorities = get_config_variable(
            "DATADOG_ALERT_PRIORITIES",
            ["datadog", "alert_priorities"],
            config,
            False,
            ["P1", "P2", "P3", "P4"],
        )

        self.alert_tags_filter = get_config_variable(
            "DATADOG_ALERT_TAGS_FILTER",
            ["datadog", "alert_tags_filter"],
            config,
            False,
            [],
        )

        # Observable extraction settings
        self.extract_observables_from_alerts = get_config_variable(
            "DATADOG_EXTRACT_OBSERVABLES_FROM_ALERTS",
            ["datadog", "extract_observables_from_alerts"],
            config,
            False,
            True,
        )

        # Context settings
        self.include_alert_context = get_config_variable(
            "DATADOG_INCLUDE_ALERT_CONTEXT",
            ["datadog", "include_alert_context"],
            config,
            False,
            True,
        )

        # Initialize client and services
        self.client = DataDogClient(
            self.api_token, self.app_key, self.api_base_url, self.helper
        )
        self.importer = DataImporter(self.helper)
        self.converter = StixConverter(
            self.helper, self.create_incident_response_cases, self.app_base_url
        )

        # Validate configuration
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate connector configuration"""
        if not self.api_token:
            raise ValueError("DATADOG_TOKEN is required")

        if not isinstance(self.import_interval, int) or self.import_interval <= 0:
            raise ValueError("import_interval must be a positive integer (minutes)")

        if self.max_tlp not in ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]:
            raise ValueError(f"Invalid TLP level: {self.max_tlp}")

        # Validate alert configuration
        if not self.import_alerts:
            raise ValueError("import_alerts must be enabled")

    def _get_import_timestamp(self) -> datetime:
        """
        Get timestamp for incremental imports

        Returns:
            Datetime for the last import or configured start date
        """
        # Get last run timestamp from connector state
        current_state = self.helper.get_state()

        # Use stored state for incremental imports
        if current_state and "last_run_timestamp" in current_state:
            dt = datetime.fromisoformat(current_state["last_run_timestamp"])
            # Ensure timezone-aware datetime
            return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt

        # On first run, use configured start date if available
        if self.import_start_date:
            try:
                dt = datetime.fromisoformat(self.import_start_date)
                # Ensure timezone-aware datetime
                return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
            except ValueError:
                self.helper.log_warning(
                    f"Invalid start date format: {self.import_start_date}"
                )

        # Default to 24 hours ago on first run if no start date configured
        return datetime.now(UTC) - timedelta(hours=24)

    def _update_import_timestamp(self, timestamp: datetime) -> None:
        """
        Update the last import timestamp in connector state

        Args:
            timestamp: Timestamp to store
        """
        self.helper.set_state({"last_run_timestamp": timestamp.isoformat()})

    def _import_data(self, work_id: str | None = None) -> dict[str, Any]:
        """
        Import data from external service

        Args:
            work_id: Optional work ID for tracking

        Returns:
            Dictionary containing import results and statistics
        """
        since = self._get_import_timestamp()
        current_time = datetime.now(UTC)

        # Log detailed timestamp information for debugging
        time_diff = (current_time - since).total_seconds()
        self.helper.log_info(f"Starting import since {since.isoformat()}")
        self.helper.log_info(f"Current time: {current_time.isoformat()}")
        self.helper.log_info(
            f"Time range: {time_diff/3600:.2f} hours ({time_diff:.0f} seconds)"
        )

        try:
            # Fetch data from DataDog based on configuration
            all_import_data = []

            # Import alerts if enabled
            if self.import_alerts:
                self.helper.log_info("Fetching DataDog alerts...")
                alerts_data = self.client.get_alerts(
                    since=since,
                    priorities=self.alert_priorities,
                    tags_filter=self.alert_tags_filter,
                )
                if alerts_data and alerts_data.get("success"):
                    all_import_data.append(
                        {
                            "type": "alerts",
                            "data": alerts_data.get("alerts", []),
                            "total": alerts_data.get("total", 0),
                        }
                    )
                    self.helper.log_info(
                        f"Fetched {alerts_data.get('total', 0)} alerts"
                    )

            if not all_import_data:
                self.helper.log_warning("No data available for import")
                return {"imported": 0, "errors": 0}

            # Process and convert data
            results = self.importer.process_datadog_data(
                all_import_data,
                extract_observables_from_alerts=self.extract_observables_from_alerts,
                include_alert_context=self.include_alert_context,
                create_incident_response_cases=self.create_incident_response_cases,
            )

            # Collect all STIX objects from all alerts (batching approach)
            all_stix_objects = []
            object_errors = 0

            self.helper.log_info(
                f"Creating STIX objects from {len(results.get('processed_items', []))} processed items"
            )

            for idx, data_item in enumerate(results.get("processed_items", [])):
                try:
                    stix_objects = self.converter.create_stix_objects(data_item)
                    if stix_objects:
                        all_stix_objects.extend(stix_objects)
                        if idx < 3:  # Log first few for debugging
                            self.helper.log_debug(
                                f"Created {len(stix_objects)} objects for {data_item.get('type')} item: {data_item.get('name', 'Unknown')}"
                            )
                    else:
                        self.helper.log_warning(
                            f"No objects created for item: {data_item.get('id', 'unknown')}"
                        )
                        object_errors += 1
                except Exception as e:
                    self.helper.log_error(
                        f"Error creating objects for item {data_item.get('id', 'unknown')}: {str(e)}",
                        exc_info=True,
                    )
                    object_errors += 1

            self.helper.log_info(
                f"Successfully created {len(all_stix_objects)} STIX objects from {len(results.get('processed_items', []))} alerts ({object_errors} errors)"
            )

            # If no objects created, return early
            if not all_stix_objects:
                self.helper.log_warning("No STIX objects to send")
                return {"imported": 0, "errors": object_errors}

            # Create a single bundle with all objects (batched approach)
            try:
                stix_bundle = self.converter.create_bundle(all_stix_objects)
                self.helper.log_info(
                    f"Created single bundle containing {len(all_stix_objects)} objects from {len(results.get('processed_items', []))} alerts"
                )
            except Exception as e:
                self.helper.log_error(f"Error creating bundle: {str(e)}", exc_info=True)
                return {"imported": 0, "errors": 1}

            # Send the single bundle to OpenCTI
            try:
                self.helper.send_stix2_bundle(
                    stix_bundle.serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
                self.helper.log_info(
                    f"Sent bundle with {len(all_stix_objects)} objects to OpenCTI"
                )

                # Update last import timestamp
                self._update_import_timestamp(current_time)

                return {
                    "imported": 1,  # One bundle sent
                    "errors": object_errors,
                    "processed": len(results.get("processed_items", [])),
                    "objects": len(all_stix_objects),
                    "timestamp": current_time.isoformat(),
                }

            except Exception as e:
                self.helper.log_error(f"Error sending bundle: {str(e)}", exc_info=True)
                return {"imported": 0, "errors": 1}

        except Exception as e:
            self.helper.log_error(f"Import error: {str(e)}")
            return {"imported": 0, "errors": 1}

    def run(self) -> None:
        """
        Main execution loop for external import connector
        """
        self.helper.log_info("Starting DataDog external import connector")
        self.helper.log_info(f"Import interval: {self.import_interval} minutes")

        while True:
            try:
                # Register work for this import cycle
                friendly_name = f"DataDog import - {datetime.now(UTC).isoformat()}"
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                try:
                    # Perform import
                    results = self._import_data(work_id)

                    # Log results with improved messaging for batched approach
                    if results.get("imported", 0) > 0:
                        message = (
                            f"Import completed: {results['imported']} bundle(s) sent "
                            f"({results.get('processed', 0)} alerts processed, "
                            f"{results.get('objects', 0)} STIX objects created, "
                            f"{results.get('errors', 0)} errors)"
                        )
                    else:
                        message = (
                            f"Import completed: No new data to import "
                            f"({results.get('errors', 0)} errors)"
                        )
                    self.helper.log_info(message)

                    # Mark work as completed
                    if work_id:
                        self.helper.api.work.to_processed(work_id, message)

                except Exception as e:
                    error_message = f"Import cycle failed: {str(e)}"
                    self.helper.log_error(error_message)

                    if work_id:
                        self.helper.api.work.to_processed(work_id, error_message)

                # Wait for next import cycle
                self.helper.log_info(f"Next import in {self.import_interval} minutes")
                time.sleep(self.import_interval * 60)

            except KeyboardInterrupt:
                self.helper.log_info("Import connector stopped by user")
                break
            except Exception as e:
                self.helper.log_error(f"Unexpected error in main loop: {str(e)}")
                time.sleep(60)  # Wait before retrying

    def start(self):
        """Start the connector"""
        self.run()


if __name__ == "__main__":
    try:
        connector = DataDogConnector()
        connector.start()
    except Exception as e:
        print(f"Failed to start connector: {e}")
        raise
