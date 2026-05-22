"""OpenCTI DataDog External Import Connector"""

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from lib.client import DataDogClient
from lib.converter import StixConverter
from lib.importer import DataImporter
from lib.utils import normalize_csv_list
from pycti import OpenCTIConnectorHelper, get_config_variable


def _load_config() -> dict:
    """Load the connector configuration from ``config.yml`` if present.

    Mirrors the canonical pattern used by every other external-import
    connector in this repo: when ``src/config.yml`` exists alongside
    this module, parse it with ``yaml.safe_load`` and pass the
    resulting mapping into ``OpenCTIConnectorHelper`` / every
    ``get_config_variable`` call below. When the file is missing
    (Docker / Kubernetes deployments that use env vars exclusively),
    fall back to an empty mapping and let ``get_config_variable``
    resolve every key from the process environment instead.

    The earlier shape hard-coded ``config: dict = {}`` and never
    loaded the YAML file even when one was shipped — contradicting
    the README's "create config.yml then run python connector.py"
    instructions and ``src/config.yml.sample`` which advertised the
    YAML configuration shape.
    """
    config_path = Path(__file__).parent / "config.yml"
    if config_path.is_file():
        with config_path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


config: dict = _load_config()


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

        # DataDog's canonical API endpoint is ``api.datadoghq.com``
        # (note the trailing ``hq.com``). The previous default
        # ``https://api.datadog.com`` is a marketing redirect that
        # returns 301 / 308 for API calls — every shipped sample
        # (``config.yml.sample`` / ``docker-compose.yml.sample`` /
        # ``.env.sample``) already points at the correct hostname.
        self.api_base_url = get_config_variable(
            "DATADOG_API_BASE_URL",
            ["datadog", "api_base_url"],
            config,
            False,
            "https://api.datadoghq.com",
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

        # Default to ``False`` so the connector's default bundle stays
        # minimal — every shipped sample (``config.yml.sample`` /
        # ``.env.sample`` / ``docker-compose.yml.sample``) already
        # defaults to ``false``. Keeping the code default consistent
        # with the documented sample avoids the "documented default vs
        # runtime default" mismatch that would otherwise create case
        # objects in production deployments that copy the sample
        # verbatim and never override the flag.
        self.create_incident_response_cases = get_config_variable(
            "DATADOG_CREATE_INCIDENT_RESPONSE_CASES",
            ["datadog", "create_incident_response_cases"],
            config,
            False,
            False,
        )

        # Ensure boolean type (in case it's read as string from config)
        if isinstance(self.create_incident_response_cases, str):
            self.create_incident_response_cases = (
                self.create_incident_response_cases.lower() in ["true", "1", "yes"]
            )

        self.helper.log_info(
            f"Config: create_incident_response_cases = {self.create_incident_response_cases} (type: {type(self.create_incident_response_cases).__name__})"
        )

        # Alert filtering.
        #
        # Both knobs are documented as comma-separated env vars
        # (``DATADOG_ALERT_PRIORITIES="P1,P2"`` /
        # ``DATADOG_ALERT_TAGS_FILTER="env:prod,team:secops"``) AND
        # as YAML lists in ``config.yml.sample`` — so the value can
        # arrive here as either a Python ``list`` (YAML path) or a
        # raw ``str`` (env path). Without normalisation the env path
        # would silently break both downstream consumers: the
        # ``signal_priority not in priorities`` membership check in
        # ``lib/client.py`` would devolve into a substring match
        # (``"P1" in "P1,P2"`` is ``True`` but matches every prefix
        # of the comma-separated list), and the
        # ``[f"@tags:{tag}" for tag in tags_filter]`` comprehension
        # would iterate the string character-by-character and emit a
        # garbage ``filter[query]=@tags:e @tags:n @tags:v …`` URL.
        # ``normalize_csv_list`` collapses both shapes (plus
        # ``None`` / blank inputs) into a clean ``list[str]`` so
        # the consumers can treat the value uniformly.
        self.alert_priorities = normalize_csv_list(
            get_config_variable(
                "DATADOG_ALERT_PRIORITIES",
                ["datadog", "alert_priorities"],
                config,
                False,
                ["P1", "P2", "P3", "P4"],
            )
        )

        self.alert_tags_filter = normalize_csv_list(
            get_config_variable(
                "DATADOG_ALERT_TAGS_FILTER",
                ["datadog", "alert_tags_filter"],
                config,
                False,
                [],
            )
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

        # Page-size used when paginating the DataDog Security
        # Monitoring API. Surfaced as a configurable to match the
        # documented ``DATADOG_BATCH_SIZE`` env var; the client uses
        # it for the ``page[limit]`` query parameter (DataDog's docs
        # cap this at 1000 for the v2 endpoint).
        self.batch_size = get_config_variable(
            "DATADOG_BATCH_SIZE",
            ["datadog", "batch_size"],
            config,
            True,
            100,
        )

        # Initialize client and services. The converter receives the
        # configured ``max_tlp`` so every emitted STIX object carries
        # the operator's chosen marking instead of silently defaulting
        # to ``TLP:WHITE`` (the previous shape validated the env var
        # but never propagated it past the connector layer).
        self.client = DataDogClient(
            self.api_token,
            self.app_key,
            self.api_base_url,
            self.helper,
            batch_size=self.batch_size,
        )
        self.importer = DataImporter(self.helper)
        self.converter = StixConverter(
            self.helper,
            self.create_incident_response_cases,
            self.app_base_url,
            tlp_level=self.max_tlp,
        )

        # Validate configuration
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate connector configuration"""
        if not self.api_token:
            raise ValueError("DATADOG_TOKEN is required")

        # DataDog's Security Monitoring v2 API rejects calls without
        # the App key with a 403 (the client already sends it on every
        # request). Failing fast here with a clear message keeps the
        # connector from looping on permission errors when the
        # operator forgets to set ``DATADOG_APP_KEY`` — both keys are
        # listed as required in the README and samples.
        if not self.app_key:
            raise ValueError("DATADOG_APP_KEY is required")

        if not isinstance(self.import_interval, int) or self.import_interval <= 0:
            raise ValueError("import_interval must be a positive integer (minutes)")

        if self.max_tlp not in [
            "TLP:CLEAR",
            "TLP:WHITE",
            "TLP:GREEN",
            "TLP:AMBER",
            "TLP:AMBER+STRICT",
            "TLP:RED",
        ]:
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

            # Import alerts if enabled.
            #
            # ``get_alerts`` returns ``None`` when the underlying API
            # call failed in a way the client could not recover from
            # (paginating the Security Monitoring v2 endpoint blew
            # through the bounded 429 retry, a 5xx survived the
            # adapter retries, the JSON parse failed). Distinguishing
            # ``None`` (API failure) from ``{"success": True, "alerts": []}``
            # (genuinely no new signals in the configured window) is
            # critical: lumping them together used to mark the Work as
            # ``processed`` (success) and emit a "No data available
            # for import" warning, hiding API outages in the work
            # summary and metrics. The state cursor is *not* advanced
            # in either branch (the timestamp-advance gate later in
            # this method only fires after a successful bundle send),
            # so an API failure correctly lets the next cycle retry
            # the same window — but the operator now sees the failure
            # surface as an in-error Work and ``errors: 1`` in the
            # run summary instead of a silent "0 errors" success.
            if self.import_alerts:
                self.helper.log_info("Fetching DataDog alerts...")
                alerts_data = self.client.get_alerts(
                    since=since,
                    priorities=self.alert_priorities,
                    tags_filter=self.alert_tags_filter,
                )
                if alerts_data is None:
                    self.helper.log_error(
                        "Aborting cycle: DataDog Security Monitoring API "
                        "fetch failed; the state cursor will NOT be "
                        "advanced so the same time window is retried on "
                        "the next cycle."
                    )
                    return {"imported": 0, "errors": 1}
                if alerts_data.get("success"):
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
                else:
                    # Defensive: ``get_alerts`` currently only returns
                    # ``None`` or ``{"success": True, ...}``, but a future
                    # change that introduces an explicit
                    # ``{"success": False, "error": ...}`` shape must not
                    # silently fall through to the "no data" path either.
                    self.helper.log_error(
                        "Aborting cycle: DataDog alerts response missing "
                        "``success`` flag; treating as API failure."
                    )
                    return {"imported": 0, "errors": 1}

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

            # Surface any importer-level fatal error onto the cycle's
            # error count — ``process_datadog_data`` returns
            # ``errors=1`` when the per-alert processing loop short-
            # circuits via an uncaught exception. Without this, an
            # importer crash on a malformed signal would land here as
            # ``processed_items=[]`` / ``object_errors=0`` and the
            # cycle would be reported as a clean green no-op despite
            # silently losing data. Seed ``object_errors`` from the
            # importer count so the per-item conversion errors below
            # accumulate on top.
            object_errors = int(results.get("errors", 0) or 0)

            # Collect all STIX objects from all alerts (batching approach)
            all_stix_objects = []

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

            # Send the single bundle to OpenCTI.
            # ``cleanup_inconsistent_bundle=True`` instructs the
            # ingestion worker to drop relationships whose source /
            # target / marking SDOs are missing from the bundle, so we
            # surface inconsistencies as data quality issues instead
            # of silently mis-ingested partial bundles. ``StixConverter``
            # ensures the marking-definition object is always present
            # in the bundle so this guard is never tripped by the
            # connector itself.
            try:
                self.helper.send_stix2_bundle(
                    stix_bundle.serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                self.helper.log_info(
                    f"Sent bundle with {len(all_stix_objects)} objects to OpenCTI"
                )

                # Only advance the ``last_run_timestamp`` cursor when
                # every processed item produced STIX objects. If some
                # alerts failed to convert (``object_errors > 0``),
                # holding the cursor at its previous value lets the
                # next cycle retry them — advancing past would silently
                # drop them from the ingest forever. The processed
                # alerts that DID succeed are still in the bundle we
                # just sent; OpenCTI's deterministic ids guarantee
                # they will be deduplicated on the retry pass.
                if object_errors == 0:
                    self._update_import_timestamp(current_time)
                    timestamp_advanced = True
                else:
                    self.helper.log_warning(
                        f"Bundle sent with {object_errors} conversion error(s); "
                        "holding last_run_timestamp at the previous value so the "
                        "failed alerts are retried on the next cycle."
                    )
                    timestamp_advanced = False

                return {
                    "imported": 1,  # One bundle sent
                    "errors": object_errors,
                    "processed": len(results.get("processed_items", [])),
                    "objects": len(all_stix_objects),
                    "timestamp": (
                        current_time.isoformat() if timestamp_advanced else None
                    ),
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

                    # Log results with improved messaging for batched approach.
                    #
                    # Three distinct outcomes — keep them visually
                    # distinct in both the connector logs and the
                    # OpenCTI Work summary so an operator never has
                    # to cross-reference ``in_error`` to know what
                    # actually happened during the cycle:
                    #
                    # 1. ``imported > 0``: at least one bundle was
                    #    sent — report counts (and any errors that
                    #    folded into the cycle).
                    # 2. ``imported == 0`` and ``errors > 0``: the
                    #    cycle failed before any bundle could be sent
                    #    (API fetch returned ``None``, conversion /
                    #    bundling raised, etc.). Surfacing this as
                    #    "Import failed" stops the previous
                    #    misleading "No new data to import (1 errors)"
                    #    shape that conflated outages with clean
                    #    no-op cycles.
                    # 3. ``imported == 0`` and ``errors == 0``:
                    #    genuinely nothing new in the window —
                    #    "No new data to import" is correct.
                    imported_count = results.get("imported", 0)
                    cycle_errors = results.get("errors", 0)
                    if imported_count > 0:
                        message = (
                            f"Import completed: {imported_count} bundle(s) sent "
                            f"({results.get('processed', 0)} alerts processed, "
                            f"{results.get('objects', 0)} STIX objects created, "
                            f"{cycle_errors} errors)"
                        )
                    elif cycle_errors > 0:
                        message = (
                            f"Import failed: no bundle sent ({cycle_errors} "
                            "error(s)); state cursor NOT advanced — the same "
                            "window will be retried on the next cycle"
                        )
                    else:
                        message = "Import completed: No new data to import"
                    self.helper.log_info(message)

                    # Mark work as completed.
                    #
                    # ``in_error=True`` when the cycle reported ANY
                    # error: either a failed API fetch
                    # (``imported == 0`` AND ``errors > 0`` — the
                    # ``alerts_data is None`` branch in
                    # ``_import_data``) or a partial conversion
                    # failure (``imported > 0`` AND
                    # ``errors > 0`` — some alerts converted, some
                    # didn't). Without this, the OpenCTI UI shows the
                    # Work as a clean success even when the run
                    # silently dropped data — which masked recurring
                    # API outages and conversion regressions in
                    # production.
                    if work_id:
                        cycle_in_error = results.get("errors", 0) > 0
                        self.helper.api.work.to_processed(
                            work_id, message, in_error=cycle_in_error
                        )

                except Exception as e:
                    # ``in_error=True`` MUST be paired with the
                    # ``log_error`` call so a hard cycle failure
                    # (any uncaught exception during ``_import_data``)
                    # is surfaced as a red Work in the OpenCTI UI
                    # instead of the default green-on-success outcome
                    # the platform applies when ``in_error`` is
                    # omitted. ``exc_info=True`` captures the stack
                    # trace alongside the message so operators can
                    # diagnose the failure without re-running the
                    # cycle in debug mode.
                    error_message = f"Import cycle failed: {str(e)}"
                    self.helper.log_error(error_message, exc_info=True)

                    if work_id:
                        self.helper.api.work.to_processed(
                            work_id, error_message, in_error=True
                        )

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
