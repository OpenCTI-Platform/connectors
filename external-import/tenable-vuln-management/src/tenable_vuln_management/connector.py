import concurrent.futures
import sys
import warnings
from datetime import datetime, timezone
from typing import Any

from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError

from .client_api import ConnectorClient
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .models.common import ValidationWarning
from .models.tenable import VulnerabilityFinding


class Connector:
    """
    Specifications of the external import Tenable Vuln Management connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(
            helper=self.helper,
            config=self.config,
            default_marking=self.config.tio_marking_definition,
        )
        self.work_id: str | None = None
        self._metadata: list[dict[str, Any]] | None = None

    def _initiate_work(self) -> None:
        """Initiate a new work process in the OpenCTI platform.

        This method:
            1. Update data retrieval start date based on state
            2. Initiates work in OpenCTI platform and register work_id attribute
            3. Logs the event
            4. Returns the work ID for future use.
        """
        now_isodatetime = datetime.now(timezone.utc).isoformat()

        state = self.helper.get_state() or {}
        self.helper.connector_logger.debug(
            "[CONNECTOR] Connector current state", {"state": state}
        )

        last_run = state.get("last_run_start_datetime")
        last_successful_run = state.get("last_successful_run_start_datetime")

        # Update state
        state.update({"last_run_start_datetime": now_isodatetime})
        self.helper.set_state(state=state)

        # Update data retrieval start datetime
        if last_successful_run is not None:
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector last run", {"last_run_start_datetime": last_run}
            )
            previous_since = str(self.config.tio_export_since)
            self.config.tio_export_since = last_successful_run
            self.helper.connector_logger.warning(
                "[CONNECTOR] Connector acquisition SINCE parameter overwritten",
                {"previous": previous_since, "current": self.config.tio_export_since},
            )
        else:
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector has never run successfully..."
            )

        # Initiate a new work
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, self.helper.connect_name
        )
        # reset metadata
        self._metadata = None
        self.helper.connector_logger.info(
            "[CONNECTOR] Running connector...",
            {"connector_name": self.helper.connect_name},
        )

    def _process(
        self,
        data: list[dict[str, Any]],
        export_uuid: str,
        export_type: str,
        export_chunk_id: int,
    ) -> bool:
        """Process data retrieved by the pyTenable `ExportIterator`.

        This method handles the following tasks:
        1. Verifies the data model from the Tenable API response.
        2. Injects the data into the revamp process, mapping it to OpenCTI object use cases.
        3. Converts the data to STIX 2 format and sends the resulting bundle to the OpenCTI queue.

        Args:
            data (list[dict[str, Any]]): A chunk of data retrieved from the Tenable API.
            export_uuid (str): Unused but required when using `pytenable.ExportIterator.run_threaded`.
            export_type (str): Unused but required when using `pytenable.ExportIterator.run_threaded`.
            export_chunk_id (str): Unused but required when using `pytenable.ExportIterator.run_threaded`.

        Returns:
            success_flag(bool): True if all sub process run fine.

        References:
            https://pytenable.readthedocs.io/en/stable/api/io/exports.html#tenable.io.exports.iterator.ExportsIterator
            [Accessed on September 29, 2024]

        """
        _ = export_uuid, export_type, export_chunk_id
        vuln_findings, entities, stix_objects = [], [], []  # results holder
        success_flag = True

        # Acquire vulnerability uuids
        try:
            self._metadata = (
                self.client.get_finding_ids() if self._metadata is None else None
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "Error when trying to acquire tenable finding ids", {"error": str(e)}
            )

        # Acquire
        for item in data:
            try:
                # even though we implemented the ability to bulk convert api response, we do it one by one to maximize
                # the amount of ingested data in case of a corrupted line
                with warnings.catch_warnings(
                    action="error", category=ValidationWarning
                ):
                    vuln_findings.extend(
                        VulnerabilityFinding.from_api_response_body(
                            [item], metadata=self._metadata or []
                        )
                    )
            except ValidationWarning as e:
                self.helper.connector_logger.warning(
                    "Unexpected Tenable API response extra parameters",
                    {"warning": str(e), "content": item},
                )
            except ValidationError as e:
                success_flag = False
                self.helper.connector_logger.error(
                    "Unexpected Tenable API response",
                    {"error": str(e), "content": item},
                )
            except Exception as e:
                success_flag = False
                self.helper.connector_logger.error(
                    "Error when trying to acquire tenable findings", {"error": str(e)}
                )
        # Revamp
        for vuln_finding in vuln_findings:
            try:
                entities.extend(
                    self.converter_to_stix.process_vuln_finding(
                        vuln_finding=vuln_finding
                    )
                )
            except Exception as e:
                success_flag = False
                self.helper.connector_logger.error(
                    "Error when trying to process a tenable finding",
                    {"tenable_finding": vuln_finding, "error": str(e)},
                )
        # Deduplicate chunk if needed to lighten stress on queue later
        # E.g. Assets are repeated in vuln findings => leading to duplicated Systems
        entities = list(set(entities))

        # Convert
        stix_objects.extend([entity.to_stix2_object() for entity in entities])

        # Load
        if stix_objects:
            stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
            bundles_sent = self.helper.send_stix2_bundle(
                bundle=stix_objects_bundle, work_id=self.work_id
            )
            self.helper.connector_logger.info(
                "Sending STIX objects to OpenCTI...",
                {"bundles_sent": str(len(bundles_sent))},
            )
        return success_flag

    def _run_threaded_jobs(self) -> list[bool]:
        """Run the jobs to export vulnerabilities using threads.

        This method spawns multiple threads to process vulnerabilities via the client's `export_vulnerabilities` method,
            then await them to be finished.

        Returns:
            results(list[bool]): True if job succeeded False otherwise.
        """
        jobs = self.client.export_vulnerabilities().run_threaded(
            func=self._process, kwargs=None, num_threads=self.config.num_threads
        )
        return [job.result() for job in concurrent.futures.as_completed(jobs)]

    def _finalize_work(self, results: list[bool]) -> None:
        """Finalize the work process and logs the completion message.

        This method
            1. Update the connector state depending on the results.
            2. Marks the work as processed on the OpenCTI platform.
            3. Logs a message indicating that the connector ran.

        Args:
            results(list[bool]): The processing results (True if OK False otherwise).

        See Also:
            _initiate_work method
        """
        state: dict[Any, Any] = self.helper.get_state() or {}
        now_isodatetime = datetime.now(timezone.utc).isoformat()
        success_flag = all(results)
        if success_flag:
            state.update(
                {
                    "last_successful_run_start_datetime": state.get(
                        "last_run_start_datetime"
                    ),
                }
            )
        self.helper.set_state(state=state)
        message = (
            f"{self.helper.connect_name} connector {'successfully' if success_flag else ''} run, "
            f"storing last_run as {now_isodatetime}"
        )
        self.helper.connector_logger.info(message)

    def process_message(self) -> None:
        in_error = True
        try:
            self.helper.connector_logger.info(
                "[CONNECTOR] Starting connector work...",
                {"connector_name": self.helper.connect_name},
            )
            self._initiate_work()
            results = self._run_threaded_jobs()
            self._finalize_work(results)
            in_error = (
                not all(results) if len(results) != 0 else False
            )  # no error if nothing to retrieve
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

        finally:
            self.helper.api.work.to_processed(
                work_id=self.work_id,
                message="[CONNECTOR] Connector exited gracefully",
                in_error=in_error,
            )
            self.work_id = None

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
