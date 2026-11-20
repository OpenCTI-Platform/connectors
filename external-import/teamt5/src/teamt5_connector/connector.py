import sys
from datetime import datetime, timezone
from typing import Any, Optional

import stix2
from connectors_sdk import (
    ConnectorError,
    ErrorStore,
    OctiUnreachableError,
    UnknownError,
)
from pycti import Identity as pyctiIdentity
from pycti import MarkingDefinition, OpenCTIConnectorHelper
from stix2 import Identity
from teamt5_connector.indicator_bundle_handler import IndicatorBundleHandler
from teamt5_connector.report_handler import ReportHandler
from teamt5_connector.settings import ConnectorSettings
from teamt5_services import Teamt5Client


class TeamT5Connector:

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        self.config = config
        self.helper = helper
        self.client = Teamt5Client(self.helper, self.config)

        self.author = Identity(
            id=pyctiIdentity.generate_id(self.config.connector.name, "organization"),
            name=self.config.connector.name,
            identity_class="organization",
        )

        self.tlp_ref = self._create_tlp_marking(self.config.teamt5.tlp_level.lower())

        self.report_handler = ReportHandler(
            self.client, helper, config, self.author, self.tlp_ref
        )
        self.indicator_bundle_handler = IndicatorBundleHandler(
            self.client, helper, config, self.author, self.tlp_ref
        )

    @staticmethod
    def _return_run_error_list(
        run_error: Optional[ConnectorError] = None,
    ) -> list[dict[str, Any]]:
        """Return the errors of the run in the pycti format.

        :param run_error: The error that stopped the run, if any.
        :return: The error that stopped the run, if any, then the errors recorded in
            the ErrorStore during the run, in the order they were recorded.
        """
        errors = [run_error] if run_error is not None else []
        errors.extend(ErrorStore().get_errors())
        return [error.convert_to_pycti_format() for error in errors]

    def _close_work_in_error(self, work_id: Optional[str], err: Exception) -> None:
        """Close the Work left open by a failed run, marking it ``in_error``.

        Without it, a crash mid-run leaves the Work stuck in the "running" state in
        the OpenCTI UI. The close call is itself guarded so that a platform
        partition that caused the original failure cannot also crash the error
        handler: its failure is recorded in the ErrorStore as an
        ``OctiUnreachableError``.

        :param work_id: The id of the Work left open, or ``None`` if none is open.
        :param err: The error that stopped the run.
        """
        if work_id is None:
            return
        try:
            self.helper.api.work.to_processed(
                work_id,
                f"Unhandled exception: {err}",
                in_error=True,
            )
        except Exception as close_err:  # noqa: BLE001
            ErrorStore().record_error(
                OctiUnreachableError(
                    f"Failed to mark work {work_id} as in_error: {close_err}"
                )
            )
            self.helper.connector_logger.error(
                "[CONNECTOR] Failed to mark work as in_error",
                meta={"work_id": work_id, "error": str(close_err)},
            )

    def process_message(self) -> list[dict[str, Any]]:
        """Run one scheduled import of TeamT5 reports and indicator bundles.

        :return: The errors of the run, in the pycti format, reported to OpenCTI
            with the connector's ping: the error that stopped the run, if any, then
            the errors handled during the run. Empty when nothing failed.
        """
        # A run starts with an empty store: the errors of the previous run are not
        # reported again
        ErrorStore().clear()

        self.helper.connector_logger.info(f"{self.config.connector.name}: Starting Run")

        # ``work_id`` is created lazily inside the handler loop (one per handler).
        # Tracking the *currently open* Work in the outer scope lets the
        # ``except Exception`` handler below mark it as ``in_error=True`` so a
        # crash mid-run does not leave a Work record stuck in the "running"
        # state in the OpenCTI UI. We reset to ``None`` after every clean
        # ``to_processed`` so we only ever close the Work that was actually
        # left open by the failing handler.
        work_id: Optional[str] = None
        try:
            now = datetime.now(tz=timezone.utc)
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "Connector last run",
                    meta={"last_run_datetime": last_run},
                )
                last_run_timestamp = int(datetime.fromisoformat(last_run).timestamp())

            # If the connector has never run, we should retrieve from the timestamp specified in configs
            else:
                self.helper.connector_logger.info("Connector has never run...")
                last_run_timestamp = int(
                    self.config.teamt5.first_run_retrieval_timestamp
                )

            # ``last_run`` is only advanced when every handler completes
            # without partial failure (no ``_MAX_PAGE_FAILURES`` bail-out
            # AND every retrieved bundle was successfully pushed). Holding
            # the cursor at its previous value on partial failure lets the
            # next scheduled run retry the unprocessed tail — advancing
            # past it would silently skip every TeamT5 item between the
            # frozen ``last_run`` and the failed bundle, which is the data
            # loss path the Copilot review thread on ``connector.py:106``
            # called out.
            had_partial_failure = False

            # For each handler (Reports and IOC Bundles) retrieve bundle references and push to OpenCTI
            for handler in [self.report_handler, self.indicator_bundle_handler]:
                self.helper.connector_logger.info(
                    f"Retrieving {handler.name} references from after: {datetime.fromtimestamp(last_run_timestamp)}"
                )
                retrieved_bundle_refs = handler.retrieve_bundle_references(
                    last_run_timestamp
                )

                if handler.aborted:
                    # ``_MAX_PAGE_FAILURES`` bail-out — the listing did
                    # not complete, so the cursor stays where it is.
                    had_partial_failure = True

                if retrieved_bundle_refs:

                    self.helper.connector_logger.info(
                        f"Retrieval complete. {len(retrieved_bundle_refs)} new {handler.name} references found."
                    )
                    work_name = f"Creating {handler.name}s from TeamT5"
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, work_name
                    )
                    num_pushed = handler.push_objects(work_id, retrieved_bundle_refs)
                    push_message = f"Connector Pushed {num_pushed} {handler.name}s"
                    self.helper.connector_logger.info(push_message)
                    # ``in_error=True`` when not every retrieved bundle made
                    # it through (some bundle download / parse failed and was
                    # skipped) so the OpenCTI UI flags the Work red instead
                    # of green-on-failure.
                    self.helper.api.work.to_processed(
                        work_id, push_message, in_error=handler.partial_push
                    )
                    if handler.partial_push:
                        had_partial_failure = True
                    work_id = None

                elif handler.aborted:
                    # Distinct log line when the listing bailed out after
                    # ``_MAX_PAGE_FAILURES`` consecutive failed pages —
                    # the run actually FAILED to retrieve the upstream
                    # listing and the next scheduled cycle will retry,
                    # so logging "No new ... found" here would lie to
                    # the operator about why no objects were imported.
                    # ``had_partial_failure`` is already set above when
                    # the abort flag flipped, so the cursor is also held
                    # at its previous value.
                    self.helper.connector_logger.warning(
                        f"{handler.name} retrieval aborted after consecutive "
                        f"failed pages; no objects were imported and "
                        f"last_run will be held at its previous value so "
                        f"the next scheduled run retries."
                    )

                else:
                    self.helper.connector_logger.info(f"No new {handler.name}s found")

            current_state = self.helper.get_state() or {}
            current_state_datetime = now.isoformat(timespec="seconds")
            if had_partial_failure:
                # Keep the previous ``last_run`` value so the next cycle
                # retries the unprocessed window. Log explicitly so the
                # operator can see the cursor was intentionally held.
                self.helper.connector_logger.warning(
                    f"{self.helper.connect_name} connector finished with partial failure; "
                    "holding last_run at the previous value so the next scheduled run "
                    "retries the unprocessed bundles.",
                    meta={"previous_last_run": current_state.get("last_run")},
                )
            else:
                current_state["last_run"] = current_state_datetime
                self.helper.set_state(current_state)
                self.helper.connector_logger.info(
                    f"{self.helper.connect_name} connector successfully run, storing last_run as "
                    + current_state_datetime
                )
            return self._return_run_error_list()

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped...",
                meta={"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except ConnectorError as err:
            # A standardized error stopped the run: it is reported as is, with
            # its own code and criticity.
            self.helper.connector_logger.error(
                "[CONNECTOR] Unhandled exception during run",
                meta={"error": str(err)},
            )
            self._close_work_in_error(work_id, err)
            return self._return_run_error_list(err)
        except Exception as err:
            # Any other exception is reported as an UnknownError.
            self.helper.connector_logger.error(
                "[CONNECTOR] Unhandled exception during run",
                meta={"error": str(err)},
            )
            self._close_work_in_error(work_id, err)
            return self._return_run_error_list(UnknownError(str(err)))

    def _create_tlp_marking(self, level: str) -> stix2.MarkingDefinition:
        """
        Returns a STIX2 Marking Definition corresponding to the TLP level defined
        in the connector's configuration. When ``level`` does not match any of the
        supported labels, the connector logs the misconfiguration and falls back
        to ``TLP:CLEAR`` so the run keeps producing a well-marked bundle instead
        of crashing on a typo.

        :param level: Configured string reflecting the desired TLP level.
        :return: A Marking Definition for the desired TLP Marking.
        """
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:CLEAR",
                },
            ),
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        if level not in mapping:
            self.helper.connector_logger.info(
                f"Invalid TLP Marking: {level} defaulting to TLP:CLEAR"
            )
            return mapping["clear"]

        return mapping[level]

    def run(self) -> None:
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
