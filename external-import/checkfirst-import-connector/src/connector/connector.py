"""Entry point class for the Checkfirst external-import connector."""

import sys
from datetime import datetime, timezone

from checkfirst_client import CheckfirstClient
from checkfirst_client.api_models import Article
from connector.connector_state import ConnectorState
from connector.converter_to_stix import ConversionError, ConverterToStix
from connector.settings import ConnectorSettings
from connectors_sdk.models import BaseIdentifiedEntity
from pycti import OpenCTIConnectorHelper
from utils.run_reporter import SkipReason, run_reporter

PAGE_SIZE = 1_000
BUNDLE_SIZE = 10_000


class BundleSendError(Exception):
    pass


class CheckfirstImportConnector:
    """Minimal external-import connector implementation.

    This follows the standard external-import connector template:
    - `process_message()` does one ingestion pass
    - `run()` schedules runs via `OpenCTIConnectorHelper.schedule_iso()`

    The actual API ingestion + STIX mapping is implemented under
    `checkfirst_dataset/` and reused here.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.logger = self.helper.connector_logger

        self.state = ConnectorState(helper)
        self.api_client = CheckfirstClient(
            helper=helper,
            base_url=self.config.checkfirst.api_url,
            api_key=self.config.checkfirst.api_key.get_secret_value(),
        )
        self.converter = ConverterToStix(
            helper=helper,
            tlp_level=self.config.checkfirst.tlp_level.value,
        )

    def _create_pravda_infrastructure_entities(self) -> list[BaseIdentifiedEntity]:
        """Create entities for known Pravda network infrastructure.
        Called only when starting from page 1 (first run or force_reprocess).
        """
        self.logger.info(
            "[CONNECTOR] Creating Pravda network infrastructure (first run)"
        )

        campaign, attributed_to = self.converter.get_campaign_for_year(year=2023)
        pravda_network_entities = self.converter.convert_pravda_network_infrastructure(
            campaign
        )

        return [campaign, attributed_to] + pravda_network_entities

    def _send_infrastructure_bundle(self) -> None:
        """Send a one-off bundle of known Pravda network infrastructure objects.
        Exectued only when starting from page 1 (first run or force_reprocess).
        """
        self.logger.info("[CONNECTOR] Force reprocess enabled", {"start_page": 1})
        octi_objects = self._create_pravda_infrastructure_entities()
        self._send_bundle(octi_objects)

        self.logger.info(
            "[CONNECTOR] Pravda network infrastructure sent to OpenCTI",
        )

    def _create_row_entities(self, row: Article) -> list[BaseIdentifiedEntity]:
        self.logger.debug(
            "[CONNECTOR] Converting row to OpenCTI objects",
            {"row_number": row.row_number, "row_id": row.id},
        )

        campaign, attributed_to = self.converter.get_campaign_for_year(
            year=row.published_date.year
        )
        article_entities = self.converter.convert_article(row, campaign)

        return [campaign, attributed_to] + article_entities

    def _prepare_rows_bundle(
        self, octi_objects: set[BaseIdentifiedEntity]
    ) -> list[BaseIdentifiedEntity]:
        """Prepare the list of OCTI objects to be sent in a bundle.
        This includes deduplication of Channel objects by merging their external references.
        """
        self.logger.debug(
            "[CONNECTOR] Deduplicating OpenCTI objects for bundle",
            {"octi_objects_count": len(octi_objects)},
        )

        bundle_objects: list[BaseIdentifiedEntity] = []

        channels_ids = set()
        for octi_object in octi_objects:
            if octi_object.id in channels_ids:
                channel = next(
                    (obj for obj in bundle_objects if obj.id == octi_object.id), None
                )
                if (
                    channel
                    and channel.external_references
                    and octi_object.external_references
                ):
                    channel.external_references.extend(octi_object.external_references)
            elif octi_object.id.startswith("channel--"):
                channels_ids.add(octi_object.id)
                bundle_objects.append(octi_object)
            else:
                bundle_objects.append(octi_object)

        self.logger.debug(
            "[CONNECTOR] Bundle ready to be sent",
            {"bundle_objects_count": len(bundle_objects)},
        )

        return bundle_objects

    def _send_rows_bundles(self, start_page: int) -> None:
        self.logger.info(
            "[CONNECTOR] Fetching data from API",
            {"api_endpoint": self.config.checkfirst.api_endpoint},
        )

        # Set of _unique_ OCTI objects to be sent
        # (uniqueness is determined by comparing objects' whole content, not just their IDs)
        octi_objects: set[BaseIdentifiedEntity] = set()

        rows_yielded = 0
        rows_in_bundle = 0
        current_page = start_page

        for row in self.api_client.iter_api_rows(
            api_endpoint=self.config.checkfirst.api_endpoint,
            start_page=start_page,
            since=self.config.checkfirst.since,
            max_row_bytes=self.config.checkfirst.max_row_bytes,
        ):
            self.logger.debug(
                "[CONNECTOR] Processing row from API",
                {"row_number": row.row_number, "row_id": row.id},
            )

            rows_yielded += 1
            run_reporter.rows_seen += 1

            try:
                row_octi_objects = self._create_row_entities(row)

                # Rows share many same entities, so only original objects are added to the set
                # (OCTI models are hashable and comparable for this very purpose)
                for row_octi_object in row_octi_objects:
                    if row_octi_object not in octi_objects:
                        octi_objects.add(row_octi_object)

            except ConversionError as err:  # noqa: BLE001
                run_reporter.skip(SkipReason.ROW_MAPPING_ERROR)
                self.logger.warning(
                    "Skipping row due to conversion error",
                    {
                        "row_number": row.row_number,
                        "row_id": row.id,
                        "error": str(err),
                    },
                )
                continue

            run_reporter.rows_mapped += 1
            rows_in_bundle += 1

            # Increment page every 1_000 rows
            if rows_yielded % PAGE_SIZE == 0:
                current_page += 1

            # Send bundles of ~10_000 entities
            if len(octi_objects) >= BUNDLE_SIZE:
                try:
                    self.logger.info(
                        "Sending bundle",
                        {
                            "octi_objects_count": len(octi_objects),
                            "rows_count": rows_in_bundle,
                            "page": current_page,
                        },
                    )

                    bundle_objects = self._prepare_rows_bundle(octi_objects)
                    self._send_bundle(bundle_objects)

                    self.state.last_page = current_page
                    self.state.save()
                except BundleSendError:
                    self.logger.warning(
                        "Bundle send failed. Skipping it and try the next bundle",
                        {
                            "octi_objects_count": len(octi_objects),
                            "rows_count": rows_in_bundle,
                            "page": current_page,
                        },
                    )
                finally:
                    # Reset for next bundle
                    octi_objects = set()
                    rows_in_bundle = 0

        if not rows_yielded:
            # Log and let the connector end the run
            self.logger.info("No rows fetched from API", {"start_page": start_page})
        elif rows_in_bundle > 0:
            # Send remaining rows
            self.logger.info(
                "Sending final bundle",
                {
                    "octi_objects_count": len(octi_objects),
                    "rows_count": rows_in_bundle,
                    "page": current_page,
                },
            )
            bundle_objects = self._prepare_rows_bundle(octi_objects)
            self._send_bundle(bundle_objects)

            self.state.last_page = current_page
            self.state.save()

    def _send_bundle(
        self,
        octi_objects: list[BaseIdentifiedEntity],
    ) -> None:
        """Assemble and send a STIX bundle to OpenCTI."""
        try:
            if not octi_objects:
                return

            self.logger.debug(
                "[CONNECTOR] Converting OpenCTI objects into STIX2.1 objects",
                {
                    "objects_count": len(self.converter.required_objects)
                    + len(octi_objects)
                },
            )

            octi_objects = self.converter.required_objects + octi_objects
            stix_objects = [obj.to_stix2_object() for obj in octi_objects]

            self.logger.info(
                "[CONNECTOR] Sending STIX objects to OpenCTI...",
                {"objects_count": len(stix_objects)},
            )

            now = datetime.now(tz=timezone.utc)
            work_id = self.helper.api.work.initiate_work(
                connector_id=self.config.connector.id,
                friendly_name=f"{self.config.connector.name} - {now.isoformat()}",
            )

            bundle = self.helper.stix2_create_bundle(stix_objects)
            sent_bundles = self.helper.send_stix2_bundle(
                bundle=bundle,
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )
            run_reporter.bundles_sent += 1

            run_current_summary = run_reporter.to_summary()
            self.helper.api.work.to_processed(
                work_id=work_id,
                message=run_current_summary,
            )

            self.logger.info(
                "[CONNECTOR] STIX bundles sent to OpenCTI...",
                {"sent_bundles": len(sent_bundles)},
            )
        except Exception as err:
            self.logger.error("[CONNECTOR] Bundle send failed", {"error": str(err)})
            run_reporter.error(SkipReason.BUNDLE_SEND_ERROR)

            raise BundleSendError(err) from err

    def process_message(self) -> None:
        """One connector run: fetch API data and push bundles to OpenCTI."""
        self.logger.info(
            "[CONNECTOR] Running connector...",
            {"connector_name": self.config.connector.name},
        )

        # Ensure clean metrics for each run
        run_reporter.reset()

        try:
            # Get the current state
            current_state = self.state.load()
            if current_state.last_run is not None:
                self.logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run": current_state.last_run},
                )
            else:
                self.logger.info("[CONNECTOR] Connector has never run...")

            # Determine the starting page for this run
            if self.config.checkfirst.force_reprocess:
                start_page = 1
            elif current_state.last_page:
                start_page = current_state.last_page
            else:
                start_page = 1

            # On first run (or if force_reprocess is enabled), send a one-off bundle
            # with known Pravda network infrastructure entities.
            if start_page == 1:
                self._send_infrastructure_bundle()
            else:
                self.logger.info(
                    "[CONNECTOR] Resuming from page", {"start_page": start_page}
                )

            # On each run, fetch rows from the API and send bundle of mapped STIX objects
            self._send_rows_bundles(start_page)

        except BundleSendError:
            # Bundle send failure is logged in `_send_bundle` and can't be recovered,
            # so we just end the run here and go to `finally` statement to get run summary.
            pass
        except (KeyboardInterrupt, SystemExit):
            self.logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.config.connector.name},
            )
            sys.exit(0)
        except Exception as err:
            self.logger.error(
                "[CONNECTOR] Unexpected error. See connector's log for more details.",
                {"error": str(err)},
            )
        finally:
            self.state.last_run = datetime.now(timezone.utc)
            self.state.save()

            run_summary = run_reporter.to_summary()
            self.logger.info("Run summary", {"summary": run_summary})

            run_reporter.reset()

    def run(self) -> None:
        """Start the connector using the standard scheduler."""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,  # type: ignore
        )
