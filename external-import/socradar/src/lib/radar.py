import sys
from datetime import datetime, timezone
from typing import Generator

import pycti
import stix2
from lib.api_client import RadarAPIClient, RadarAPIError, RadarFeedItem
from lib.config_loader import ConfigLoader, FeedList
from lib.converter_to_stix import ConverterError, ConverterToStix

BATCH_MAX_SIZE = 1_000


class RadarConnector:
    """
    OpenCTI connector for SOCRadar threat intelligence feeds.
    Processes indicators in batches and creates STIX2 objects.
    """

    def __init__(
        self, config: ConfigLoader, helper: pycti.OpenCTIConnectorHelper
    ) -> None:
        """Initialize RadarConnector with configuration and helpers"""
        self.config = config
        self.helper = helper

        self.api_client = RadarAPIClient(
            api_base_url=self.config.radar.base_feed_url,
            api_key=self.config.radar.socradar_key,
        )
        self.converter_to_stix = ConverterToStix()

        self.work_id: str | None = None

    def _initiate_work(self):
        """
        Initiate a work on OpenCTI.
        """
        now = datetime.now(tz=timezone.utc)
        friendly_name = f"SOCRadar Connector run @ {now.isoformat(timespec='seconds')}"
        self.work_id = self.helper.api.work.initiate_work(
            connector_id=self.helper.connector_id,
            friendly_name=friendly_name,
        )

    def _finalize_work(self):
        """
        Finalize connector's run work on OpenCTI.
        """
        if self.work_id is None:
            raise ValueError(
                "No work_id to finalize work, call self._initiate_work first"
            )

        self.helper.api.work.to_processed(
            work_id=self.work_id, message="Work gracefully closed."
        )

        self.work_id = None

    def _send_bundle(self, stix_objects: list[stix2.Identity | stix2.Indicator]):
        """
        Create and send bundle to work queue.
        :param stix_objects: List of STIX2 objects to send to ingestion
        """
        bundle = self.helper.stix2_create_bundle(stix_objects)
        sent_bundles = self.helper.send_stix2_bundle(bundle, work_id=self.work_id)

        self.helper.connector_logger.info(
            "Sending STIX bundles to OpenCTI",
            {"work_id": self.work_id, "bundles_count": len(sent_bundles)},
        )

    def _handle_batch(self, stix_objects: list[stix2.Identity | stix2.Indicator]):
        """
        Handle a batch of STIX objects (create work, create and send bundle, then close work).
        :param stix_objects: STIX objects batch to handle (length must be lower than BATCH_MAX_SIZE)
        """
        if len(stix_objects) > BATCH_MAX_SIZE:
            raise ValueError(
                f"STIX objects count exceeds max batch size ({BATCH_MAX_SIZE})"
            )

        self._initiate_work()
        self._send_bundle(stix_objects)
        self._finalize_work()

    def _collect_feed_items(self, feed_list: FeedList) -> list[RadarFeedItem]:
        """
        Collection feed items on SOCRadar API.
        :param feed_list: Collection to get items from.
        """
        self.helper.connector_logger.info(
            f"Collecting items for '{feed_list.name}' feed list",
            {"feed_list_id": feed_list.id, "feed_list_name": feed_list.name},
        )

        feed_items = self.api_client.get_feed(feed_list.id)

        self.helper.connector_logger.info(
            f"{len(feed_items)} items found for '{feed_list.name}' feed list:",
            {
                "feed_list_id": feed_list.id,
                "feed_list_name": feed_list.name,
                "items_count": len(feed_items),
            },
        )

        return feed_items

    def _convert_feed_items(
        self, feed_items: list[RadarFeedItem]
    ) -> Generator[list[stix2.Identity | stix2.Indicator], None, None]:
        """
        Process collection's feed items into STIX Indicator.
        """
        for feed_item in feed_items:
            try:
                author, indicator = self.converter_to_stix.process_on(feed_item)

                self.helper.connector_logger.debug(
                    f"Indicator successfully created",
                    {"author": author, "indicator": indicator},
                )

                yield [author, indicator]
            except ConverterError as err:
                self.helper.connector_logger.error(
                    f"Skipping item due to STIX2 Identity conversion error: {err}",
                    {"error": err},
                )
                continue

    def process(self):
        """
        Run main process to collect, process and send intelligence to OpenCTI.
        """
        try:
            self.helper.connector_logger.info(
                "Starting connector",
                {"connector_name": self.helper.connect_name},
            )

            for feed_list in self.config.radar.feed_lists:
                try:
                    feed_items = self._collect_feed_items(feed_list)
                except RadarAPIError as err:
                    self.helper.connector_logger.error(
                        f"Skipping '{feed_list.name}' feed list due to API client error",
                        {"error": err},
                    )
                    continue

                stix_batch = []
                stix_objects_count = 0

                for stix_objects in self._convert_feed_items(feed_items):
                    stix_batch.extend(stix_objects)

                    # If we reached a batch boundary
                    if len(stix_batch) >= BATCH_MAX_SIZE:
                        self._handle_batch(stix_batch)
                        stix_objects_count += len(stix_batch)
                        stix_batch = []  # Reset to create a new batch

                # Final leftover
                if stix_batch:
                    self._handle_batch(stix_batch)
                    stix_objects_count += len(stix_batch)

                self.helper.connector_logger.info(
                    f"Bundles for '{feed_list.name}' feed list successfully sent",
                    {"work_id": self.work_id, "stix_objects_count": stix_objects_count},
                )

            self.helper.connector_logger.info(
                "Connector successfully run",
                {"connector_name": self.helper.connect_name},
            )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped by user or system",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                f"Unexpected error: {err}",
                {"error": err},
            )

        finally:
            # If an error occured while iterating on feed lists,
            # close potential opened work gracefully.
            if self.work_id:
                self._finalize_work()

    def run(self):
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format

        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        """
        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
