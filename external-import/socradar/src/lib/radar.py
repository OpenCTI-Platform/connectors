import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict

import pycti
import stix2
from lib.api_client import RadarAPIClient, RadarAPIError, RadarFeedItem
from lib.config_loader import ConfigLoader, FeedList

BATCH_MAX_SIZE = 10_000
TLP_MARKING = stix2.TLP_WHITE.id


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

        self.identity_cache: dict[str, stix2.Identity] = {}
        self.identity_cache: Dict[str, stix2.Identity] = {}
        self.regex_patterns = {
            "md5": r"^[a-fA-F\d]{32}$",
            "sha1": r"^[a-fA-F\d]{40}$",
            "sha256": r"^[a-fA-F\d]{64}$",
            "ipv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
            "ipv6": r"^(?:[a-fA-F\d]{1,4}:){7}[a-fA-F\d]{1,4}$",
            "domain": r"^(?=.{1,255}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,6}$",
            "url": r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
        }

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

        return items

    def _matches_pattern(self, value: str, pattern_name: str) -> bool:
        """Match value against regex pattern"""
        return bool(re.match(self.regex_patterns[pattern_name], value))

    def _validate_dates(self, first_seen: str, last_seen: str):
        """Validate and convert date strings to datetime objects"""
        # Step 1.0: Set datetime format
        dt_format = "%Y-%m-%d %H:%M:%S"

        # Step 1.1: Convert strings to datetime objects
        valid_from = datetime.strptime(first_seen, dt_format)
        valid_until = datetime.strptime(last_seen, dt_format)

        # Step 1.2: Ensure valid time range
        if valid_until <= valid_from:
            valid_until = valid_from + timedelta(hours=1)

        return valid_from, valid_until

    def _create_stix_pattern(self, value: str, feed_type: str) -> str:
        """
        Build a STIX pattern from feed_type or fallback detection
        (handles ip, domain, url, hash, etc.)
        """
        # If feed_type is "ip", check IPv4 or IPv6
        if feed_type == "ip":
            if self._matches_pattern(value, "ipv4"):
                return f"[ipv4-addr:value = '{value}']"
            elif self._matches_pattern(value, "ipv6"):
                return f"[ipv6-addr:value = '{value}']"

        known_patterns = {
            "url": lambda v: f"[url:value = '{v}']",
            "domain": lambda v: f"[domain-name:value = '{v}']",
            "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
            "ipv6": lambda v: f"[ipv6-addr:value = '{v}']",
            "md5": lambda v: f"[file:hashes.'MD5' = '{v}']",
            "sha1": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
            "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
        }

        if feed_type in known_patterns:
            return known_patterns[feed_type](value)

        # Fallback detection
        for ptype, regex in self.regex_patterns.items():
            if re.match(regex, value):
                # e.g. ptype=md5 => "[file:hashes.'MD5' = '...']"
                if ptype in known_patterns:
                    return known_patterns[ptype](value)

        # Otherwise, custom
        return f"[x-custom:value = '{value}']"

    def _get_or_create_identity(self, maintainer_name: str):
        """
        Use pycti.Identity.generate_id(...) for stable dedup
        Return a stix2.Identity w/ that ID
        """
        if maintainer_name in self.identity_cache:
            return self.identity_cache[maintainer_name]

        try:
            now = datetime.now(tz=timezone.utc)
            identity = stix2.Identity(
                id=pycti.Identity.generate_id(
                    name=maintainer_name,
                    identity_class="organization",
                ),
                name=maintainer_name,
                identity_class="organization",
                description=f"Feed Provider: {maintainer_name}",
                created=now,
                modified=now,
            )
            self.identity_cache[maintainer_name] = identity
            return identity
        except stix2.exceptions.STIXError as err:
            self.helper.connector_logger.error(
                f"Error creating Identity for {maintainer_name}", {"error": err}
            )
            return None

    def _process_feed_item(self, item: dict):
        """Process single feed item into STIX objects"""
        # Step 1.0: Initialize empty list for STIX objects
        stix_objects = []

        # Step 2.0: Extract core fields from feed item
        # Step 2.1: Get primary indicator value
        value = item.get("feed")
        # Step 2.2: Get indicator type (default to IP if not specified)
        feed_type = item.get("feed_type", "ip").lower()
        # Step 2.3: Get source/maintainer information
        maintainer = item.get("maintainer_name", "Unknown")

        # Step 3.0: Extract and validate timestamp fields
        # Step 3.1: Get first seen date
        first_seen_str = item.get("first_seen_date")
        # Step 3.2: Get last seen date
        last_seen_str = item.get("latest_seen_date")
        # Step 3.3: Validate required fields exist
        if not (value and first_seen_str and last_seen_str):
            self.helper.connector_logger.error(f"Item missing fields: {item}")
            return stix_objects

        # Step 4.0: Convert and validate dates
        valid_from, valid_until = self._validate_dates(first_seen_str, last_seen_str)

        # Step 5.0: Create or get cached identity object
        identity_obj = self._get_or_create_identity(maintainer)
        if not identity_obj:
            return stix_objects

        # Step 6.0: Generate STIX pattern for indicator
        pattern = self._create_stix_pattern(value, feed_type)
        if not pattern:
            self.helper.connector_logger.error(
                f"Could not determine pattern for: {value} / {feed_type}"
            )
            return stix_objects

        try:
            # Step 8.0: Create STIX2 Indicator object
            indicator = stix2.Indicator(
                id=pycti.Indicator.generate_id(pattern),
                name=f"{feed_type.upper()}: {value}",
                description=f"Source: {maintainer}\nValue: {value}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=valid_from,
                valid_until=valid_until,
                created_by_ref=identity_obj.id,
                object_marking_refs=[stix2.TLP_WHITE.id],
                labels=["malicious-activity", feed_type],
                created=valid_from,
                modified=valid_from,
            )

            # Step 9.0: Combine all STIX objects
            stix_objects.extend([identity_obj, indicator])
            # Step 9.1: Log success
            self.helper.connector_logger.info(
                f"Created {feed_type} indicator => {value} from {maintainer}"
            )
        except stix2.exceptions.STIXError as err:
            self.helper.connector_logger.error(
                f"Indicator ID generation error", {"error": err}
            )

        return stix_objects

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

                for feed_item in feed_items:
                    stix_objects = self._process_feed_item(feed_item)
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
