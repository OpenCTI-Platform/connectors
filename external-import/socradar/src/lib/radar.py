import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict

import pycti
import requests
import stix2

from stix2 import TLP_WHITE, Bundle
from lib.config_loader import ConfigLoader

BATCH_SIZE = 1000
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


        # Step 1.1: Load configuration file
        if os.path.isfile(config_path):
            with open(config_path, "r") as f:

        # Step 3.4: Set format type for API requests
        self.format_type = ".json?key="

        # Step 4.0: Initialize caches and patterns
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

    def _process_feed(self, work_id: str):
        """
        Batched feed ingestion in chunks of 1000 items
        """
        self.helper.connector_logger.info("RadarConnector: Starting feed collection...")

        for collection_name, collection_data in self.collections.items():
            try:
                # Build feed URL
                coll_id = collection_data["id"][0]
                feed_url = (
                    f"{self.base_url}{coll_id}{self.format_type}{self.socradar_key}&v=2"
                )

                self.helper.connector_logger.info(
                    f"Fetching data from {collection_name} => {feed_url}"
                )
                resp = requests.get(feed_url, timeout=30)
                resp.raise_for_status()
                items = resp.json()
                self.helper.connector_logger.info(
                    f"Got {len(items)} items from {collection_name}"
                )

                stix_batch = []
                total_sent = 0

                for idx, item in enumerate(items, start=1):
                    new_objs = self._process_feed_item(item)
                    if new_objs:
                        stix_batch.extend(new_objs)

                    # If we reached a batch boundary
                    if idx % BATCH_SIZE == 0:
                        bundle = Bundle(objects=stix_batch, allow_custom=True)
                        self.helper.send_stix2_bundle(
                            bundle.serialize(), work_id=work_id
                        )
                        total_sent += len(stix_batch)
                        self.helper.connector_logger.info(
                            f"Sent batch of {len(stix_batch)} objects (total: {total_sent})"
                        )
                        stix_batch = []

                # Final leftover
                if stix_batch:
                    bundle = Bundle(objects=stix_batch, allow_custom=True)
                    self.helper.send_stix2_bundle(bundle.serialize(), work_id=work_id)
                    total_sent += len(stix_batch)
                    self.helper.connector_logger.info(
                        f"Sent final batch of {len(stix_batch)} objects (total: {total_sent})"
                    )

            except Exception as err:
                self.helper.connector_logger.error(
                    f"Failed to process {collection_name}", {"error", err}
                )

    def process(self):
        """
        Run main process to collect, process and send intelligence to OpenCTI.
        """
        error_flag = False

        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            current_state = self.helper.get_state() or {}
            if current_state.get("last_run"):
                last_run = datetime.fromisoformat(
                    current_state.get("last_run")
                ).replace(tzinfo=timezone.utc)

                self.helper.connector_logger.info(
                    "Connector last run:", {"last_run": last_run}
                )
            else:
                self.helper.connector_logger.info("Connector has never run")

            # TODO: init work only if data to ingest
            now = datetime.now(tz=timezone.utc)
            friendly_name = (
                f"SOCRadar Connector run @ {now.isoformat(timespec='seconds')}"
            )
            self.work_id = self.helper.api.work.initiate_work(
                connector_id=self.helper.connector_id,
                friendly_name=friendly_name,
            )

            self._process_feed(self.work_id)
            message = "Radar feed import complete"
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            error_flag = True
            message = "Connector stopped by user or system"
            self.helper.connector_logger.info(
                message, {"connector_name": self.helper.connect_name}
            )
            sys.exit(0)
        except Exception as err:
            error_flag = True
            self.helper.connector_logger.error("Unexpected error.", {"error": str(err)})
            message = "Unexpected error. See connector's log for more details."

        finally:
            if self.work_id:
                self.helper.api.work.to_processed(
                    work_id=self.work_id,
                    message=message,
                    in_error=error_flag,
                )

            self.work_id = None

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
