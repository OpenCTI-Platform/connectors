"""
Echo CTI OpenCTI Connector

This module contains the main connector class that fetches IOCs from
the Echo CTI API and sends them to OpenCTI.
"""

import os
import time
from datetime import datetime
from typing import Any, Dict

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from echocti.client import EchoCTIClient
from echocti.converter import STIXConverter


class EchoCTI:
    """Echo CTI OpenCTI External Import Connector."""

    _CONFIG_NAMESPACE = "echocti"

    def __init__(self) -> None:
        """Initialize the connector."""
        config = self._read_configuration()

        # OpenCTI Helper
        self.helper = OpenCTIConnectorHelper(config)

        # Echo CTI API configuration
        self.base_url = get_config_variable(
            "ECHOCTI_API_URL",
            ["echocti", "api_url"],
            config,
            default="https://api.echocti.com/ioc2/feeds",
        )
        self.client_id = get_config_variable(
            "ECHOCTI_CLIENT_ID",
            ["echocti", "client_id"],
            config,
            required=True,
        )
        self.client_secret = get_config_variable(
            "ECHOCTI_CLIENT_SECRET",
            ["echocti", "client_secret"],
            config,
            required=True,
        )
        self.verify_ssl = get_config_variable(
            "ECHOCTI_VERIFY_SSL",
            ["echocti", "verify_ssl"],
            config,
            default=True,
        )

        # Filter parameters
        self.feed_type = get_config_variable(
            "ECHOCTI_TYPE",
            ["echocti", "type"],
            config,
            default="all",
        )
        self.state = get_config_variable(
            "ECHOCTI_STATE",
            ["echocti", "state"],
            config,
            default="active",
        )
        self.time_since_created = get_config_variable(
            "ECHOCTI_TIME_SINCE_CREATED",
            ["echocti", "time_since_created"],
            config,
        )
        self.time_since_updated = get_config_variable(
            "ECHOCTI_TIME_SINCE_UPDATED",
            ["echocti", "time_since_updated"],
            config,
        )
        self.max_count = get_config_variable(
            "ECHOCTI_MAX_COUNT",
            ["echocti", "max_count"],
            config,
            default=0,
            isNumber=True,
        )
        self.vendor = get_config_variable(
            "ECHOCTI_VENDOR",
            ["echocti", "vendor"],
            config,
        )
        self.tag = get_config_variable(
            "ECHOCTI_TAG",
            ["echocti", "tag"],
            config,
        )

        # STIX converter settings
        self.author_name = "Echo CTI"
        self.default_confidence = get_config_variable(
            "ECHOCTI_DEFAULT_CONFIDENCE",
            ["echocti", "default_confidence"],
            config,
            default=50,
            isNumber=True,
        )

        # Update existing data
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            default=True,
        )

        # Initialize Echo CTI API client
        self.client = EchoCTIClient(
            client_id=self.client_id,
            client_secret=self.client_secret,
            api_url=self.base_url,
            verify_ssl=self.verify_ssl,
        )

        # Initialize STIX converter
        self.converter = STIXConverter(
            author_name=self.author_name,
            default_confidence=self.default_confidence,
        )

        self.helper.log_info("Echo CTI Connector initialized")
        self._log_config()

    @staticmethod
    def _read_configuration() -> Dict[str, Any]:
        """Read configuration from file."""
        config_paths = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml"),
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "..", "config.yml"
            ),
            os.path.join(os.getcwd(), "config.yml"),
        ]

        for config_path in config_paths:
            if os.path.isfile(config_path):
                with open(config_path, encoding="utf-8") as f:
                    return yaml.safe_load(f)

        return {}

    def _log_config(self) -> None:
        """Log the configuration."""
        self.helper.log_info(f"API URL: {self.base_url}")
        self.helper.log_info(f"Feed Type: {self.feed_type}")
        self.helper.log_info(f"State: {self.state}")
        self.helper.log_info(f"Max Count: {self.max_count}")
        if self.time_since_created:
            self.helper.log_info(f"Time Since Created: {self.time_since_created}")
        if self.time_since_updated:
            self.helper.log_info(f"Time Since Updated: {self.time_since_updated}")
        if self.vendor:
            self.helper.log_info(f"Vendor: {self.vendor}")
        if self.tag:
            self.helper.log_info(f"Tag: {self.tag}")

    def _collect_feeds(self) -> list:
        """
        Collect IOC feeds from Echo CTI.

        Returns:
            List of IOCs grouped by feed type
        """
        all_feeds = []

        if self.feed_type and self.feed_type.lower() != "all":
            # Fetch specific types
            types_to_fetch = [t.strip() for t in self.feed_type.split(",")]

            for feed_type in types_to_fetch:
                self.helper.log_info(f"Fetching {feed_type} type IOCs...")
                try:
                    feeds = self.client.get_feeds(
                        feed_type=feed_type,
                        state=self.state,
                        time_since_created=self.time_since_created,
                        time_since_updated=self.time_since_updated,
                        max_count=self.max_count,
                        vendor=self.vendor,
                        tag=self.tag,
                    )
                    # Add type info
                    for feed in feeds:
                        if "type" not in feed:
                            feed["type"] = feed_type
                    all_feeds.extend(feeds)
                except Exception as e:
                    self.helper.log_error(f"Failed to fetch {feed_type} feeds: {e}")
        else:
            # Fetch all types
            self.helper.log_info("Fetching all IOC types...")
            try:
                feeds = self.client.get_feeds(
                    state=self.state,
                    time_since_created=self.time_since_created,
                    time_since_updated=self.time_since_updated,
                    max_count=self.max_count,
                    vendor=self.vendor,
                    tag=self.tag,
                )
                all_feeds.extend(feeds)
            except Exception as e:
                self.helper.log_error(f"Failed to fetch feeds: {e}")

        return all_feeds

    def _process_feeds(self, work_id: str) -> None:
        """
        Process feeds and send to OpenCTI.

        Args:
            work_id: OpenCTI work ID
        """
        self.helper.log_info("Processing Echo CTI feeds...")

        # Collect feeds
        feeds = self._collect_feeds()

        if not feeds:
            self.helper.log_info("No IOCs found to process")
            return

        self.helper.log_info(f"Found {len(feeds)} IOCs")

        # Convert to STIX Bundle
        bundle = self.converter.convert_feeds(feeds, self.feed_type)

        # Send to OpenCTI
        self.helper.log_info("Sending STIX Bundle to OpenCTI...")

        self.helper.send_stix2_bundle(
            bundle.serialize(),
            update=self.update_existing_data,
            work_id=work_id,
        )

        self.helper.log_info("Feeds successfully sent to OpenCTI")

    def run(self) -> None:
        """Run the connector."""
        self.helper.log_info("Echo CTI Connector started")

        while True:
            try:
                # Create work ID
                timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                friendly_name = f"Echo CTI run @ {timestamp}"
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                self.helper.log_info(f"New work started: {friendly_name}")

                # Process feeds
                self._process_feeds(work_id)

                # Complete the work
                message = f"Echo CTI import completed @ {timestamp}"
                self.helper.api.work.to_processed(work_id, message)

                self.helper.log_info(message)

            except Exception as e:
                self.helper.log_error(f"Connector error: {e}")
                import traceback

                self.helper.log_error(traceback.format_exc())

            # Wait for next run
            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Run and terminate mode, exiting")
                break

            # Use helper's schedule mechanism
            time.sleep(
                self.helper.get_run_and_terminate() and 0 or 60
            )  # Minimum 60 seconds wait
