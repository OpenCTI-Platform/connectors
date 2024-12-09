# Standard library imports
import os
import re
import time
import uuid
from datetime import datetime, timedelta

# Third-party imports
import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import (
    TLP_WHITE,
    URL,
    Bundle,
    DomainName,
    File,
    Identity,
    Indicator,
    IPv4Address,
    IPv6Address,
    KillChainPhase,
    Relationship,
)


class RadarConnector:

    def __init__(self):
        # Step 1.0: Initialize connector from config
        config_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        config = yaml.load(open(config_path), Loader=yaml.SafeLoader)
        self.helper = OpenCTIConnectorHelper(config)

        # Step 1.1: Get radar-specific configurations
        self.base_url = get_config_variable(
            "RADAR_BASE_FEED_URL", ["radar", "base_feed_url"], config
        )
        self.format_type = get_config_variable(
            "RADAR_FORMAT_TYPE", ["radar", "format_type"], config
        )
        self.socradar_key = get_config_variable(
            "RADAR_SOCRADAR_KEY", ["radar", "socradar_key"], config
        )
        self.collections = get_config_variable(
            "RADAR_COLLECTIONS_UUID", ["radar", "collections_uuid"], config
        )
        self.interval = get_config_variable(
            "RADAR_INTERVAL", ["radar", "run_interval"], config, True
        )

        # Initialize empty identity mapping
        self.identity_mapping = {}

        # Step 1.2: Initialize regex patterns for value classification
        self.regex_patterns = {
            "md5": r"^[a-fA-F\d]{32}$",
            "sha1": r"^[a-fA-F\d]{40}$",
            "sha256": r"^[a-fA-F\d]{64}$",
            "ipv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
            "ipv6": r"^(?:[a-fA-F\d]{1,4}:){7}[a-fA-F\d]{1,4}$",
            "domain": r"^(?=.{1,255}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,6}$",
            "url": r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
        }

    def _get_indicator_type(self, feed_type):
        """Map feed types to STIX indicator types"""
        type_mapping = {
            "url": ["url-watchlist"],
            "domain": ["domain-watchlist"],
            "ip": ["ip-watchlist"],
            "hash": ["file-hash-watchlist"],
        }
        return type_mapping.get(feed_type, ["malicious-activity"])

    def _get_or_create_identity(self, maintainer_name):
        """Get existing identity or create new one for maintainer"""
        try:
            if maintainer_name in self.identity_mapping:
                return self.identity_mapping[maintainer_name]

            current_time = datetime.utcnow()

            # Create new identity for maintainer
            identity = Identity(
                id=f"identity--{str(uuid.uuid4())}",
                name=maintainer_name,
                identity_class="organization",
                description=f"Feed Provider: {maintainer_name}",
                sectors=["technology"],
                created=current_time,
                modified=current_time,
            )

            # Store in mapping for reuse
            self.identity_mapping[maintainer_name] = identity
            self.helper.log_info(
                f"Created new identity for maintainer: {maintainer_name}"
            )
            return identity

        except Exception as e:
            self.helper.log_error(
                f"Error creating identity for {maintainer_name}: {str(e)}"
            )
            return None

    def _process_feed_item(self, item, work_id):
        try:
            value = item["feed"]
            feed_type = item.get("feed_type", "").lower()
            maintainer = item.get("maintainer_name", "Unknown")
            first_seen = datetime.strptime(item["first_seen_date"], "%Y-%m-%d %H:%M:%S")
            last_seen = datetime.strptime(item["latest_seen_date"], "%Y-%m-%d %H:%M:%S")

            if last_seen <= first_seen:
                last_seen = first_seen + timedelta(days=365)

            # Get or create identity for this maintainer
            maintainer_identity = self._get_or_create_identity(maintainer)
            if not maintainer_identity:
                self.helper.log_error(
                    f"Could not create identity for maintainer: {maintainer}"
                )
                return

            pattern = self._create_stix_pattern(value, feed_type)
            if not pattern:
                self.helper.log_error(
                    f"Could not create pattern for: {value} ({feed_type})"
                )
                return

            # Create kill chain phase
            kill_chain_phase = KillChainPhase(
                kill_chain_name="lockheed-martin-cyber-kill-chain",
                phase_name="reconnaissance",
            )

            indicator = Indicator(
                id=f"indicator--{str(uuid.uuid4())}",
                name=f"{feed_type.upper()}: {value}",
                description=f"Type: {feed_type}\nValue: {value}\nSource: {maintainer}",
                pattern_type="stix",
                pattern=pattern,
                valid_from=first_seen,
                valid_until=last_seen,
                labels=[feed_type, "malicious-activity"],
                confidence=75,
                indicator_types=self._get_indicator_type(feed_type),
                kill_chain_phases=[kill_chain_phase],
                created=first_seen,
                modified=first_seen,
                created_by_ref=maintainer_identity.id,  # Use maintainer's identity
                object_marking_refs=[TLP_WHITE],
            )

            # Create relationship between indicator and maintainer identity
            relationship = Relationship(
                id=f"relationship--{str(uuid.uuid4())}",
                relationship_type="created-by",
                source_ref=indicator.id,
                target_ref=maintainer_identity.id,
                description=f"This indicator was created by {maintainer}",
                created=first_seen,
                modified=first_seen,
                confidence=75,
                object_marking_refs=[TLP_WHITE],
            )

            # Create bundle with all objects
            bundle = Bundle(objects=[maintainer_identity, indicator, relationship])

            # Send to OpenCTI
            self.helper.send_stix2_bundle(bundle.serialize(), work_id=work_id)

            self.helper.log_info(
                f"Created {feed_type} indicator for: {value} from {maintainer}"
            )

        except Exception as e:
            self.helper.log_error(f"Error processing item {str(item)}: {str(e)}")

    def _create_observable(self, value, feed_type):
        """Create appropriate observable based on value type with proper STIX ID"""
        try:
            if feed_type == "url" or self._matches_pattern(value, "url"):
                return URL(
                    id=f"url--{str(uuid.uuid4())}",
                    value=value,
                    type="url",
                    defanged=False,
                )
            elif feed_type == "domain" or self._matches_pattern(value, "domain"):
                return DomainName(
                    id=f"domain-name--{str(uuid.uuid4())}",
                    value=value,
                    type="domain-name",
                    defanged=False,
                )
            elif feed_type == "ip" or self._matches_pattern(value, "ipv4"):
                return IPv4Address(
                    id=f"ipv4-addr--{str(uuid.uuid4())}",
                    value=value,
                    type="ipv4-addr",
                    defanged=False,
                )
            elif self._matches_pattern(value, "ipv6"):
                return IPv6Address(
                    id=f"ipv6-addr--{str(uuid.uuid4())}",
                    value=value,
                    type="ipv6-addr",
                    defanged=False,
                )
            elif feed_type == "hash":
                if self._matches_pattern(value, "md5"):
                    return File(
                        id=f"file--{str(uuid.uuid4())}",
                        type="file",
                        hashes={"MD5": value},
                    )
                elif self._matches_pattern(value, "sha1"):
                    return File(
                        id=f"file--{str(uuid.uuid4())}",
                        type="file",
                        hashes={"SHA-1": value},
                    )
                elif self._matches_pattern(value, "sha256"):
                    return File(
                        id=f"file--{str(uuid.uuid4())}",
                        type="file",
                        hashes={"SHA-256": value},
                    )
            return None
        except Exception as e:
            self.helper.log_error(f"Error creating observable for {value}: {str(e)}")
            return None

    def _matches_pattern(self, value, pattern_name):
        """Step 3.2: Check if value matches a regex pattern"""
        import re

        return re.match(self.regex_patterns[pattern_name], value) is not None

    def _create_stix_pattern(self, value, feed_type):
        """Create STIX pattern based on feed type"""
        # Direct mapping for feed types
        if feed_type == "url":
            return f"[url:value = '{value}']"
        elif feed_type == "domain":
            return f"[domain-name:value = '{value}']"
        elif feed_type == "ip":  # Add handling for IP type
            if re.match(self.regex_patterns["ipv4"], value):
                return f"[ipv4-addr:value = '{value}']"
            elif re.match(self.regex_patterns["ipv6"], value):
                return f"[ipv6-addr:value = '{value}']"
        elif feed_type == "hash":
            if re.match(self.regex_patterns["md5"], value):
                return f"[file:hashes.'MD5' = '{value}']"
            elif re.match(self.regex_patterns["sha1"], value):
                return f"[file:hashes.'SHA-1' = '{value}']"
            elif re.match(self.regex_patterns["sha256"], value):
                return f"[file:hashes.'SHA-256' = '{value}']"

        # Fallback to pattern detection if feed_type doesn't match
        for pattern_type, regex in self.regex_patterns.items():
            if re.match(regex, value):
                if pattern_type == "url":
                    return f"[url:value = '{value}']"
                elif pattern_type == "domain":
                    return f"[domain-name:value = '{value}']"
                elif pattern_type == "ipv4":
                    return f"[ipv4-addr:value = '{value}']"
                elif pattern_type == "ipv6":
                    return f"[ipv6-addr:value = '{value}']"

        self.helper.log_error(
            f"Could not determine pattern for value: {value} (type: {feed_type})"
        )
        return None

    def run(self):
        self.helper.log_info("Starting RadarConnector...")

        # Force first run by setting last_run to None
        self.helper.set_state(None)

        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                last_run = current_state.get("last_run") if current_state else None

                if last_run is None or ((timestamp - last_run) > self.interval):
                    self.helper.log_info("Starting feed collection...")

                    for collection_name, collection_data in self.collections.items():
                        try:
                            collection_id = collection_data["id"][0]
                            feed_url = f"{self.base_url}{collection_id}{self.format_type}{self.socradar_key}&v=2"

                            self.helper.log_info(
                                f"Fetching data from: {collection_name}"
                            )
                            response = requests.get(feed_url)
                            response.raise_for_status()

                            items = response.json()
                            total_items = len(items)
                            self.helper.log_info(
                                f"Processing {total_items} items from {collection_name}"
                            )

                            # Process in smaller batches
                            batch_size = 10  # Reduced from 100
                            total_batches = (total_items + batch_size - 1) // batch_size

                            for i in range(0, total_items, batch_size):
                                batch = items[i : i + batch_size]
                                current_batch = i // batch_size + 1

                                self.helper.log_info(
                                    f"Processing batch {current_batch}/{total_batches}"
                                )

                                work_id = self.helper.api.work.initiate_work(
                                    self.helper.connect_id,
                                    f"Processing batch {current_batch}/{total_batches} of {collection_name}",
                                )

                                for item in batch:
                                    self._process_feed_item(item, work_id)
                                    time.sleep(0.5)  # Add small delay between items

                                self.helper.api.work.to_processed(
                                    work_id, "Batch processing completed"
                                )
                                time.sleep(2)  # Increased delay between batches

                        except Exception as e:
                            self.helper.log_error(
                                f"Error processing collection {collection_name}: {str(e)}"
                            )

                    self.helper.set_state({"last_run": timestamp})
                    self.helper.log_info(
                        f"Feed collection complete. Next run in {self.interval} seconds"
                    )

                time.sleep(60)

            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)
