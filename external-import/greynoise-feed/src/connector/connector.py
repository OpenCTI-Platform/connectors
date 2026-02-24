import sys
from datetime import datetime, timedelta
from random import shuffle

import pytz
import stix2
from dateutil.parser import parse
from greynoise.api import APIConfig, GreyNoise
from greynoise.exceptions import RequestFailure
from pycti import (
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)

from .config_loader import ConfigLoader

INTEGRATION_NAME = "opencti-feed-v4.0"


class GreyNoiseFeedConnector:
    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="GreyNoise Feed",
            description="GreyNoise collects and analyzes untargeted, widespread, "
            "and opportunistic scan and attack activity that reaches every server directly connected to the Internet.",
            custom_properties={
                "x_opencti_reliability": "B - Usually reliable",
                "x_opencti_organization_type": "vendor",
            },
        )

        # Cache for label
        self.labels_cache = {}

    def get_feed_query(self, feed_type: str):
        query = ""
        if feed_type.lower() not in [
            "benign",
            "malicious",
            "suspicious",
            "benign+malicious",
            "benign+suspicious+malicious",
            "malicious+suspicious",
            "all",
        ]:
            self.helper.log_error(
                "Value for feed_type is not valid. Valid options are: benign, malicious, suspicious, "
                "benign+malicious, benign+suspicious+malicious, malicious+suspicious, all"
            )
            sys.exit(1)
        elif feed_type.lower() == "benign":
            query = "last_seen_benign:1d classification:benign"
        elif feed_type.lower() == "malicious":
            query = "last_seen_malicious:1d classification:malicious"
        elif feed_type.lower() == "suspicious":
            query = "last_seen_suspicious:1d classification:suspicious"
        elif feed_type.lower() == "benign+malicious":
            query = "(last_seen_malicious:1d classification:malicious) OR (last_seen_benign:1d classification:benign)"
        elif feed_type.lower() == "malicious+suspicious":
            query = "(last_seen_malicious:1d classification:malicious) OR (last_seen_suspicious:1d classification:suspicious)"
        elif feed_type.lower() == "benign+suspicious+malicious":
            query = "(last_seen_malicious:1d classification:malicious) OR (last_seen_suspicious:1d classification:suspicious) OR (last_seen_benign:1d classification:benign)"
        elif feed_type.lower() == "all":
            query = "last_seen:1d"

        return query

    def _process_labels(self, data: dict) -> tuple:
        """
        This method allows you to start the process of creating labels and recovering associated malware.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :param data_tags: A parameter that contains all the data relating to the existing tags in GreyNoise
        :return: A tuple (all labels, all malwares)
        """

        self.all_labels = []
        all_malwares = []

        if data["internet_scanner_intelligence"]["classification"] == "benign":
            # Create label GreyNoise "benign"
            self._create_custom_label("gn-classification: benign", "#06c93a")
            # Include additional label "benign-actor"
            self._create_custom_label(
                f"gn-benign-actor: {data['internet_scanner_intelligence']['actor']} ",
                "#06c93a",
            )
        elif data["internet_scanner_intelligence"]["classification"] == "unknown":
            # Create label GreyNoise "unknown"
            self._create_custom_label("gn-classification: unknown", "#a6a09f")
        elif data["internet_scanner_intelligence"]["classification"] == "malicious":
            # Create label GreyNoise "malicious"
            self._create_custom_label("gn-classification: malicious", "#ff8178")
        elif data["internet_scanner_intelligence"]["classification"] == "suspicious":
            # Create label GreyNoise "suspicious"
            self._create_custom_label("gn-classification: suspicious", "#e3d922")

        if data["business_service_intelligence"]["trust_level"] == "1":
            # Create label GreyNoise "trust level 1"
            self._create_custom_label("gn-trust-level: reasonably ignore", "#90D5FF")
            # Include additional label "provider"
            self._create_custom_label(
                f"gn-provider: {data['business_service_intelligence']['name']} ",
                "#90D5FF",
            )
        elif data["business_service_intelligence"]["trust_level"] == "2":
            # Create label GreyNoise "trust level 1"
            self._create_custom_label("gn-trust-level: commonly seen", "#57B9FF")
            # Include additional label "provider"
            self._create_custom_label(
                f"gn-provider: {data['business_service_intelligence']['name']} ",
                "#57B9FF",
            )

        return self.all_labels, all_malwares

    def _create_custom_label(self, name_label: str, color_label: str):
        """
        This method allows you to create a custom label, using the OpenCTI API.

        :param name_label: A parameter giving the name of the label.
        :param color_label: A parameter giving the color of the label.
        """

        if name_label in self.labels_cache:
            self.all_labels.append(self.labels_cache[name_label]["value"])
        else:
            new_custom_label = self.helper.api.label.read_or_create_unchecked(
                value=name_label, color=color_label
            )
            if new_custom_label is None:
                self.helper.connector_logger.error(
                    "[ERROR] The label could not be created. "
                    "If your connector does not have the permission to create labels, "
                    "please create it manually before launching",
                    {"name_label": name_label},
                )
            else:
                self.labels_cache[name_label] = new_custom_label
                self.all_labels.append(new_custom_label["value"])

    @staticmethod
    def _get_match(data, key, value):
        return next((x for x in data if x[key] == value), None)

    def _get_indicator_score(self, classification):
        if classification == "malicious":
            score = self.config.greynoise_feed.indicator_score_malicious
        elif classification == "suspicious":
            score = self.config.greynoise_feed.indicator_score_suspicious
        else:
            score = self.config.greynoise_feed.indicator_score_benign

        return score

    def _process_data(self, work_id, ips_list):
        bundle_entities = []
        bundle_relationships = []

        self.helper.log_info("Building Indicator Bundles")
        for ip in ips_list:

            if "ip" not in ip or "internet_scanner_intelligence" not in ip:
                continue

            description = (
                "Internet Scanning IP detected by GreyNoise with classification `"
                + ip["internet_scanner_intelligence"]["classification"]
                + "`."
            )
            pattern = "[ipv4-addr:value = '" + ip["ip"] + "']"

            labels, malwares = self._process_labels(ip)

            if (
                "first_seen" in ip["internet_scanner_intelligence"]
                and ip["internet_scanner_intelligence"]["first_seen"]
            ):
                first_seen = parse(
                    ip["internet_scanner_intelligence"]["first_seen"]
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                last_seen = parse(
                    ip["internet_scanner_intelligence"]["last_seen_timestamp"]
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                first_seen = parse(
                    ip["internet_scanner_intelligence"]["last_seen_timestamp"]
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                last_seen = datetime.strptime(
                    ip["internet_scanner_intelligence"]["last_seen_timestamp"],
                    "%Y-%m-%d",
                ) + timedelta(hours=23)
                last_seen = last_seen.strftime("%Y-%m-%dT%H:%M:%SZ")
            # Generate ExternalReference
            external_reference = stix2.ExternalReference(
                source_name="GreyNoise Feed",
                url="https://viz.greynoise.io/ip/" + ip["ip"],
            )

            # Generate Indicator
            stix_indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=ip["ip"],
                description=description,
                created_by_ref=self.identity["standard_id"],
                pattern_type="stix",
                pattern=pattern,
                external_references=[external_reference],
                object_marking_refs=[stix2.TLP_GREEN],
                labels=labels,
                created=first_seen,
                custom_properties={
                    "x_opencti_score": (
                        self._get_indicator_score(
                            ip["internet_scanner_intelligence"]["classification"]
                        )
                    ),
                    "x_opencti_main_observable_type": "IPv4-Addr",
                },
            )
            bundle_entities.append(stix_indicator)

            # Generate Observable
            stix_observable = stix2.IPv4Address(
                type="ipv4-addr",
                value=ip["ip"],
                object_marking_refs=[stix2.TLP_GREEN],
                custom_properties={
                    "x_opencti_description": description,
                    "x_opencti_score": (
                        self._get_indicator_score(
                            ip["internet_scanner_intelligence"]["classification"]
                        )
                    ),
                    "created_by_ref": self.identity["standard_id"],
                    "labels": labels,
                    "external_references": [external_reference],
                },
            )
            bundle_entities.append(stix_observable)

            # Generate relationship Indicator => Observable
            stix_relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", stix_indicator.id, stix_observable.id
                ),
                relationship_type="based-on",
                source_ref=stix_indicator.id,
                target_ref=stix_observable.id,
                created_by_ref=self.identity["standard_id"],
                object_marking_refs=[stix2.TLP_GREEN],
            )
            bundle_relationships.append(stix_relationship)

        # Creating the bundle from the list
        if len(bundle_entities) > 0:
            shuffle(bundle_relationships)
            bundle_objects = bundle_entities + bundle_relationships
            batch_count = 0
            bundle_objects_len = len(bundle_objects)
            batch_size = 50000
            for i in range(batch_count, bundle_objects_len, batch_size):
                self.helper.log_info("Batch: " + str(int(i) / int(batch_size)))
                x = i
                self.helper.log_info("Creating Bundles")
                bundle = self.helper.stix2_create_bundle(
                    bundle_objects[x : x + batch_size]
                )
                self.helper.log_info("Submitting Bundles")
                self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                )

    def process(self):
        self.helper.log_info("GreyNoise feed - Initialization...")

        self.labels_cache = {}
        try:
            # Get the current timestamp and check
            now = datetime.now(pytz.UTC)
            current_state = self.helper.get_state()
            if (
                current_state is not None
                and "api_key_error" in current_state
                and current_state["api_key_error"]
            ):
                self.helper.log_error(
                    "API Key Error - Connector will not run - Update API Key and Clear State to Run Again"
                )
                return
            if current_state is not None and "last_run_timestamp" in current_state:
                last_run_timestamp = parse(current_state["last_run_timestamp"])
            else:
                last_run_timestamp = now - timedelta(days=1)
            if current_state is not None and "most_recent_last_seen" in current_state:
                most_recent_last_seen = parse(current_state["most_recent_last_seen"])
            else:
                most_recent_last_seen = datetime.now(pytz.UTC) - timedelta(days=30)

            self.helper.log_info(
                "Fetching GreyNoise feeds since "
                + last_run_timestamp.astimezone(pytz.UTC).isoformat()
            )

            try:
                ips_list = []
                api_config = APIConfig(
                    api_key=self.config.greynoise_feed.api_key.get_secret_value(),
                    integration_name=INTEGRATION_NAME,
                )
                session = GreyNoise(api_config)

                query = self.get_feed_query(self.config.greynoise_feed.feed_type)
                self.helper.log_info(
                    "Querying GreyNoise API - First Results Page (" + query + ")"
                )
                response = session.query(query=query, exclude_raw=True, size=5000)
                complete = response.get("request_metadata", {}).get("complete", True)
                scroll = response.get("request_metadata", {}).get("scroll", "")

                # Process
                if "data" in response and len(response["data"]) > 0:
                    added_count = 0
                    skip_count = 0
                    most_recent_timestamp = None
                    for ip in response["data"]:
                        last_seen_str = ip.get("internet_scanner_intelligence", {}).get(
                            "last_seen_timestamp", ""
                        )
                        # Parse the timestamp string (format: "2026-01-26 19:59:37") to a timezone-aware datetime
                        last_seen_dt = datetime.strptime(
                            last_seen_str, "%Y-%m-%d %H:%M:%S"
                        ).replace(tzinfo=pytz.UTC)
                        if last_seen_dt > most_recent_last_seen:
                            ips_list.append(ip)
                            added_count += 1
                            if (
                                most_recent_timestamp is None
                                or most_recent_timestamp < last_seen_dt
                            ):
                                most_recent_timestamp = last_seen_dt
                        else:
                            skip_count += 1
                    self.helper.log_info("Added: " + str(added_count) + " IPs")
                    self.helper.log_info("Skipped: " + str(skip_count) + " IPs")

                if len(ips_list) >= self.config.greynoise_feed.limit:
                    complete = True
                    ips_list = ips_list[0 : self.config.greynoise_feed.limit]

                while not complete:
                    self.helper.log_info(
                        "Query GreyNoise API - Next Results Page (" + query + ")"
                    )
                    response = session.query(
                        query=query, scroll=scroll, exclude_raw=True, size=5000
                    )
                    complete = response.get("request_metadata", {}).get(
                        "complete", True
                    )
                    scroll = response.get("request_metadata", {}).get("scroll", "")

                    # Process
                    if "data" in response and len(response["data"]) > 0:
                        added_count = 0
                        skip_count = 0
                        for ip in response["data"]:
                            last_seen_str = ip.get(
                                "internet_scanner_intelligence", {}
                            ).get("last_seen_timestamp", "")
                            # Parse the timestamp string (format: "2026-01-26 19:59:37") to a timezone-aware datetime
                            last_seen_dt = datetime.strptime(
                                last_seen_str, "%Y-%m-%d %H:%M:%S"
                            ).replace(tzinfo=pytz.UTC)
                            if last_seen_dt > most_recent_last_seen:
                                ips_list.append(ip)
                                added_count += 1
                                if (
                                    most_recent_timestamp is None
                                    or most_recent_timestamp < last_seen_dt
                                ):
                                    most_recent_timestamp = last_seen_dt
                            else:
                                skip_count += 1
                        self.helper.log_info("Added: " + str(added_count) + " IPs")
                        self.helper.log_info("Skipped: " + str(skip_count) + " IPs")

                        if len(ips_list) >= self.config.greynoise_feed.limit:
                            complete = True
                            ips_list = ips_list[0 : self.config.greynoise_feed.limit]

                if most_recent_timestamp is not None:
                    most_recent_last_seen = most_recent_timestamp
                self.helper.log_info("Query GreyNoise API - Completed")
                self.helper.log_info("GreyNoise Indicator Count: " + str(len(ips_list)))
                self.helper.log_info(
                    "Most Recent Last Seen: " + most_recent_last_seen.isoformat()
                )

                # Process
                friendly_name = (
                    "GreyNoise Feed connector run (" + str(len(ips_list)) + " IPs)"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self._process_data(work_id, ips_list)
                message = (
                    "Connector successfully run, storing last_run_timestamp as "
                    + now.astimezone(pytz.UTC).isoformat()
                    + " and most_recent_last_seen as "
                    + most_recent_last_seen.isoformat()
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
                self.helper.set_state(
                    {
                        "last_run_timestamp": now.astimezone(pytz.UTC).isoformat(),
                        "most_recent_last_seen": most_recent_last_seen.isoformat(),
                        "api_key_error": False,
                    }
                )

            except RequestFailure as e:
                status_code = e.args[0]
                if status_code == 401:
                    self.helper.set_state(
                        {
                            "last_run_timestamp": now.astimezone(pytz.UTC).isoformat(),
                            "most_recent_last_seen": most_recent_last_seen.isoformat(),
                            "api_key_error": True,
                        }
                    )
                    self.helper.log_error(
                        "API authentication failed - your plan may not support this endpoint"
                    )
                else:
                    self.helper.log_error(str(e))
            except Exception as e:
                self.helper.log_error(str(e))

        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))
            sys.exit(1)

    def run(self):
        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
