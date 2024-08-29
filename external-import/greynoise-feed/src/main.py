import os
import time
from datetime import datetime, timedelta

import stix2
import yaml
from dateutil.parser import parse
from greynoise import GreyNoise
from pycti import (
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
    get_config_variable,
)


class GreyNoiseFeed:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.api_key = get_config_variable(
            "GREYNOISE_API_KEY", ["greynoisefeed", "api_key"], config
        )
        self.feed_type = get_config_variable(
            "GREYNOISE_FEED_TYPE", ["greynoisefeed", "feed_type"], config, required=True
        )
        self.indicator_score = get_config_variable(
            "GREYNOISE_INDICATOR_SCORE",
            ["greynoisefeed", "indicator_score"],
            config,
            isNumber=True,
        )
        self.limit = get_config_variable(
            "GREYNOISE_LIMIT", ["greynoisefeed", "limit"], config, isNumber=True
        )
        self.interval = get_config_variable(
            "GREYNOISE_INTERVAL",
            ["greynoisefeed", "interval"],
            config,
            isNumber=True,
        )
        self.greynoise_ent_name = get_config_variable(
            "GREYNOISE_NAME", ["greynoisefeed", "name"], config
        )
        self.greynoise_ent_desc = get_config_variable(
            "GREYNOISE_DESCRIPTION", ["greynoisefeed", "description"], config
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name=self.greynoise_ent_name,
            description=self.greynoise_ent_desc,
        )

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def get_feed_query(self, feed_type):
        query = ""
        if feed_type.lower() not in ["benign", "malicious", "benign+malicious", "all"]:
            self.helper.log_error(
                "Value for feed_type is not one of: benign, malicious, or all"
            )
            exit(1)
        elif feed_type.lower() == "benign":
            query = "last_seen:1d classification:benign"
        elif feed_type.lower() == "malicious":
            query = "last_seen:1d classification:malicious"
        elif feed_type.lower() == "benign+malicious":
            query = "last_seen:1d (classification:malicious OR classification:benign)"
        elif feed_type.lower() == "all":
            query = "last_seen:1d"

        return query

    def _process_labels(self, data: dict, data_tags: dict) -> tuple:
        """
        This method allows you to start the process of creating labels and recovering associated malware.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :param data_tags: A parameter that contains all the data relating to the existing tags in GreyNoise
        :return: A tuple (all labels, all malwares)
        """

        self.all_labels = []
        all_malwares = []
        entity_tags = data["tags"]

        if data["classification"] == "benign":
            # Create label GreyNoise "benign"
            self._create_custom_label("gn-classification: benign", "#06c93a")
            # Include additional label "benign-actor"
            self._create_custom_label(f"gn-benign-actor: {data['actor']} ", "#06c93a")

        elif data["classification"] == "unknown":
            # Create label GreyNoise "unknown"
            self._create_custom_label("gn-classification: unknown", "#a6a09f")

        elif data["classification"] == "malicious":
            # Create label GreyNoise "malicious"
            self._create_custom_label("gn-classification: malicious", "#ff8178")

        if data["bot"] is True:
            # Create label for "Known Bot Activity"
            self._create_custom_label("Known BOT Activity", "#7e4ec2")

        if data["metadata"]["tor"] is True:
            # Create label for "Known Tor Exit Node"
            self._create_custom_label("Known TOR Exit Node", "#7e4ec2")

        # Create all Labels in entity_tags
        for tag in entity_tags:
            tag_details_matching = self._get_match(data_tags["metadata"], "name", tag)
            if tag_details_matching is not None:
                tag_details = tag_details_matching
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] The tag was created, but its details were not correctly recognized by GreyNoise,"
                    " which is often related to a name problem.",
                    {"Tag_name": tag},
                )
                self.all_labels.append(tag)
                continue

            # Create red label when malicious intent and type not category worm and activity
            if tag_details["intention"] == "malicious" and tag_details[
                "category"
            ] not in ["worm", "activity"]:
                self._create_custom_label(f"{tag}", "#ff8178")

            # If category is worm, prepare malware object
            elif tag_details["category"] == "worm":
                malware_worm = {
                    "name": f"{tag}",
                    "description": f"{tag_details['description']}",
                    "type": "worm",
                }
                all_malwares.append(malware_worm)
                self.all_labels.append(tag)

            # If category is malicious and activity, prepare malware object
            elif (
                tag_details["intention"] == "malicious"
                and tag_details["category"] == "activity"
            ):
                malware_malicious_activity = {
                    "name": f"{tag}",
                    "description": f"{tag_details['description']}",
                    "type": "malicious_activity",
                }
                all_malwares.append(malware_malicious_activity)
                self.all_labels.append(tag)

            else:
                # Create white label otherwise
                self._create_custom_label(f"{tag}", "#ffffff")

        return self.all_labels, all_malwares

    def _create_custom_label(self, name_label: str, color_label: str):
        """
        This method allows you to create a custom label, using the OpenCTI API.

        :param name_label: A parameter giving the name of the label.
        :param color_label: A parameter giving the color of the label.
        """

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
            self.all_labels.append(new_custom_label["value"])

    @staticmethod
    def _get_match(data, key, value):
        return next((x for x in data if x[key] == value), None)

    @staticmethod
    def _generate_stix_relationship(
        source_ref: str,
        stix_core_relationship_type: str,
        target_ref: str,
        created_by_ref: str,
        start_time: str | None = None,
        stop_time: str | None = None,
    ) -> dict:
        """
        This method allows you to create a relationship in Stix2 format.

        :param source_ref: This parameter is the "from" of the relationship.
        :param stix_core_relationship_type: Parameter,
        :param target_ref: This parameter is the "to" of the relationship.
        :param created_by_ref: This parameter is the id of the creator.
        :param start_time: This parameter is the start of the relationship. Value not required, None by default.
        :param stop_time: This parameter is the stop of the relationship. Value not required, None by default.
        :return: A dict
        """

        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            start_time=start_time,
            stop_time=stop_time,
            target_ref=target_ref,
            created_by_ref=created_by_ref,
        )

    def run(self):
        self.helper.log_info("GreyNoise feed dataset...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run) > ((int(self.interval) - 1) * 60 * 60 * 24)
                ):
                    # Initiate the run
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "GreyNoise Feed connector run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        # Requesting data over GreyNoise
                        ip_list = []
                        session = GreyNoise(
                            api_key=self.api_key, integration_name="opencti-feed-v2.2"
                        )

                        self.helper.log_info("GreyNoise Feed Type - Indicator Feed")
                        query = self.get_feed_query(self.feed_type)
                        self.helper.log_info("Query GreyNoise API - First Results Page")
                        response = session.query(query=query, exclude_raw=True)
                        complete = response.get("complete", True)
                        scroll = response.get("scroll", "")

                        for item in response["data"]:
                            ip_list.append(item)
                        self.helper.log_info(
                            "GreyNoise Indicator Count: " + str(len(ip_list))
                        )
                        if len(ip_list) >= self.limit:
                            complete = True
                            self.helper.log_info("GreyNoise Indicator Limit Reached")
                        # get additional indicators
                        while not complete:
                            self.helper.log_info(
                                "Query GreyNoise API - Next Results Page"
                            )
                            response = session.query(
                                query=query, scroll=scroll, exclude_raw=True
                            )
                            complete = response.get("complete", True)
                            scroll = response.get("scroll", "")

                            for item in response["data"]:
                                ip_list.append(item)
                            self.helper.log_info(
                                "GreyNoise Indicator Count: " + str(len(ip_list))
                            )
                            if len(ip_list) >= self.limit:
                                self.helper.log_info(
                                    "GreyNoise Indicator Limit Reached"
                                )
                                complete = True

                        self.helper.log_info("Query GreyNoise API - Completed")

                        # preparing the bundle to be sent to OpenCTI worker

                        bundle_objects = []
                        json_data_tags = session.metadata()

                        self.helper.log_info("Building Indicator Bundles")
                        for d in ip_list[: self.limit]:
                            description = (
                                f"Internet Scanning IP detected by GreyNoise with "
                                f"classification {d.get('classification', '')}"
                            )
                            pattern = "[ipv4-addr:value = '" + d.get("ip", "") + "']"
                            if "metadata" in d:
                                ref_description = (
                                    f'[{d["metadata"].get("country_code", "")}] '
                                    f'- {d["metadata"].get("city", "")}'
                                )
                            else:
                                ref_description = (
                                    " Link to indicator in GreyNoise Visualizer"
                                )

                            labels, malwares = self._process_labels(d, json_data_tags)
                            first_seen = parse(d["first_seen"]).strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            )
                            if d["first_seen"] == d["last_seen"]:
                                last_seen = datetime.strptime(
                                    d["last_seen"], "%Y-%m-%d"
                                ) + timedelta(hours=23)
                                last_seen = last_seen.strftime("%Y-%m-%dT%H:%M:%SZ")
                            else:
                                last_seen = parse(d["last_seen"]).strftime(
                                    "%Y-%m-%dT%H:%M:%SZ"
                                )

                            # Generate ExternalReference
                            external_reference = stix2.ExternalReference(
                                source_name=self.greynoise_ent_name,
                                url="https://viz.greynoise.io/ip/" + d.get("ip", ""),
                                external_id=d.get("ip", ""),
                                description=ref_description,
                            )
                            stix_indicator = stix2.Indicator(
                                id=Indicator.generate_id(pattern),
                                name=d["ip"],
                                description=description,
                                created_by_ref=self.identity["standard_id"],
                                pattern_type="stix",
                                pattern=pattern,
                                external_references=[external_reference],
                                object_marking_refs=[stix2.TLP_WHITE],
                                labels=labels,
                                custom_properties={
                                    "x_opencti_score": self.indicator_score,
                                    "x_opencti_main_observable_type": "IPv4-Addr",
                                },
                            )
                            stix_observable = stix2.IPv4Address(
                                type="ipv4-addr",
                                spec_version="2.1",
                                value=d["ip"],
                                object_marking_refs=[stix2.TLP_WHITE],
                                custom_properties={
                                    "x_opencti_description": description,
                                    "x_opencti_score": self.indicator_score,
                                    "created_by_ref": self.identity["standard_id"],
                                    "labels": labels,
                                    "external_references": [external_reference],
                                },
                            )
                            # Adding the IP to the list
                            stix_relationship = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "based-on", stix_indicator.id, stix_observable.id
                                ),
                                relationship_type="based-on",
                                source_ref=stix_indicator.id,
                                target_ref=stix_observable.id,
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            for malware in malwares:
                                stix_malware = stix2.Malware(
                                    id=Malware.generate_id(malware["name"]),
                                    created_by_ref=self.identity["standard_id"],
                                    name=malware["name"],
                                    description=malware["description"],
                                    is_family=False,
                                    malware_types=malware["type"]
                                    if malware["type"] == "worm"
                                    else None,
                                    created=first_seen,
                                )
                                bundle_objects.append(stix_malware)

                                # Generate Relationship : observable -> "related-to" -> malware
                                self.helper.log_info(f"ip: {d['ip']}")
                                self.helper.log_info(
                                    f"first_seen: {first_seen} - last_seen: {last_seen}"
                                )
                                observable_to_malware = (
                                    self._generate_stix_relationship(
                                        Indicator.generate_id(pattern),
                                        "related-to",
                                        stix_malware.id,
                                        self.identity["standard_id"],
                                        first_seen,
                                        last_seen,
                                    )
                                )
                                bundle_objects.append(observable_to_malware)
                            if "cves" in d and d["cves"]:
                                for cve in d["cves"]:
                                    # Generate Vulnerability
                                    stix_vulnerability = stix2.Vulnerability(
                                        id=Vulnerability.generate_id(cve),
                                        name=cve,
                                        created_by_ref=self.identity["standard_id"],
                                        allow_custom=True,
                                    )
                                    bundle_objects.append(stix_vulnerability)

                                    # Generate Relationship : observable -> "related-to" -> vulnerability
                                    observable_to_vulnerability = stix2.Relationship(
                                        id=StixCoreRelationship.generate_id(
                                            "related-to",
                                            stix_observable.id,
                                            stix_vulnerability.id,
                                        ),
                                        relationship_type="related-to",
                                        source_ref=stix_observable.id,
                                        target_ref=stix_vulnerability.id,
                                        object_marking_refs=[stix2.TLP_WHITE],
                                    )
                                    bundle_objects.append(observable_to_vulnerability)
                            if "cve" in d and d["cve"]:
                                for cve in d["cve"]:
                                    # Generate Vulnerability
                                    stix_vulnerability = stix2.Vulnerability(
                                        id=Vulnerability.generate_id(cve),
                                        name=cve,
                                        created_by_ref=self.identity["standard_id"],
                                        allow_custom=True,
                                    )
                                    bundle_objects.append(stix_vulnerability)
                                    # Generate Relationship : observable -> "related-to" -> vulnerability
                                    observable_to_vulnerability = stix2.Relationship(
                                        id=StixCoreRelationship.generate_id(
                                            "related-to",
                                            stix_observable.id,
                                            stix_vulnerability.id,
                                        ),
                                        relationship_type="related-to",
                                        source_ref=stix_observable.id,
                                        target_ref=stix_vulnerability.id,
                                        object_marking_refs=[stix2.TLP_WHITE],
                                    )
                                    bundle_objects.append(observable_to_vulnerability)
                            bundle_objects.append(stix_indicator)
                            bundle_objects.append(stix_observable)
                            bundle_objects.append(stix_relationship)
                        # Creating the bundle from the list
                        bundle = self.helper.stix2_create_bundle(bundle_objects)
                        # Sending the bundle
                        self.helper.send_stix2_bundle(
                            bundle,
                            work_id=work_id,
                        )

                        # Store the current timestamp as a last run
                        message = (
                            "Connector successfully run, storing last_run as "
                            + str(timestamp)
                        )
                        self.helper.log_info(message)
                        self.helper.set_state({"last_run": timestamp})
                        self.helper.api.work.to_processed(work_id, message)
                        self.helper.log_info(
                            "Last_run stored, next run in: "
                            + str(round(self.get_interval() / 60 / 60 / 24, 2))
                            + " days"
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))

                    time.sleep(60)
                else:
                    # wait for next run
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = GreyNoiseFeed()
        connector.run()
    except:
        time.sleep(10)
        exit(0)
