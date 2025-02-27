import os
import time
from datetime import datetime, timedelta
from random import shuffle

import pytz
import stix2
import yaml
from dateutil.parser import parse
from greynoise import GreyNoise
from pycti import (
    Identity,
    Indicator,
    Location,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    StixSightingRelationship,
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
        self.indicator_score_malicious = get_config_variable(
            "GREYNOISE_INDICATOR_SCORE_MALICIOUS",
            ["greynoisefeed", "indicator_score_malicious"],
            config,
            isNumber=True,
            default=75,
        )
        self.indicator_score_benign = get_config_variable(
            "GREYNOISE_INDICATOR_SCORE_BENIGN",
            ["greynoisefeed", "indicator_score_benign"],
            config,
            isNumber=True,
            default=20,
        )
        self.greynoise_ent_name = get_config_variable(
            "GREYNOISE_NAME",
            ["greynoisefeed", "name"],
            config,
            default="GreyNoise Feed",
        )
        self.greynoise_ent_desc = get_config_variable(
            "GREYNOISE_DESCRIPTION",
            ["greynoisefeed", "description"],
            config,
            default="GreyNoise collects and analyzes untargeted, widespread, and opportunistic scan and attack activity that reaches every server directly connected to the Internet.",
        )
        self.greynoise_limit = get_config_variable(
            "GREYNOISE_LIMIT",
            ["greynoisefeed", "limit"],
            config,
            isNumber=True,
            default=10000,
        )
        self.greynoise_import_meta_data = get_config_variable(
            "GREYNOISE_IMPORT_METADATA",
            ["greynoisefeed", "import_metadata"],
            config,
            default=False,
        )
        self.greynoise_interval = get_config_variable(
            "GREYNOISE_INTERVAL",
            ["greynoisefeed", "interval"],
            config,
            isNumber=True,
            default=24,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name=self.greynoise_ent_name,
            description=self.greynoise_ent_desc,
        )

        # Cache for label
        self.labels_cache = {}

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

    def _process_data(self, work_id, session, ips_list):
        bundle_entities = []
        bundle_relationships = []
        json_data_tags = session.metadata()
        self.helper.log_info("Building Indicator Bundles")
        for ip in ips_list:
            if "ip" not in ip or "classification" not in ip:
                continue

            description = (
                "Internet Scanning IP detected by GreyNoise with classification `"
                + ip["classification"]
                + "`."
            )
            pattern = "[ipv4-addr:value = '" + ip["ip"] + "']"

            labels, malwares = self._process_labels(ip, json_data_tags)

            first_seen = parse(ip["first_seen"]).strftime("%Y-%m-%dT%H:%M:%SZ")
            if ip["first_seen"] == ip["last_seen"]:
                last_seen = datetime.strptime(ip["last_seen"], "%Y-%m-%d") + timedelta(
                    hours=23
                )
                last_seen = last_seen.strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                last_seen = parse(ip["last_seen"]).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Generate ExternalReference
            external_reference = stix2.ExternalReference(
                source_name=self.greynoise_ent_name,
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
                        self.indicator_score_malicious
                        if ip["classification"] == "malicious"
                        else self.indicator_score_benign
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
                        self.indicator_score_malicious
                        if ip["classification"] == "malicious"
                        else self.indicator_score_benign
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

            # Malwares
            stix_malwares = []
            for malware in malwares:
                stix_malware = stix2.Malware(
                    id=Malware.generate_id(malware["name"]),
                    name=malware["name"],
                    description=malware["description"],
                    is_family=False,
                    malware_types=(
                        malware["type"] if malware["type"] == "worm" else None
                    ),
                    created=first_seen,
                    created_by_ref=self.identity["standard_id"],
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                stix_malwares.append(stix_malware)
                bundle_entities.append(stix_malware)

                stix_relationship_observable_malware = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", stix_observable.id, stix_malware.id
                    ),
                    relationship_type="related-to",
                    source_ref=stix_observable.id,
                    target_ref=stix_malware.id,
                    created_by_ref=self.identity["standard_id"],
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                bundle_relationships.append(stix_relationship_observable_malware)

                stix_relationship_indicator_malware = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates", stix_indicator.id, stix_malware.id
                    ),
                    relationship_type="indicates",
                    source_ref=stix_indicator.id,
                    target_ref=stix_malware.id,
                    created_by_ref=self.identity["standard_id"],
                    object_marking_refs=[stix2.TLP_WHITE],
                )
                bundle_relationships.append(stix_relationship_indicator_malware)

            # CVE
            if "cve" in ip and ip["cve"]:
                for cve in ip["cve"]:
                    stix_vulnerability = stix2.Vulnerability(
                        id=Vulnerability.generate_id(cve),
                        name=cve,
                        created_by_ref=self.identity["standard_id"],
                        object_marking_refs=[stix2.TLP_WHITE],
                    )
                    bundle_entities.append(stix_vulnerability)

                    stix_relationship_observable_vulnerability = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to",
                            stix_observable.id,
                            stix_vulnerability.id,
                        ),
                        relationship_type="related-to",
                        source_ref=stix_observable.id,
                        target_ref=stix_vulnerability.id,
                        created_by_ref=self.identity["standard_id"],
                        object_marking_refs=[stix2.TLP_WHITE],
                    )
                    bundle_relationships.append(
                        stix_relationship_observable_vulnerability
                    )

            # Metadata
            if self.greynoise_import_meta_data:
                if "metadata" in ip:
                    metadata = ip["metadata"]
                    stix_as = None
                    if "asn" in metadata:
                        try:
                            stix_as = stix2.AutonomousSystem(
                                name=metadata["asn"],
                                number=int(metadata["asn"].replace("AS", "")),
                                object_marking_refs=[stix2.TLP_WHITE],
                                custom_properties={
                                    "created_by_ref": self.identity["standard_id"],
                                },
                            )
                            bundle_entities.append(stix_as)

                            stix_relationship_observable_as = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "belongs-to", stix_observable.id, stix_as.id
                                ),
                                relationship_type="belongs-to",
                                source_ref=stix_observable.id,
                                target_ref=stix_as.id,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            bundle_relationships.append(stix_relationship_observable_as)
                        except:
                            pass
                    if "organization" in metadata:
                        stix_organization = stix2.Identity(
                            id=Identity.generate_id(
                                metadata["organization"], "organization"
                            ),
                            name=metadata["organization"],
                            identity_class="organization",
                        )
                        bundle_entities.append(stix_organization)

                        stix_relationship_observable_organization = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "belongs-to", stix_observable.id, stix_organization.id
                            ),
                            relationship_type="belongs-to",
                            source_ref=stix_observable.id,
                            target_ref=stix_organization.id,
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[stix2.TLP_WHITE],
                        )
                        bundle_relationships.append(
                            stix_relationship_observable_organization
                        )

                        if stix_as is not None:
                            stix_relationship_as_organization = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "related-to", stix_as.id, stix_organization.id
                                ),
                                relationship_type="related-to",
                                source_ref=stix_as.id,
                                target_ref=stix_organization.id,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            bundle_relationships.append(
                                stix_relationship_as_organization
                            )
                    stix_city = None
                    if "city" in metadata:
                        stix_city = stix2.Location(
                            id=Location.generate_id(metadata["city"], "City"),
                            name=metadata["city"],
                            country="N/A",
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={"x_opencti_location_type": "City"},
                        )
                        bundle_entities.append(stix_city)

                        stix_relationship_observable_city = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "located-at", stix_observable.id, stix_city.id
                            ),
                            relationship_type="located-at",
                            source_ref=stix_observable.id,
                            target_ref=stix_city.id,
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[stix2.TLP_WHITE],
                        )
                        bundle_relationships.append(stix_relationship_observable_city)

                    if "country" in metadata:
                        stix_country = stix2.Location(
                            id=Location.generate_id(metadata["country"], "Country"),
                            name=metadata["country"],
                            country=metadata["country"],
                            created_by_ref=self.identity["standard_id"],
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={"x_opencti_location_type": "Country"},
                        )
                        bundle_entities.append(stix_country)

                        if stix_city is None:
                            stix_relationship_observable_city = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "located-at", stix_observable.id, stix_country.id
                                ),
                                relationship_type="located-at",
                                source_ref=stix_observable.id,
                                target_ref=stix_country.id,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            bundle_relationships.append(
                                stix_relationship_observable_city
                            )
                        else:
                            stix_relationship_city_country = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "located-at", stix_city.id, stix_country.id
                                ),
                                relationship_type="located-at",
                                source_ref=stix_city.id,
                                target_ref=stix_country.id,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_WHITE],
                            )
                            bundle_relationships.append(stix_relationship_city_country)
                    if "destination_countries" in metadata:
                        for country in metadata["destination_countries"]:
                            stix_country_destination = stix2.Location(
                                id=Location.generate_id(country, "Country"),
                                name=country,
                                country=country,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_WHITE],
                                custom_properties={
                                    "x_opencti_location_type": "Country"
                                },
                            )
                            bundle_entities.append(stix_country_destination)

                            stix_sighting_indicator = stix2.Sighting(
                                id=StixSightingRelationship.generate_id(
                                    stix_indicator.id,
                                    stix_country_destination.id,
                                    first_seen,
                                    last_seen,
                                ),
                                sighting_of_ref=stix_indicator.id,
                                where_sighted_refs=[stix_country_destination.id],
                                count=1,
                                first_seen=first_seen,
                                last_seen=last_seen,
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_GREEN],
                            )
                            bundle_relationships.append(stix_sighting_indicator)

                            # stix_sighting_observable = stix2.Sighting(
                            #    id=StixSightingRelationship.generate_id(
                            #        stix_observable.id,
                            #        stix_country_destination.id,
                            #        first_seen,
                            #        last_seen,
                            #    ),
                            #    sighting_of_ref="indicator--7eac24ff-8131-4400-9e56-cc8fe2c65078",  # Fake ID
                            #    where_sighted_refs=[stix_country_destination.id],
                            #    count=1,
                            #    first_seen=first_seen,
                            #    last_seen=last_seen,
                            #    created_by_ref=self.identity["standard_id"],
                            #    object_marking_refs=[stix2.TLP_GREEN],
                            #    custom_properties={
                            #        "x_opencti_sighting_of_ref": stix_observable.id,
                            #    },
                            # )
                            # bundle_objects.append(stix_sighting_observable)

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

    def run(self):
        self.helper.log_info("GreyNoise feed - Initialization...")
        while True:
            self.labels_cache = {}
            try:
                # Get the current timestamp and check
                now = datetime.now(pytz.UTC)
                current_state = self.helper.get_state()
                if current_state is not None and "last_run_timestamp" in current_state:
                    last_run_timestamp = parse(current_state["last_run_timestamp"])

                    pause_run = True

                    while pause_run:
                        self.helper.log_info(
                            "GreyNoise feed - Checking Last Run Interval"
                        )
                        now = datetime.now(pytz.UTC)
                        diff = now - last_run_timestamp
                        days, seconds = diff.days, diff.seconds
                        last_run_hours = days * 24 + seconds // 3600
                        if last_run_hours < self.greynoise_interval:
                            self.helper.log_info(
                                "GreyNoise feed - Last Run Less than Interval - Waiting 60 minutes"
                            )
                            time.sleep(3600)
                        else:
                            pause_run = False
                else:
                    last_run_timestamp = now - timedelta(days=1)

                self.helper.log_info(
                    "Fetching GreyNoise feeds since "
                    + last_run_timestamp.astimezone(pytz.UTC).isoformat()
                )
                try:
                    ips_list = []
                    session = GreyNoise(
                        api_key=self.api_key, integration_name="opencti-feed-v2.4"
                    )

                    query = self.get_feed_query(self.feed_type)
                    self.helper.log_info(
                        "Querying GreyNoise API - First Results Page (" + query + ")"
                    )
                    response = session.query(query=query, exclude_raw=True)
                    complete = response.get("complete", True)
                    scroll = response.get("scroll", "")

                    # Process
                    if "data" in response and len(response["data"]) > 0:
                        for ip in response["data"]:
                            ips_list.append(ip)

                    while not complete:
                        self.helper.log_info(
                            "Query GreyNoise API - Next Results Page (" + query + ")"
                        )
                        response = session.query(
                            query=query, scroll=scroll, exclude_raw=True
                        )
                        complete = response.get("complete", True)
                        scroll = response.get("scroll", "")

                        # Process
                        if "data" in response and len(response["data"]) > 0:
                            for ip in response["data"]:
                                ips_list.append(ip)

                            if len(ips_list) > self.greynoise_limit:
                                complete = True

                    self.helper.log_info("Query GreyNoise API - Completed")
                    self.helper.log_info(
                        "GreyNoise Indicator Count: " + str(len(ips_list))
                    )

                    # Process
                    friendly_name = (
                        "GreyNoise Feed connector run ("
                        + str(self.greynoise_limit)
                        + " IPs)"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    self._process_data(work_id, session, ips_list)
                    message = (
                        "Connector successfully run, storing last_run_timestamp as "
                        + now.astimezone(pytz.UTC).isoformat()
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(message)
                    self.helper.set_state(
                        {"last_run_timestamp": now.astimezone(pytz.UTC).isoformat()}
                    )
                except Exception as e:
                    self.helper.log_error(str(e))

                # Wait
                # time.sleep(3600 * self.greynoise_interval)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                exit(0)


if __name__ == "__main__":
    try:
        connector = GreyNoiseFeed()
        connector.run()
    except:
        time.sleep(10)
        exit(0)
