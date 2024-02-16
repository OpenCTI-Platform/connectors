import json
import os
import re
import ssl
import time
import urllib
from datetime import datetime
from greynoise import GreyNoise
from urllib import parse

import certifi
import stix2
import yaml
from pycti import (
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
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
        print('helper')
        self.helper = OpenCTIConnectorHelper(config)
        print('api_key')
        self.api_key = get_config_variable(
            "GREYNOISE_API_KEY", ["greynoisefeed", "api_key"], config
        )
        self.source = get_config_variable(
            "GREYNOISE_SOURCE", ["greynoisefeed", "source"], config
        )
        self.feed_type = get_config_variable(
            "GREYNOISE_FEED_TYPE", ["greynoisefeed", "feed_type"], config, required=True
        )
        self.tag_list = get_config_variable(
            "GREYNOISE_TAG_LIST", ["greynoisefeed", "tag_list"], config
        )
        self.limit = get_config_variable(
            "GREYNOISE_LIMIT", ["greynoisefeed", "limit"], config, True
        )
        self.interval = get_config_variable(
            "GREYNOISE_INTERVAL", ["greynoisefeed", "interval"], config, True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="GreyNoise",
            description="GreyNoise provides IP intelligence information on internet scanners.",
        )

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def get_feed_query(self, feed_type):
        print('get_feed_query')
        query = ""
        if feed_type.lower() not in ['benign', 'malicious', 'all']:
            self.helper.log_error("Value for feed_type is not one of: benign, malicious, or all")
            exit(1)
        elif feed_type.lower() == "benign":
            query = "last_seen:1d classification:benign"
        elif feed_type.lower() == "malicious":
            query = "last_seen:1d classification:malicious"
        elif feed_type.lower() == "all":
            query = "last_seen:1d"

        return query

    def run(self):
        self.helper.log_info("greynoise feed dataset...")
        print('main')
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
                        session = GreyNoise(api_key=self.api_key, integration_name="opencti-feed-v2.0")
                        if self.source == "feed":
                            self.helper.log_info("GreyNoise Feed Type - Indicator Feed")
                            query = self.get_feed_query(self.feed_type)
                            self.helper.log_info("Query GreyNoise API - First Results Page")
                            response = session.query(query=query, exclude_raw=True, size=10)
                            complete = True
                            #complete = response.get("complete", True)
                            scroll = response.get("scroll", "")

                            for item in response["data"]:
                                item_trimmed = {
                                    "ip": item["ip"],
                                    "classification": item["classification"]
                                }
                                ip_list.append(item_trimmed)

                            # get additional indicators
                            while not complete:
                                self.helper.log_info("Query GreyNoise API - Next Results Page")
                                response = session.query(query=query, scroll=scroll, exclude_raw=True)
                                complete = response.get("complete", True)
                                scroll = response.get("scroll", "")

                                for item in response["data"]:
                                    item_trimmed = {
                                        "ip": item["ip"],
                                        "classification": item["classification"]
                                    }
                                    ip_list.append(item_trimmed)
                        elif self.source == "tags":
                            for tag in tag_list:
                                continue
                        else:
                            self.helper.log_error("Value for source is not one of: feed, tag")
                            exit(1)

                        self.helper.log_info("Query GreyNoise API - Completed")

                        # preparing the bundle to be sent to OpenCTI worker
                        external_reference = stix2.ExternalReference(
                            source_name="GreyNoise",
                            url="https://viz.greynoise.io/",
                            description="GreyNoise Visualizer URL",
                        )
                        bundle_objects = []

                        self.helper.log_info("Building Indicator Bundles")
                        for d in ip_list:
                            if self.source == "feed":
                                description = (f"Internet Scanning IP detected by GreyNoise with "
                                               f"classification {d.get('classification', '')}")
                            elif self.source == "tags":
                                description = (f"Internet Scanning IP detected by GreyNoise with "
                                               f"tag name {d.get('tag_name', '')}")
                            else:
                                description = "Internet Scanning IP detected by GreyNoise"
                            pattern = "[ipv4-addr:value = '" + d.get("ip", "") + "']"
                            stix_indicator = stix2.Indicator(
                                id=Indicator.generate_id(pattern),
                                name=d["ip"],
                                description=description,
                                created_by_ref=self.identity["standard_id"],
                                confidence=self.helper.connect_confidence_level,
                                pattern_type="stix",
                                pattern=pattern,
                                external_references=[external_reference],
                                object_marking_refs=[stix2.TLP_WHITE],
                                custom_properties={
                                    "x_opencti_score": "85",
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
                                    "x_opencti_score": "85",
                                    "created_by_ref": self.identity["standard_id"],
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
                            bundle_objects.append(stix_indicator)
                            bundle_objects.append(stix_observable)
                            bundle_objects.append(stix_relationship)
                        # Creating the bundle from the list
                        bundle = stix2.Bundle(bundle_objects, allow_custom=True)
                        bundle_json = bundle.serialize()
                        # Sending the bundle
                        self.helper.send_stix2_bundle(
                            bundle_json,
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))
                    # Store the current timestamp as a last run
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
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
        print('init')
        connector = GreyNoiseFeed()
        print('run')
        connector.run()
    except Exception as e:
#        print('except')
        # print(e)
        time.sleep(10)
        exit(0)
