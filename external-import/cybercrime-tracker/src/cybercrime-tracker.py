import datetime
import os
import sys
import time
import traceback
from urllib.parse import quote, urlparse

import feedparser
import stix2
import yaml
from pycti import (
    Identity,
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from pygrok import Grok
from stix2 import URL, DomainName, IPv4Address


class Cybercrimetracker:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = "{}/config.yml".format(
            os.path.dirname(os.path.abspath(__file__))
        )
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Connector Config
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            isNumber=True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        # CYBERCRIME-TRACKER.NET Config
        self.feed_url = get_config_variable(
            "CYBERCRIME_TRACKER_FEED_URL", ["cybercrime-tracker", "feed_url"], config
        )
        self.connector_tlp = get_config_variable(
            "CYBERCRIME_TRACKER_TLP", ["cybercrime-tracker", "tlp"], config
        )
        if self.connector_tlp == "WHITE":
            self.connector_tlp = "CLEAR"
        self.create_indicators = get_config_variable(
            "CYBERCRIME_TRACKER_CREATE_INDICATORS",
            ["cybercrime-tracker", "create_indicators"],
            config,
        )
        self.create_observables = get_config_variable(
            "CYBERCRIME_TRACKER_CREATE_OBSERVABLES",
            ["cybercrime-tracker", "create_observables"],
            config,
        )
        self.interval = get_config_variable(
            "CYBERCRIME_TRACKER_INTERVAL",
            ["cybercrime-tracker", "interval"],
            config,
            isNumber=True,
        )

    @staticmethod
    def _time_to_datetime(input_date: time) -> datetime.datetime:
        return datetime.datetime(
            input_date.tm_year,
            input_date.tm_mon,
            input_date.tm_mday,
            input_date.tm_hour,
            input_date.tm_min,
            input_date.tm_sec,
            tzinfo=datetime.timezone.utc,
        )

    def parse_feed_entry(self, entry):
        """
        Parses an entry from the feed and returns a dict with:

        date: date in iso format
        type: name of the malware associated with the C2 server
        url: the url of the C2
        ip: the IP address of the C2
        ext_link: An external link to CYBERCRIME-TRACKER.NET with details

        Note: CYBERCRIME-TRACKER.NET does not provide the protocol in the url
        as such we always assume 'http'.
        """
        parsed_entry = {}

        pattern = (
            r"(?:\[%{GREEDYDATA:cwhqid}\]\s+Type:\s+%{GREEDYDATA:type}"
            + r"\s+-%{GREEDYDATA}:\s+%{IP:ip}|"
            + r"\[%{GREEDYDATA:cwhqid}\]\s+Type:\s+%{GREEDYDATA:type})"
        )

        entry_summary = Grok(pattern).match(entry["summary"])

        if entry_summary:
            parsed_entry["date"] = self._time_to_datetime(entry["published_parsed"])
            parsed_entry["type"] = entry_summary["type"]
            parsed_entry["ext_link"] = entry["link"]
            parsed_entry["url"] = "http://{}".format(quote(entry["title"]))
            hostname = urlparse(parsed_entry["url"]).hostname

            if entry_summary["ip"] is None:
                parsed_entry["ip"] = hostname
            else:
                parsed_entry["ip"] = entry_summary["ip"]
                parsed_entry["domain"] = hostname

            self.helper.log_info("Parsed entry: {}".format(entry["title"]))

            return parsed_entry
        else:
            self.helper.log_error("Could not parse: {}".format(entry["title"]))
            return False

    def gen_indicator_pattern(self, parsed_entry):
        if "domain" in parsed_entry.keys():
            indicator_pattern = (
                "[ipv4-addr:value='{}'] ".format(parsed_entry["ip"])
                + "AND [url:value='{}'] ".format(parsed_entry["url"])
                + "AND [domain-name:value='{}']".format(parsed_entry["domain"])
            )
        else:
            indicator_pattern = "[ipv4-addr:value='{}'] ".format(
                parsed_entry["ip"]
            ) + "AND [url:value='{}']".format(parsed_entry["url"])

        return indicator_pattern

    def run(self):
        self.helper.log_info("Fetching data CYBERCRIME-TRACKER.NET...")
        tlp = self.helper.api.marking_definition.read(
            filters=[
                {"key": "definition", "values": "TLP:{}".format(self.connector_tlp)}
            ]
        )
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()

                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: {}".format(
                            datetime.datetime.utcfromtimestamp(last_run).strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")

                # Run if it is the first time or we are past the interval

                if last_run is None or ((timestamp - last_run) > self.interval):
                    self.helper.log_info("Connector will run!")
                    now = datetime.datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Cybercrime-Tracker run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        self.helper.log_info("Parsing feed on " + self.feed_url)
                        # Get Feed Content
                        feed = feedparser.parse(self.feed_url)
                        self.helper.log_info(
                            "Found: {} entries.".format(len(feed["entries"]))
                        )
                        self.feed_summary = {
                            "Source": feed["feed"]["title"],
                            "Date": self._time_to_datetime(
                                feed["feed"]["published_parsed"]
                            ),
                            "Details": feed["feed"]["subtitle"],
                            "Link": feed["feed"]["link"],
                        }

                        # Create the bundle
                        bundle_objects = list()
                        identity_name = "CYBERCRIME-TRACKER.NET"
                        organization = stix2.Identity(
                            id=Identity.generate_id(identity_name, "organization"),
                            name=identity_name,
                            identity_class="organization",
                            description="Tracker collecting and sharing daily updates of C2 IPs/Urls. http://cybercrime-tracker.net",
                        )
                        bundle_objects.append(organization)
                        for entry in feed["entries"]:
                            parsed_entry = self.parse_feed_entry(entry)
                            external_reference = stix2.ExternalReference(
                                source_name="{}".format(self.feed_summary["Source"]),
                                url=parsed_entry["ext_link"],
                            )
                            indicator_pattern = self.gen_indicator_pattern(parsed_entry)
                            malware = stix2.Malware(
                                id=Malware.generate_id(parsed_entry["type"]),
                                is_family=True,
                                name=parsed_entry["type"],
                                description="{} malware.".format(parsed_entry["type"]),
                            )
                            bundle_objects.append(malware)
                            indicator = None
                            if self.create_indicators:
                                indicator = stix2.Indicator(
                                    id=Indicator.generate_id(indicator_pattern),
                                    name=parsed_entry["url"],
                                    description="C2 URL for: {}".format(
                                        parsed_entry["type"]
                                    ),
                                    labels=["C2 Server"],
                                    pattern_type="stix",
                                    pattern=indicator_pattern,
                                    valid_from=parsed_entry["date"],
                                    created=parsed_entry["date"],
                                    modified=parsed_entry["date"],
                                    created_by_ref=organization.id,
                                    object_marking_refs=[tlp["standard_id"]],
                                    external_references=[external_reference],
                                    custom_properties={
                                        "x_opencti_main_observable_type": "Url"
                                    },
                                )
                                bundle_objects.append(indicator)
                                relation = stix2.Relationship(
                                    id=StixCoreRelationship.generate_id(
                                        "indicates",
                                        indicator.id,
                                        malware.id,
                                        self._time_to_datetime(
                                            entry["published_parsed"]
                                        ),
                                        self._time_to_datetime(
                                            entry["published_parsed"]
                                        ),
                                    ),
                                    source_ref=indicator.id,
                                    target_ref=malware.id,
                                    relationship_type="indicates",
                                    start_time=self._time_to_datetime(
                                        entry["published_parsed"]
                                    ),
                                    stop_time=self._time_to_datetime(
                                        entry["published_parsed"]
                                    )
                                    + datetime.timedelta(0, 3),
                                    description="URLs associated to: "
                                    + parsed_entry["type"],
                                    confidence=self.confidence_level,
                                    created_by_ref=organization.id,
                                    object_marking_refs=[tlp["standard_id"]],
                                    created=parsed_entry["date"],
                                    modified=parsed_entry["date"],
                                    external_references=[external_reference],
                                    allow_custom=True,
                                )
                                bundle_objects.append(relation)
                            if self.create_observables:
                                observable_url = URL(
                                    value=parsed_entry["url"],
                                    object_marking_refs=[tlp["standard_id"]],
                                    custom_properties={
                                        "labels": ["C2 Server"],
                                        "created_by_ref": organization.id,
                                        "external_references": [external_reference],
                                    },
                                )
                                bundle_objects.append(observable_url)
                                observable_ip = IPv4Address(
                                    value=parsed_entry["ip"],
                                    object_marking_refs=[tlp["standard_id"]],
                                    custom_properties={
                                        "labels": ["C2 Server"],
                                        "created_by_ref": organization.id,
                                        "external_references": [external_reference],
                                    },
                                )
                                bundle_objects.append(observable_ip)
                                observable_domain = None
                                if "domain" in parsed_entry.keys():
                                    observable_domain = DomainName(
                                        value=parsed_entry["domain"],
                                        object_marking_refs=[tlp["standard_id"]],
                                        custom_properties={
                                            "labels": ["C2 Server"],
                                            "created_by_ref": organization.id,
                                            "external_references": [external_reference],
                                        },
                                    )
                                    bundle_objects.append(observable_domain)

                                if indicator is not None:
                                    relationship_1 = stix2.Relationship(
                                        id=StixCoreRelationship.generate_id(
                                            "based-on", indicator.id, observable_url.id
                                        ),
                                        relationship_type="based-on",
                                        created_by_ref=organization.id,
                                        source_ref=indicator.id,
                                        target_ref=observable_url.id,
                                        allow_custom=True,
                                    )
                                    bundle_objects.append(relationship_1)
                                    relationship_2 = stix2.Relationship(
                                        id=StixCoreRelationship.generate_id(
                                            "based-on", indicator.id, observable_ip.id
                                        ),
                                        relationship_type="based-on",
                                        created_by_ref=organization.id,
                                        source_ref=indicator.id,
                                        target_ref=observable_ip.id,
                                        allow_custom=True,
                                    )
                                    bundle_objects.append(relationship_2)
                                    if observable_domain is not None:
                                        relationship_3 = stix2.Relationship(
                                            id=StixCoreRelationship.generate_id(
                                                "based-on",
                                                indicator.id,
                                                observable_domain.id,
                                            ),
                                            relationship_type="based-on",
                                            created_by_ref=organization.id,
                                            source_ref=indicator.id,
                                            target_ref=observable_domain.id,
                                            allow_custom=True,
                                        )
                                        bundle_objects.append(relationship_3)

                        # create stix bundle
                        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
                        # send data
                        self.helper.send_stix2_bundle(
                            bundle=bundle.serialize(),
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                    except Exception:
                        self.helper.log_error(traceback.format_exc())

                    # Store the current timestamp as a last run
                    message = (
                        "Connector successfully run,  storing last_run as: {}".format(
                            str(timestamp)
                        )
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: {} seconds.".format(
                            str(round(self.interval, 2))
                        )
                    )
                else:
                    new_interval = self.interval - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run. \
                            Next run in: {} seconds.".format(
                            str(round(new_interval, 2))
                        )
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)

            except Exception:
                self.helper.log_error(traceback.format_exc())

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)

            time.sleep(60)


if __name__ == "__main__":
    try:
        cybercrimetrackerConnector = Cybercrimetracker()
        cybercrimetrackerConnector.run()
    except Exception:
        print(traceback.format_exc())
        time.sleep(10)
        sys.exit(0)
