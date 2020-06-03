import os
import yaml
import time
import feedparser

from pycti import OpenCTIConnectorHelper, get_config_variable
from pygrok import Grok
from datetime import datetime, timezone
from urllib.parse import urlparse, quote


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
        self.update_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        # CYBERCRIME-TRACKER.NET Config
        self.feed_url = get_config_variable(
            "CYBERCRIMET_RACKER_FEED_URL", ["cybercrime-tracker", "feed_url"], config,
        )
        self.connector_tlp = get_config_variable(
            "CYBERCRIME_TRACKER_TLP", ["cybercrime-tracker", "tlp"], config,
        )
        self.interval = get_config_variable(
            "CYBERCRIMETRACKER_INTERVAL",
            ["cybercrime-tracker", "interval"],
            config,
            isNumber=True,
        )

    @staticmethod
    def _time_to_datetime(input_date: time) -> datetime:
        return datetime(
            input_date.tm_year,
            input_date.tm_mon,
            input_date.tm_mday,
            input_date.tm_hour,
            input_date.tm_min,
            input_date.tm_sec,
            tzinfo=timezone.utc,
        ).isoformat()

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
                + "AND [domain:value='{}']".format(parsed_entry["domain"])
            )
        else:
            indicator_pattern = "[ipv4-addr:value='{}'] ".format(
                parsed_entry["ip"]
            ) + "AND [url:value='{}']".format(parsed_entry["url"])

        return indicator_pattern

    def run(self):

        self.helper.log_info("Fetching data CYBERCRIME-TRACKER.NET...")

        tag = self.helper.api.tag.create(
            tag_type="C2-Type", value="C2 Server", color="#fc236b",
        )
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
                            datetime.utcfromtimestamp(last_run).strftime(
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

                    # Create entity for the feed.
                    organization = self.helper.api.identity.create(
                        type="Organization",
                        name="CYBERCRIME-TRACKER.NET",
                        description="Tracker collecting and sharing \
                            daily updates of C2 IPs/Urls. \
                            http://cybercrime-tracker.net",
                    )

                    for entry in feed["entries"]:

                        parsed_entry = self.parse_feed_entry(entry)

                        ext_reference = self.helper.api.external_reference.create(
                            source_name="{}".format(self.feed_summary["Source"],),
                            url=parsed_entry["ext_link"],
                        )

                        indicator_pattern = self.gen_indicator_pattern(parsed_entry)

                        # Add malware related to indicator
                        malware = self.helper.api.malware.create(
                            name=parsed_entry["type"],
                            description="{} malware.".format(parsed_entry["type"]),
                        )

                        # Add indicator
                        indicator = self.helper.api.indicator.create(
                            name=parsed_entry["url"],
                            description="C2 URL for: {}".format(parsed_entry["type"]),
                            pattern_type="stix",
                            indicator_pattern=indicator_pattern,
                            main_observable_type="URL",
                            valid_from=parsed_entry["date"],
                            created=parsed_entry["date"],
                            modified=parsed_entry["date"],
                            createdByRef=organization["id"],
                            markingDefinitions=[tlp["id"]],
                            update=self.update_data,
                        )

                        # Add tag
                        self.helper.api.stix_entity.add_tag(
                            id=indicator["id"], tag_id=tag["id"],
                        )

                        self.helper.api.stix_entity.add_external_reference(
                            id=indicator["id"],
                            external_reference_id=ext_reference["id"],
                        )

                        # Add relationship with malware
                        relation = self.helper.api.stix_relation.create(
                            fromType="Indicator",
                            fromId=indicator["id"],
                            toType="Malware",
                            toId=malware["id"],
                            relationship_type="indicates",
                            first_seen=self._time_to_datetime(
                                entry["published_parsed"]
                            ),
                            last_seen=self._time_to_datetime(entry["published_parsed"]),
                            description="URLs associated to: " + parsed_entry["type"],
                            weight=self.confidence_level,
                            role_played="C2 Server",
                            createdByRef=organization["id"],
                            created=parsed_entry["date"],
                            modified=parsed_entry["date"],
                            update=self.update_data,
                        )

                        self.helper.api.stix_entity.add_external_reference(
                            id=relation["id"],
                            external_reference_id=ext_reference["id"],
                        )

                        # Create Observables and link them to Indicator
                        observable_url = self.helper.api.stix_observable.create(
                            type="URL",
                            observable_value=parsed_entry["url"],
                            createdByRef=organization["id"],
                            markingDefinitions=[tlp["id"]],
                            update=self.update_data,
                        )

                        self.helper.api.stix_entity.add_external_reference(
                            id=observable_url["id"],
                            external_reference_id=ext_reference["id"],
                        )

                        self.helper.api.indicator.add_stix_observable(
                            id=indicator["id"], stix_observable_id=observable_url["id"],
                        )

                        observable_ip = self.helper.api.stix_observable.create(
                            type="IPv4-Addr",
                            observable_value=parsed_entry["ip"],
                            createdByRef=organization["id"],
                            markingDefinitions=[tlp["id"]],
                            update=self.update_data,
                        )

                        self.helper.api.stix_entity.add_external_reference(
                            id=observable_ip["id"],
                            external_reference_id=ext_reference["id"],
                        )

                        self.helper.api.indicator.add_stix_observable(
                            id=indicator["id"], stix_observable_id=observable_ip["id"],
                        )

                        if "domain" in parsed_entry.keys():
                            observable_domain = self.helper.api.stix_observable.create(
                                type="Domain",
                                observable_value=parsed_entry["domain"],
                                createdByRef=organization["id"],
                                markingDefinitions=[tlp["id"]],
                                update=self.update_data,
                            )

                            self.helper.api.stix_entity.add_external_reference(
                                id=observable_domain["id"],
                                external_reference_id=ext_reference["id"],
                            )

                            self.helper.api.indicator.add_stix_observable(
                                id=indicator["id"],
                                stix_observable_id=observable_domain["id"],
                            )
                            self.helper.api.stix_relation.create(
                                fromType="Domain",
                                fromId=observable_domain["id"],
                                toType="IPv4-Addr",
                                toId=observable_ip["id"],
                                relationship_type="resolves",
                                last_seen=self._time_to_datetime(
                                    entry["published_parsed"]
                                ),
                                weight=self.confidence_level,
                                createdByRef=organization["id"],
                                created=parsed_entry["date"],
                                modified=parsed_entry["date"],
                                update=self.update_data,
                            )

                    # Store the current timestamp as a last run
                    self.helper.log_info(
                        "Connector successfully run, \
                            storing last_run as: {}".format(
                            str(timestamp)
                        )
                    )
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.log_info(
                        "Last_run stored, next run in: {} seconds.".format(
                            str(round(self.interval, 2))
                        )
                    )

                    new_state = {"last_run": int(time.time())}
                    self.helper.set_state(new_state)
                    time.sleep(60)
                else:
                    new_interval = self.interval - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run. \
                            Next run in: {} seconds.".format(
                            str(round(new_interval, 2))
                        )
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
        cybercrimetrackerConnector = Cybercrimetracker()
        cybercrimetrackerConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
