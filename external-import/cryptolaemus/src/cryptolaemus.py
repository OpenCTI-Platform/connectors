import os
import time
from datetime import datetime

import feedparser
import yaml
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper, get_config_variable


class Cryptolaemus:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.interval = 2  # 2 Days interval between each scraping
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            isNumber=True,
        )
        self.data = {}

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("Fetching Cryptolaemus Emotet's datasets...")
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
                    self.helper.log_info("Connector will run!")

                    ## CORE ##

                    # get feed content
                    feed = feedparser.parse("https://paste.cryptolaemus.com/feed.xml")
                    # variables
                    Epoch1C2 = []  # List of C2 of Epoch1 Botnet
                    Epoch2C2 = []  # List of C2 of Epoch2 Botnet
                    Epoch3C2 = []  # List of C2 of Epoch3 Botnet
                    # We will only extract the last item
                    source = feed["items"][0][
                        "id"
                    ]  # Source of the data (id field in the rss feed)
                    date = feed["items"][0][
                        "updated"
                    ]  # Date of data (updated fild in the rss feed)
                    soup = BeautifulSoup(
                        feed["items"][0]["content"][0]["value"], "lxml"
                    )  # Content (html format) of the rss feed first item
                    # parsing of content's feed (IP:port couples are in HTML <code> with no id an no significant parent node. We get the right content by indicating right <code> in the input array
                    list1 = soup.find_all("code")[0].text.split("\n")
                    list2 = soup.find_all("code")[3].text.split("\n")
                    list3 = soup.find_all("code")[6].text.split("\n")
                    # parsing of the IP:port couples
                    for line in list1:
                        Epoch1C2.append(line.split(":"))
                    for line in list2:
                        Epoch2C2.append(line.split(":"))
                    for line in list3:
                        Epoch3C2.append(line.split(":"))
                    # Agregate
                    self.data = {
                        "Source": source,
                        "Date": date,
                        "Epoch1C2": Epoch1C2,
                        "Epoch2C2": Epoch2C2,
                        "Epoch3C2": Epoch3C2,
                    }

                    # Capitalize Cryptolaemus
                    organization = self.helper.api.identity.create(
                        type="Organization",
                        name="Cryptolaemus Team",
                        description="Team of Experts collecting and sharing daily update of C2 IP of Emotet's Epochs Botnets.",
                    )
                    external_reference = self.helper.api.external_reference.create(
                        source_name="Cryptolaemus Team's Emotet C2 update of "
                        + self.data["Date"],
                        url=self.data["Source"],
                    )
                    malware = self.helper.api.malware.create(
                        name="Emotet",
                        description="Emotet is a modular malware variant which is primarily used as a downloader for other malware variants such as TrickBot and IcedID. Emotet first emerged in June 2014 and has been primarily used to target the banking sector. (Citation: Trend Micro Banking Malware Jan 2019)",
                    )
                    # Capitalize Epoch1 C2
                    for ip in self.data["Epoch1C2"]:
                        if len(ip) >= 2 and ip[0][0].isdigit():
                            indicator = self.helper.api.indicator.create(
                                name=ip[0],
                                description="Botnet Epoch1 C2 IP Adress. Port: "
                                + ip[1],
                                pattern_type="stix",
                                pattern="[ipv4-addr:value = '" + ip[0] + "']",
                                x_opencti_main_observable_type="IPv4-Addr",
                                valid_from=self.data["Date"],
                                externalReferences=[external_reference["id"]],
                                createdBy=organization["id"],
                            )
                            observable = self.helper.api.stix_cyber_observable.create(
                                simple_observable_key="IPv4-Addr.value",
                                simple_observable_value=ip[0],
                                simple_observable_description="Botnet Epoch1 C2 IP Adress. Port: "
                                + ip[1],
                                externalReferences=[external_reference["id"]],
                                createdBy=organization["id"],
                            )
                            self.helper.api.stix_core_relationship.create(
                                fromId=indicator["id"],
                                toId=observable["id"],
                                relationship_type="based-on",
                                createdBy=organization["id"],
                            )
                            self.helper.api.stix_core_relationship.create(
                                fromId=indicator["id"],
                                toId=malware["id"],
                                relationship_type="indicates",
                                description="IP Adress associated to Emotet Epoch1 botnet",
                                confidence=self.confidence_level,
                                createdBy=organization["id"],
                                externalReferences=[external_reference["id"]],
                            )

                    # Capitalize Epoch2 C2
                    for ip in self.data["Epoch2C2"]:
                        if len(ip) >= 2 and ip[0][0].isdigit():
                            indicator = self.helper.api.indicator.create(
                                name=ip[0],
                                description="Botnet Epoch2 C2 IP Adress. Port: "
                                + ip[1],
                                pattern_type="stix",
                                pattern="[ipv4-addr:value = '" + ip[0] + "']",
                                x_opencti_main_observable_type="IPv4-Addr",
                                valid_from=self.data["Date"],
                                createdBy=organization["id"],
                            )
                            observable = self.helper.api.stix_cyber_observable.create(
                                simple_observable_key="IPv4-Addr.value",
                                simple_observable_value=ip[0],
                                simple_observable_description="Botnet Epoch2 C2 IP Adress. Port: "
                                + ip[1],
                                externalReferences=[external_reference["id"]],
                                createdBy=organization["id"],
                            )
                            self.helper.api.stix_core_relationship.create(
                                fromId=indicator["id"],
                                toId=observable["id"],
                                relationship_type="based-on",
                                createdBy=organization["id"],
                            )
                            self.helper.api.stix_core_relationship.create(
                                fromId=indicator["id"],
                                toId=malware["id"],
                                relationship_type="indicates",
                                description="IP Adress associated to Emotet Epoch2 botnet.",
                                confidence=self.confidence_level,
                                createdBy=organization["id"],
                                externalReferences=[external_reference["id"]],
                            )

                    # Capitalize Epoch3 C2
                    for ip in self.data["Epoch3C2"]:
                        if len(ip) >= 2 and ip[0][0].isdigit():
                            indicator = self.helper.api.indicator.create(
                                name=ip[0],
                                description="Botnet Epoch3 C2 IP Adress. Port: "
                                + ip[1],
                                pattern_type="stix",
                                pattern="[ipv4-addr:value = '" + ip[0] + "']",
                                x_opencti_main_observable_type="IPv4-Addr",
                                valid_from=self.data["Date"],
                                createdBy=organization["id"],
                                externalReferences=[external_reference["id"]],
                            )
                            observable = self.helper.api.stix_cyber_observable.create(
                                simple_observable_key="IPv4-Addr.value",
                                simple_observable_value=ip[0],
                                simple_observable_description="Botnet Epoch3 C2 IP Adress. Port: "
                                + ip[1],
                                externalReferences=[external_reference["id"]],
                            )
                            self.helper.api.stix_core_relationship.create(
                                fromId=indicator["id"],
                                toId=observable["id"],
                                relationship_type="based-on",
                                createdBy=organization["id"],
                            )
                            self.helper.api.stix_core_relationship.create(
                                fromId=indicator["id"],
                                toId=malware["id"],
                                relationship_type="indicates",
                                description="IP Adress associated to Emotet Epoch3 botnet.",
                                confidence=self.confidence_level,
                                createdBy=organization["id"],
                                externalReferences=[external_reference["id"]],
                            )

                    # Store the current timestamp as a last run
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
                else:
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
        cryptolaemusConnector = Cryptolaemus()
        cryptolaemusConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
