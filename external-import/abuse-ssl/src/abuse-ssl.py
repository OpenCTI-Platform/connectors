import os
import time
from datetime import datetime, timezone

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Bundle, Identity, Indicator, IPv4Address, Relationship


class AbuseSSLImportConnector:
    """Enumerates files from text, then processes them"""

    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.author = Identity(
            name=get_config_variable(
                "CONNECTOR_NAME", ["connector", "name"], config
            ).capitalize(),
            identity_class="organization",
        )
        self.api_url = get_config_variable(
            "ABUSESSL_URL",
            ["abusessl", "url"],
            config,
        )
        self.interval = (
            get_config_variable(
                "ABUSESSL_INTERVAL",
                ["abusessl", "interval"],
                config,
            )
            * 60
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

    def run(self):
        """Running component of class"""
        while True:
            try:
                current_state = self.helper.get_state()
                now = datetime.now(tz=timezone.utc)
                friendly_name = "TxtSTIX run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                if current_state is not None and "last_run" in current_state:
                    last_seen = datetime.fromtimestamp(current_state["last_run"])
                    self.helper.log_info(f"Connector last ran at: {last_seen} (UTC)")
                else:
                    self.helper.log_info("Connector has never run")

                ips = self.get_ips(self.api_url)
                observables = self.create_observables(ips)
                indicators = self.create_indicators(observables)
                relationships = self.create_relationships(observables, indicators)
                bundle = self.create_bundle(observables, indicators, relationships)
                self.send_bundle(bundle, work_id)

                message = (
                    "Connector successfully run ("
                    + str((len(indicators) + len(observables) + len(relationships)))
                    + " events have been processed), storing last_run as "
                    + str(now)
                )
                self.helper.log_info(message)
                self.helper.set_state(
                    {
                        "last_run": now.timestamp(),
                    }
                )
                time.sleep(self.interval)

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)

            except Exception as exception:
                self.helper.log_error(str(exception))
                time.sleep(self.interval)

    def get_ips(self, url):
        """
        Retrieves response from provided URL and grabs IPv4 addresses from resulting HTML

        :param url: URL for list of IPv4 addresses
        :return: :class:`List` of IPv4 addresses
        """
        self.helper.log_info("Enumerating IPv4 addresses")
        response = requests.get(url)
        if response.ok:
            response_text = response.text
        else:
            return response.raise_for_status()

        text_lines = response_text.split("\n")
        ip_addresses = []
        for line in text_lines:
            # Ignore lines starting with '#' and empty lines
            if not line.startswith("#") and not line == "":
                data = line.split(",")
                ip = data[1]
                ip_addresses.append(ip)
        return ip_addresses

    def create_observables(self, ip_addresses):
        """
        Creates STIX IPv4 Observables from provided list of IPv4 addresses

        :param ip_addresses: List of IPv4 addresses
        :return: :class:`List` of STIX IPv4Address Observables
        """
        self.helper.log_info("Creating STIX Observables")
        observables = []
        for ip in ip_addresses:
            observable = IPv4Address(value=ip)
            observables.append(observable)
        return observables

    def create_indicators(self, observables):
        """
        Creates STIX Indicators from provided STIX observables

        :param observables: List of STIX IPv4Address observables
        :return: :class:`List` of STIX Indicators
        """
        self.helper.log_info("Creating STIX Indicators")
        indicators = []
        for observable in observables:
            indicator = Indicator(
                name=observable.value,
                description="Malicious SSL connections",
                created_by_ref=f"{self.author.id}",
                confidence=self.helper.connect_confidence_level,
                pattern_type="stix",
                pattern=f"[ipv4:value = '{observable.value}']",
                labels="osint",
            )
            indicators.append(indicator)
        return indicators

    def create_relationships(self, observables, indicators):
        """
        Creates a list of STIX Relationships between the given lists of STIX Observables and Indicators

        :param observables: List of STIX Observables objects
        :param indicators: List of STIX Indicators objects
        :return: List of STIX Relationship objects
        """
        self.helper.log_info("Creating STIX Relationships")
        relationships = []
        for i in range(len(observables)):
            relationship = Relationship(
                relationship_type="based-on",
                source_ref=indicators[i].id,
                target_ref=observables[i].id,
            )
            relationships.append(relationship)
        return relationships

    def create_bundle(self, observables, indicators, relationships):
        """Creates serialized STIX Bundle object from the provided lists of STIX Observables, Indicators, and Relationships

        :param indicators: List of STIX Indicator objects
        :return: Serialized STIX Bundle object
        """
        self.helper.log_info("Creating STIX Bundle")
        bundle = Bundle(self.author, observables, indicators, relationships).serialize()
        return bundle

    def send_bundle(self, bundle, work_id):
        """
        Attempts to send serialized STIX Bundle to OpenCTI client

        :param bundle: Serialized STIX Bundle
        """
        self.helper.log_info("Sending STIX Bundle")
        try:
            self.helper.send_stix2_bundle(
                bundle, work_id=work_id, update=self.update_existing_data
            )
        except:
            time.sleep(60)
            try:
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, update=self.update_existing_data
                )
            except Exception as e:
                self.helper.log_error(str(e))


if __name__ == "__main__":
    try:
        AbuseSSLImportConnector = AbuseSSLImportConnector()
        AbuseSSLImportConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
