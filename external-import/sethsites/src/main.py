import json
import os
import sys
import threading
import traceback
import yaml
import time
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from managers import ElasticsearchHelper, IncidentManager, RelationshipManager, EnvironmentManager
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix_helper import StixHelper
from scanners import (PingScanner, NmapScanner, ModbusScanner, SshScanner)
from conf import defaults
from utils import dict_merge, remove_nones
from scalpl import Cut
from stix2patterns_translator.translator import *


def build_public_network_query(environment: dict) -> dict:
    network_string = ""
    for city in environment["cities"]:
        for network in city["networks"]:
            if network["public"] == "true":
                network_string = network_string + " " + network["ip_range"]

    query = """{"sort": [{"@timestamp": "asc"}],"query": {"bool": {"should": [{"term":{"source.ip": """ + \
            f"\"{network_string.lstrip()}\"" + \
            """}},{"term":{"destination.ip": """ + \
            f"\"{network_string.lstrip()}\"" + \
            """}}],"minimum_should_match": 1}}}"""

    return json.loads(query)


class MyNetworkAttackPattern:
    def __init__(self, name):
        self.name = name


class MyThreatHost:
    def __init__(self, ip):
        self.ip = ip
        self.network_attacks = {}
        self.count = 0


class MyNetworkAttackTarget:
    def __init__(self, ip: str, count: int = 0, start: float = None, end: float = None):
        self.ip = ip
        self.count = count
        self.start = start
        self.end = end


class MyNetworkAttack:
    def __init__(self, network_attack_pattern: MyNetworkAttackPattern):
        self.network_attack_pattern = network_attack_pattern
        self.targets = {}


class SethSitesConnector:
    def __init__(self):
        self.shutdown_event: threading.Event = threading.Event()

        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.config = Cut(self.__process_config(config))

        self.helper = OpenCTIConnectorHelper(config)
        self.helper.log_info(f"config {self.config}")

        self.reload_environment = self.config.get("connector.reload_environment")

        self.fudge_time = timedelta(seconds=float(self.config.get("scanner.ping.time_sensitivity", 300)))
        self.fudge_targets = int(self.config.get("scanner.ping.target_sensitivity", 1))

        self.connector_interval = int(self.config.get("connector.interval"))
        self.helper.log_info(f"Connector Interval = {self.connector_interval}")

        self.client_name = self.config.get("client.name")
        self.helper.log_info(f"Client Name = {self.client_name}")

        self._connect_elasticsearch()
        self.es_helper = ElasticsearchHelper()
        self.environment = json.load(open("environment.json"))

        self.relationship_manager = RelationshipManager(self.helper, self.config, self.environment)
        self.environment_manager = EnvironmentManager(self.helper, self.relationship_manager, self.config,
                                                      self.environment)
        self.incident_manager = IncidentManager(self.helper, self.config, self.relationship_manager,
                                                self.environment_manager)
        self.incidents = []

        self.nmap_scanner = NmapScanner(self.config, self.environment_manager, self.elasticsearch, self.helper,
                                        self.incident_manager, self.relationship_manager, self.shutdown_event)
        self.ssh_scanner = SshScanner(self.config, self.environment_manager, self.elasticsearch, self.helper,
                                      self.incident_manager, self.relationship_manager, self.shutdown_event)
        self.ping_scanner = PingScanner(self.config, self.environment_manager, self.elasticsearch, self.helper,
                                        self.incident_manager, self.relationship_manager, self.ssh_scanner,
                                        self.shutdown_event)
        self.modbus_scanner = ModbusScanner(self.config, self.environment_manager, self.elasticsearch, self.helper,
                                            self.incident_manager, self.relationship_manager, self.shutdown_event)

        self.scanners = {
            "nmap": self.nmap_scanner,
            "ping": self.ping_scanner,
            "modbus": self.modbus_scanner,
            "ssh": self.ssh_scanner
        }
        self.scanners["ssh"] = SshScanner(self.config, self.environment_manager, self.elasticsearch, self.helper,
                                          self.incident_manager, self.relationship_manager, self.shutdown_event)

    def __process_config(self, config: dict) -> dict:
        """
        Order of precedence:
            Environment variables override command line options
            Command line options override configuration file values
            Configuration file values override defaults
        """

        # Get defaults, update with file config
        # self.helper.log_info(f"defaults {defaults}")
        # self.helper.log_info(f"config {config}")
        _conf = defaults | config
        # self.helper.log_info(f"merged {_conf}")
        # Skipping the other OpenCTI values since the helper handles them
        _env = {
            "opencti": {
                "ssl_verify": os.environ.get("OPENCTI_VERIFY_SSL", None),
                "token": os.environ.get("OPENCTI_TOKEN", None),
                "url": os.environ.get("OPENCTI_URL", None),
            },
            "connector": {
                "log_level": os.environ.get("CONNECTOR_LOG_LEVEL", None),
                "confidence_level": os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", None),
                "reload_environment": os.environ.get("CONNECTOR_RELOAD_ENVIRONMENT", None),
                "interval": os.environ.get("CONNECTOR_INTERVAL", None),
                "scope": os.environ.get("CONNECTOR_SCOPE", None),
                "name": os.environ.get("CONNECTOR_NAME", None),
                "type": os.environ.get("CONNECTOR_TYPE", None),
                "id": os.environ.get("CONNECTOR_ID", None)
            },
            "client": {
                "name": os.environ.get("CLIENT_NAME", None),
                "cloud": {
                    "auth": os.environ.get("CLOUD_AUTH", None),
                    "id": os.environ.get("CLOUD_ID", None),
                },
                "elasticsearch": {
                    "api_key": os.environ.get("ELASTICSEARCH_APIKEY", None),
                    "hosts": os.environ.get("CLIENT_ELASTICSEARCH_URL", "").split(","),
                    "username": os.environ.get("ELASTICSEARCH_USERNAME", None),
                    "password": os.environ.get("ELASTICSEARCH_PASSWORD", None),
                    "ssl_verify": os.environ.get("ELASTICSEARCH_SSL_VERIFY", None),
                }
            },
            "scanner": {
                "ping": {
                    "time_sensitivity": os.environ.get("PING_SWEEP_TIME_SENSITIVITY", None),
                    "target_sensitivity": os.environ.get("PING_SWEEP_TARGET_SENSITIVITY", None),
                }
            },
            "manager": {
                "incident": {
                    "buffer_time": os.environ.get("MANAGER_INCIDENT_BUFFER_TIME", None),
                }
            }

        }

        _env = remove_nones(_env)
        # self.helper.log_info(f"env {_env}")
        _conf |= _env
        # self.helper.log_info(f"merged {_conf}")

        return _conf

    def _connect_elasticsearch(self) -> None:
        _apikey: tuple(str) = None
        _httpauth: tuple(str) = None

        if self.config.get("cloud.auth", None):
            _httpauth = tuple(self.config.get("cloud.auth").split(":"))
        elif self.config.get("output.elasticsearch.username", None) and self.config.get(
                "output.elasticsearch.password", None
        ):
            _httpauth = (
                self.config.get("client.elasticsearch.username"),
                self.config.get("client.elasticsearch.password"),
            )

        if self.config.get("client.elasticsearch.api_key", None):
            _apikey = tuple(self.config.get("client.elasticsearch.api_key").split(":"))

        if _httpauth is not None and _apikey is not None:
            self.helper.log_error(
                "Either username/password auth or api_key auth should be used for Elasticsearch, not both."
            )
            sys.exit(1)

        if self.config.get("client.cloud.id", None):
            self.elasticsearch = Elasticsearch(
                cloud_id=self.config.get("client.cloud.id"),
                verify_certs=self.config.get("client.elasticsearch.ssl_verify", True),
                http_auth=_httpauth,
                api_key=_apikey,
            )
        else:
            self.elasticsearch = Elasticsearch(
                hosts=self.config.get("client.elasticsearch.hosts", ["localhost:9200"]),
                verify_certs=self.config.get("client.elasticsearch.ssl_verify", False),
                http_auth=_httpauth,
                api_key=_apikey,
            )

        return

    def run(self):
        print("Connector starting...")
        self.helper.log_info("Connector building our environment if it doesn't exist ...")
        self.environment_manager.check_environment()

        self.shutdown_event.clear()
        self.scanners["modbus"].start()
        self.scanners["ssh"].start()
        self.scanners["nmap"].start()
        self.scanners["ping"].start()

        self.helper.log_info("Connector searching for more data...")
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
                        (timestamp - last_run)
                        > (int(self.connector_interval) - 1)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    last_timestamp = datetime.utcfromtimestamp(last_run) if last_run is not None else None

                    # This thread doesn't really do anything right now.

                    current_state = self.helper.get_state()
                    if current_state is None:
                        self.helper.set_state({"last_run": timestamp})
                    else:
                        current_state["last_run"] = timestamp
                        self.helper.set_state(current_state)

                    time.sleep(self.connector_interval)
                else:
                    new_interval = self.connector_interval - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(new_interval)
                        + " seconds"
                    )
                    time.sleep(new_interval)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                self.shutdown_event.set()

                while threading.active_count() > 1:
                    time.sleep(10)

                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                traceback.print_exc()
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = SethSitesConnector()
        connector.run()
    except Exception as e:
        print(e)
        traceback.print_exc()
        time.sleep(10)
        exit(0)
