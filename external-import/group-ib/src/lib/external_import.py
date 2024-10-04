import os
import sys
import time
from datetime import datetime

import stix2
from config import Config
from cyberintegrations import TIAdapter
from cyberintegrations.decorators import cache_data
from cyberintegrations.utils import FileHandler, ProxyConfigurator
from pycti import OpenCTIConnectorHelper


@cache_data(
    cache_dir=Config.MITRE_CACHE_FOLDER, cache_file=Config.MITRE_CACHE_FILENAME, ttl=1
)
def get_mitre_mapper(adapter, endpoint, params, decode=True, **kwargs):
    # type: (TIAdapter, str, dict, bool, dict) -> dict
    mitre_mapper = {}

    response = adapter.send_request(
        endpoint=endpoint, params=params, decode=decode, **kwargs
    )

    for pattern_dictionary in response.get("AttackPattern").values():
        name = pattern_dictionary.get("name", "")
        if name[0] == "[":
            name = name[1:-1:]
            name = name.split("->")[-1]
        mitre_mapper[pattern_dictionary.get("mitreId")] = name

    return mitre_mapper


class ExternalImportConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        interval (str): The interval to use. It SHOULD be a string in the format '7d', '12h', '10m', '30s'
                        where the final letter SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

        # Specific connector attributes for external import connectors
        try:
            self.interval = os.environ.get("CONNECTOR_RUN_EVERY", None).lower()
            self.helper.log_info(
                f"Verifying integrity of the CONNECTOR_RUN_EVERY value: '{self.interval}'"
            )
            unit = self.interval[-1]
            if unit not in ["d", "h", "m", "s"]:
                raise TypeError
            int(self.interval[:-1])
        except TypeError as ex:
            msg = (
                f"Error ({ex}) when grabbing CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. "
                "It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter "
                "SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively. "
            )
            self.helper.log_error(msg)
            raise ValueError(msg) from ex

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        if isinstance(update_existing_data, str) and update_existing_data.lower() in [
            "true",
            "false",
        ]:
            self.update_existing_data = update_existing_data.lower() == "true"
        elif isinstance(update_existing_data, bool) and update_existing_data in [
            True,
            False,
        ]:
            self.update_existing_data = update_existing_data
        else:
            msg = (
                f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{update_existing_data}'. "
                "It SHOULD be either `true` or `false`. `false` is assumed. "
            )
            self.helper.log_warning(msg)
            self.update_existing_data = "false"

        self.cfg = Config
        self.fh = FileHandler()
        self.pc = ProxyConfigurator()

        self.endpoints_config = self.fh.read_yaml_config(config=Config.CONFIG_YML)
        self.mapping_config = self.fh.read_json_config(config=Config.CONFIG_JSON)

        self.ttl = None

        self.ti_api_url = os.environ.get("TI_API_URL")
        self._ti_api_username = os.environ.get("TI_API_USERNAME")
        self._ti_api_token = os.environ.get("TI_API_TOKEN")

        self.proxy_ip = os.environ.get("PROXY_IP")
        self.proxy_port = os.environ.get("PROXY_PORT")
        self.proxy_protocol = os.environ.get("PROXY_PROTOCOL")
        self._proxy_username = os.environ.get("PROXY_USERNAME")
        self._proxy_password = os.environ.get("PROXY_PASSWORD")

        # Global collections filters
        self.IGNORE_NON_MALWARE_DDOS = False
        self.IGNORE_NON_INDICATOR_THREATS = False
        self.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR = False

        # gather TI API creds
        self.creds = {"api_key": self._ti_api_token, "username": self._ti_api_username}
        # Proxy initialization
        self.proxies = self.pc.get_proxies(
            proxy_ip=self.proxy_ip,
            proxy_port=self.proxy_port,
            proxy_protocol=self.proxy_protocol,
            proxy_username=self._proxy_username,
            proxy_password=self._proxy_password,
        )
        # TI API initialization
        self.ti_adapter = TIAdapter(
            ti_creds_dict=self.creds,
            proxies=self.proxies,
            config_obj=Config,
            api_url=self.ti_api_url,
        )
        # create list of collections feeds generators
        self.generators_list = None
        self.MITRE_MAPPER = None

    def _collect_intelligence(
        self, collection, ttl, portion, mitre_mapper, flag=False
    ) -> list:
        """Collect intelligence from the source"""
        raise NotImplementedError

    def _get_interval(self) -> int:
        """Returns the interval to use for the connector

        This SHOULD always return the interval in seconds. If the connector expects
        the parameter to be received as hours uncomment as necessary.
        """
        unit = self.interval[-1:]
        value = self.interval[:-1]

        try:
            if unit == "d":
                # In days:
                return int(value) * 60 * 60 * 24
            if unit == "h":
                # In hours:
                return int(value) * 60 * 60
            if unit == "m":
                # In minutes:
                return int(value) * 60
            if unit == "s":
                # In seconds:
                return int(value)
        except Exception as ex:
            self.helper.log_error(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(ex)}"
            )
            raise ValueError(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(ex)}"
            ) from ex

    def run(self) -> None:
        # Main procedure
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector last run: "
                        f'{datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")}'
                    )
                else:
                    last_run = None
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector has never run"
                    )

                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) >= self._get_interval()):
                    self.helper.metric.inc("run_count")
                    self.helper.metric.state("running")
                    self.helper.log_info(f"{self.helper.connect_name} will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = f'{self.helper.connect_name} run @ {now.strftime("%Y-%m-%d %H:%M:%S")}'
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    try:
                        # create list of collections feeds generators
                        self.generators_list = self.ti_adapter.create_generators(
                            sleep_amount=1
                        )

                        # MITRE
                        self.MITRE_MAPPER = get_mitre_mapper(
                            adapter=self.ti_adapter,
                            endpoint="common/matrix/vocab/techniques",
                            params={},
                        )

                        ###
                        for collection, generator in self.generators_list:
                            time.sleep(3)

                            if not generator:
                                self.helper.log_warning(
                                    "No generator for collection: {}".format(collection)
                                )
                                continue

                            endpoints_config = self.fh.read_yaml_config(
                                config=Config.CONFIG_YML
                            )
                            if not endpoints_config["collections"][collection][
                                "enable"
                            ]:
                                self.helper.log_warning(
                                    "User disable collection: {}. Aborting!".format(
                                        collection
                                    )
                                )
                                continue

                            # TTL
                            self.ttl = (
                                self.endpoints_config.get("collections", {})
                                .get(collection, {})
                                .get("ttl", None)
                            )

                            # Global collections filters
                            self.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR = (
                                self.endpoints_config.get("extra_settings", {}).get(
                                    "intrusion_set_instead_of_threat_actor", False
                                )
                            )
                            self.IGNORE_NON_MALWARE_DDOS = self.endpoints_config.get(
                                "extra_settings", {}
                            ).get("ignore_non_malware_ddos", True)
                            self.IGNORE_NON_INDICATOR_THREATS = (
                                self.endpoints_config.get("extra_settings", {}).get(
                                    "ignore_non_indicator_threats", False
                                )
                            )

                            for portion in generator:

                                # Extra pre-processing for collections
                                if (
                                    collection == "attacks/ddos"
                                    and self.IGNORE_NON_MALWARE_DDOS
                                ):
                                    parsed_portion = portion.parse_portion(
                                        filter_map=[("malware", [])],
                                        check_existence=True,
                                    )
                                elif (
                                    collection in ["apt/threat", "hi/threat"]
                                    and self.IGNORE_NON_INDICATOR_THREATS
                                ):
                                    parsed_portion = portion.parse_portion(
                                        filter_map=[("indicators", [])],
                                        check_existence=True,
                                    )
                                else:
                                    parsed_portion = portion.parse_portion()

                                size = len(parsed_portion)
                                count = 0
                                for event in parsed_portion:
                                    count += 1
                                    self.helper.log_debug(f"Parsing {count}/{size}")

                                    bundle_objects = self._collect_intelligence(
                                        collection,
                                        self.ttl,
                                        event,
                                        self.MITRE_MAPPER,
                                        flag=self.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR,
                                    )
                                    bundle = stix2.Bundle(
                                        objects=bundle_objects, allow_custom=True
                                    ).serialize()

                                    self.helper.log_info(
                                        f"Sending {len(bundle_objects)} STIX objects to OpenCTI..."
                                    )
                                    self.helper.send_stix2_bundle(
                                        bundle,
                                        update=self.update_existing_data,
                                        work_id=work_id,
                                    )

                                # Update seqUpdate param
                                prepared_data = {"seqUpdate": portion.sequpdate}
                                self.fh.save_collection_info(
                                    config=Config.CONFIG_YML,
                                    collection=collection,
                                    **prepared_data,
                                )

                    except Exception as e:
                        self.helper.log_error(str(e))

                    # Store the current timestamp as a last run
                    message = f"{self.helper.connect_name} connector successfully run, storing last_run as {timestamp}"
                    self.helper.log_info(message)

                    self.helper.log_debug(
                        f"Grabbing current state and update it with last_run: {timestamp}"
                    )
                    current_state = self.helper.get_state()
                    if current_state:
                        current_state["last_run"] = timestamp
                    else:
                        current_state = {"last_run": timestamp}
                    self.helper.set_state(current_state)

                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        f"Last_run stored, next run in: {round(self._get_interval() / 60 / 60, 2)} hours"
                    )
                else:
                    self.helper.metric.state("idle")
                    new_interval = self._get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector will not run, "
                        f"next run in: {round(new_interval / 60 / 60, 2)} hours"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.metric.inc("error_count")
                self.helper.metric.state("stopped")
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info(f"{self.helper.connect_name} connector ended")
                sys.exit(0)

            time.sleep(60)
