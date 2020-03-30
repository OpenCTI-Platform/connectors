# coding: utf-8

import os
from typing import Optional, Dict, Any, Mapping
import yaml
import time
import requests
import re
import stix2

from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable
from pycti.utils.constants import CustomProperties


class CyberThreatCoalition:

    _OPENCTI_TYPE = {
        'domain': "[domain-name:value = '{}']",
        'ip': "[ipv4addr:value = '{}']",
        'sha256': "[file:hashes.SHA256 = '{}']",
        'sha1': "[file:hashes.SHA1 = '{}']",
        'md5': "[file:hashes.MD5 = '{}']",
        'url': "[url:value = '{}']"
    }

    _STATE_LAST_RUN = "last_run"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.cyber_threat_coalition_interval = get_config_variable(
            "CYBER_THREAT_COALITION_INTERVAL", ["cyber-threat-coalition", "interval_sec"], config, True
        )
        self.cyber_threat_coalition_base_url = get_config_variable(
            "CYBER_THREAT_COALITION_BASE_URL", ["cyber-threat-coalition", "base_url"], config, False
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

    def get_interval(self) -> int:
        return int(self.cyber_threat_coalition_interval)

    @staticmethod
    def get_hash_type(hash_value):
        if re.match(r"^[0-9a-fA-F]{32}$", hash_value):
            return 'md5'
        elif re.match(r"^[0-9a-fA-F]{40}$", hash_value):
            return 'sha1'
        elif re.match(r"^[0-9a-fA-F]{64}$", hash_value):
            return 'sha256'

    def fetch_and_send(self):

        bundle_objects = list()

        # create an identity for the coalition team
        organization = stix2.Identity(
            name="Cyber Threat Coalition Team",
            identity_class="organization",
            description="Team of Experts collecting and sharing pandemic related "
                        "cyber threat intelligence during the COVID-19 crisis time"
        )

        # add organization in bundle
        bundle_objects.append(organization)

        report_object_refs = list()

        for collection in ["domain", "ip", "url", "hash"]:
            # fetch backlist
            url = self.cyber_threat_coalition_base_url+"/"+str(collection)+".txt"
            response = requests.get(url=url)
            if response.status_code != 200:
                raise Exception("Unable to fetch {0} blacklist, server returned status: {1}",
                                collection, response.status_code)

            opencti_type = None
            pattern_type = "stix"

            # parse content
            for data in response.iter_lines(decode_unicode=True):
                if data and not data.startswith("#"):
                    if collection == 'domain':
                        opencti_type = 'domain'
                    elif collection == 'ip':
                        opencti_type = 'ip'
                    elif collection == 'url':
                        opencti_type = 'url'
                    elif collection == 'hash':
                        opencti_type = self.get_hash_type(data)
                        self.helper.log_info(opencti_type)
                        self.helper.log_info(data)

                    indicator = stix2.Indicator(
                        name=data,
                        pattern=self._OPENCTI_TYPE[opencti_type].format(data),
                        labels=["malicious-activity"],
                        created_by_ref=organization,
                        custom_properties={
                            CustomProperties.OBSERVABLE_TYPE: opencti_type,
                            CustomProperties.OBSERVABLE_VALUE: data,
                            CustomProperties.PATTERN_TYPE: pattern_type,
                        }
                    )
                    # add indicator in bundle and report_refs
                    bundle_objects.append(indicator)
                    report_object_refs.append(indicator['id'])

        # create a global threat report
        report_uuid = "552b3ae6-8522-409d-8b72-a739bc1926aa"
        
        stix_report = stix2.Report(
            id=report_uuid,
            name="COVID-19 CyberThreat Coalition BlackList",
            type="report",
            description="",
            published=datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            created_by_ref=organization,
            object_marking_refs=[stix2.TLP_WHITE],
            labels=["threat-report"],
            object_refs=report_object_refs
        )

        # add report in bundle
        bundle_objects.append(stix_report)

        # create stix bundle
        bundle = stix2.Bundle(objects=bundle_objects)

        # send data
        self.helper.send_stix2_bundle(
            bundle=bundle.serialize(),  update=self.update_existing_data
        )

    def _load_state(self) -> Dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            return True
        time_diff = current_time - last_run
        return time_diff >= self.get_interval()

    @staticmethod
    def _get_state_value(
            state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def run(self):
        self.helper.log_info("Fetching Cyber Threat Coalition vetted blacklists...")
        while True:
            try:

                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()

                self.helper.log_info(f"Loaded state: {current_state}")

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)
                if self._is_scheduled(last_run, timestamp):

                    # fetch data and send as stix bundle
                    self.fetch_and_send()

                    new_state = current_state.copy()
                    new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()

                    self.helper.log_info(f"Storing new state: {new_state}")

                    self.helper.set_state(new_state)

                    self.helper.log_info(
                        f"State stored, next run in: {self.get_interval()} seconds"
                    )
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"Connector will not run, next run in: {new_interval} seconds"
                    )
                time.sleep(60)

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as ex:
                self.helper.log_error(str(ex))
                time.sleep(60)

    
if __name__ == "__main__":
    try:
        ctc_connector = CyberThreatCoalition()
        ctc_connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
