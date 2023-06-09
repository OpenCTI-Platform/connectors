import io
import ipaddress
import json
import os
import re
import sys
import time
from hashlib import sha256
from typing import Any, Dict, List, Mapping, Optional

import magic
import stix2
import yaml
from pycti import (
    AttackPattern,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from stix2 import URL, CustomObservable, DomainName, EmailAddress, IPv4Address
from stix2.properties import ListProperty  # type: ignore # noqa: E501
from stix2.properties import ReferenceProperty, StringProperty
from triage import Client
import datetime


class HatchingTriageImporter:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Hatching Triage Importer",
            description="Hatching Triage Importer",
        )["standard_id"]

        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )

        # Get URL and token from config, use to instantiate the Triage Client
        base_url = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_BASE_URL",
            ["hatching_triage_sandbox", "base_url"],
            config,
        )
        token = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_TOKEN",
            ["hatching_triage_sandbox", "token"],
            config,
        )

        self.triage_client = Client(token,root_url=base_url)

        self.interval_sec=get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_INTERVAL_SEC",
            ["hatching_triage_sandbox", "interval_sec"],
            config,
        )

        # Get other config values
        self.use_existing_analysis = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_USE_EXISTING_ANALYSIS",
            ["hatching_triage_sandbox", "use_existing_analysis"],
            config,
        )
        self.family_color = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_FAMILY_COLOR",
            ["hatching_triage_sandbox", "family_color"],
            config,
        )
        self.botnet_color = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_BOTNET_COLOR",
            ["hatching_triage_sandbox", "botnet_color"],
            config,
        )
        self.campaign_color = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_CAMPAIGN_COLOR",
            ["hatching_triage_sandbox", "campaign_color"],
            config,
        )
        self.default_tag_color = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_TAG_COLOR",
            ["hatching_triage_sandbox", "tag_color"],
            config,
        )
        self.max_tlp = get_config_variable(
            "HATCHING_TRIAGE_SANDBOX_MAX_TLP",
            ["hatching_triage_sandbox", "max_tlp"],
            config,
        )
        _CONNECTOR_RUN_INTERVAL_SEC = 60
        _STATE_LAST_RUN = "last_run"

        
    
    def run(self):
        """Run HatchingTriage connector."""
        self._info("Starting HatchingTriage connector...")
        while True:
            self._info("Running HatchingTriage connector...")
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()

                self._info("Loaded state: {0}", current_state)

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)
                if self._is_scheduled(last_run, timestamp):
                    now = datetime.datetime.utcfromtimestamp(timestamp)
                    friendly_name = "HatchingTriage run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    pulse_import_state = self.pulse_importer.run(current_state, work_id)
                    new_state = current_state.copy()
                    new_state.update(pulse_import_state)
                    new_state[self._STATE_LAST_RUN] = time.time()

                    self._info("Storing new state: {0}", new_state)
                    self.helper.set_state(new_state)
                    message = (
                        "State stored, next run in: "
                        + str(self._get_interval())
                        + " seconds"
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self._info(message)
                else:
                    next_run = self._get_interval() - (timestamp - last_run)
                    run_interval = min(run_interval, next_run)

                    self._info(
                        "Connector will not run, next run in: {0} seconds", next_run
                    )

            except (KeyboardInterrupt, SystemExit):
                self._info("Connector stop")
                sys.exit(0)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                sys.exit(0)

            self._sleep(delay_sec=run_interval)

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        sleep_delay = (
            delay_sec if delay_sec is not None else cls._CONNECTOR_RUN_INTERVAL_SEC
        )
        time.sleep(sleep_delay)
    
    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self.helper.log_info("Connector first run")
            return True
        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _load_state(self) -> Dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state
