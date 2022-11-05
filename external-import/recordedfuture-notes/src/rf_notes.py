"""Connector to bulk ingest Recorded Future Risk Lists as STIX2 bundles
############################## TERMS OF USE ####################################
# The following code is provided for demonstration purposes only, and should   #
# not be used without independent verification. Recorded Future makes no       #
# representations or warranties, express, implied, statutory, or otherwise,    #
# regarding this code, and provides it strictly "as-is".                       #
# Recorded Future shall not be liable for, and you assume all risk of          #
# using the foregoing.                                                         #
################################################################################
"""

import os
import time
import traceback
from datetime import datetime
import yaml
from rflib import StixNote, RFClient, APP_VERSION

from pycti import OpenCTIConnectorHelper, get_config_variable


class RFNotes:
    """Connector object"""

    def __init__(self):
        """Read in config variables"""

        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.rf_token = get_config_variable("RECORDED_FUTURE_TOKEN", ["rf-notes", "token"], config)
        self.rf_initial_lookback = get_config_variable(
            "RECORDED_FUTURE_INITIAL_LOOKBACK", ["rf-notes", "initial_lookback"], config, True
        )
        self.rf_interval = get_config_variable(
            "RECORDED_FUTURE_INTERVAL", ["rf-notes", "interval"], config, True
        )
        self.rf_pull_signatures = get_config_variable(
            'RECORDED_FUTURE_PULL_SIGNATURES', ["rf-notes", "pull_signatures"], config
        )
        self.rf_insikt_only = get_config_variable(
            'RECORDED_FUTURE_INSIKT_ONLY', ["rf-notes", "insikt_only"], config
        )
        self.rf_topic = get_config_variable('RECORDED_FUTURE_TOPIC', ["rf-notes", "topic"], config)

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.rfapi = RFClient(
            self.rf_token,
            self.helper,
            header=f'OpenCTI-notes/{APP_VERSION}',
        )
        # In a crisis, smash glass and uncomment this line of code
        # self.helper.config['uri'] = self.helper.config['uri'].replace('rabbitmq', '172.19.0.6')

    def get_interval(self):
        """Converts interval hours to seconds"""
        return int(self.rf_interval) * 3600

    def run(self):
        """Run connector on a schedule"""
        while True:
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            tas = self.rfapi.get_threat_actors()
            if current_state is not None and "last_run" in current_state:
                last_run = datetime.utcfromtimestamp(current_state["last_run"]).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                self.helper.log_info("Connector last run: " + last_run)
                published = self.rf_interval
            else:
                last_run = None
                msg = (
                    'Connector has never run. Doing initial pull of'
                    f'{self.rf_initial_lookback} hours'
                )
                self.helper.log_info(msg)
                published = self.rf_initial_lookback

            try:
                self.convert_and_send(published, tas)
            except Exception as e:
                self.helper.log_error(str(e))

            self.helper.set_state({"last_run": timestamp})
            time.sleep(self.get_interval())

    def convert_and_send(self, published, tas):
        """Pulls Analyst Notes, converts to Stix2, sends to OpenCTI"""
        self.helper.log_info(
            f'Pull Signatures is is {str(self.rf_pull_signatures)} of type '
            f'{type(self.rf_pull_signatures)}'
        )
        self.helper.log_info(
            f'Insikt Only is {str(self.rf_insikt_only)} of type {type(self.rf_insikt_only)}'
        )
        self.helper.log_info(f'Topic is {str(self.rf_topic)} of type {type(self.rf_topic)}')

        notes = self.rfapi.get_notes(
            published, self.rf_pull_signatures, self.rf_insikt_only, self.rf_topic
        )
        self.helper.log_info(f'fetched {len(notes)} Analyst notes from API')
        for note in notes:
            stixnote = StixNote(self.helper, tas)
            stixnote.from_json(note)
            bundle = stixnote.to_stix_bundle()
            self.helper.log_info(
                'Sending Bundle to server with ' + str(len(bundle.objects)) + ' objects'
            )
            self.helper.send_stix2_bundle(
                bundle.serialize(),
                update=self.update_existing_data,
            )


if __name__ == "__main__":
    try:
        RF = RFNotes()
        RF.run()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        exit(0)
