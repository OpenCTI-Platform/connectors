# from src.rflib import IPAddress, Domain, URL, FileHash, TTP, Identity, Malware, StixNote, RFClient
from src.rflib import StixNote

import pytest
import os
import pathlib
import json

CWD = pathlib.Path(__file__).parent.resolve()
OUPUT_DIR = os.path.join(CWD, 'outputs')


class TestConnector:
    @pytest.mark.vcr()
    def test_basic_pull_conversion(self, rf_client, opencti_helper):
        notes = rf_client.get_notes(10000, limit=20)
        tas = rf_client.get_threat_actors()
        for i, note in enumerate(notes):
            stixnote = StixNote(opencti_helper, tas, rf_client)
            stixnote.from_json(note, stixnote.tlp.serialize())
            #            assert len(stixnote.objects) >= 1
            assert len(stixnote.to_stix_objects()) >= 1
            with open(os.path.join(OUPUT_DIR, f'{i}.json'), 'w') as outfile:
                json.dump(json.loads(stixnote.to_json_bundle()), outfile, indent=4)
