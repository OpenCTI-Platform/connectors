# from src.rflib import IPAddress, Domain, URL, FileHash, TTP, Identity, Malware, StixNote
from pathlib import Path
from src.rflib import IPAddress, Domain, URL, FileHash, StixNote
import stix2.v21
import json
import os
import pytest

CWD = Path(__file__).parent

@pytest.fixture
def rf_identity():
    return stix2.v21.Identity(name='Recorded Future', identity_class='organization')


class TestStixObjects:
    def test_ip(self, rf_identity, tmp_path):
        obj = IPAddress('8.8.8.8', 'IpAdress', rf_identity)
        js = json.loads(obj.to_json_bundle())
        assert len(js['objects']) == 3
        with open(os.path.join(tmp_path, 'iptest.json'), 'w') as file:
            json.dump(js, file, indent=4)

    def test_domain(self, rf_identity, tmp_path):
        obj = Domain('google.com', 'InternetDomainName', rf_identity)
        js = json.loads(obj.to_json_bundle())
        assert len(js['objects']) == 3
        with open(os.path.join(tmp_path, 'domaintest.json'), 'w') as file:
            json.dump(js, file, indent=4)

    def test_url(self, rf_identity, tmp_path):
        obj = URL('https://google.com', 'URL', rf_identity)
        js = json.loads(obj.to_json_bundle())
        assert len(js['objects']) == 3
        with open(os.path.join(tmp_path, 'urltest.json'), 'w') as file:
            json.dump(js, file, indent=4)

    def test_md5_hash(self, rf_identity, tmp_path):
        obj = FileHash('846e27a652a5e1bfbd0ddd38a16dc865', 'Hash', rf_identity)
        js = json.loads(obj.to_json_bundle())
        assert len(js['objects']) == 3
        with open(os.path.join(tmp_path, 'hashtest.json'), 'w') as file:
            json.dump(js, file, indent=4)

    def test_note_creation(self, opencti_helper, tas, rf_client, tmp_path):
        note = StixNote(opencti_helper, tas, rf_client)
        with open(os.path.join(CWD, 'inputs/basicnote.json'), 'r') as file:
            raw = json.load(file)
        note.from_json(raw, note.tlp.serialize())
        assert len(note.objects) > 2
        with open(os.path.join(tmp_path, 'basicnote.json'), 'w') as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_ta_note_creation(self, opencti_helper, tas, rf_client, tmp_path):
        note = StixNote(opencti_helper, tas, rf_client)
        with open(os.path.join(CWD, 'inputs/tanote.json'), 'r') as file:
            raw = json.load(file)
        note.from_json(raw, note.tlp.serialize())
        assert len(note.objects) > 2
        with open(os.path.join(tmp_path, 'tanote.json'), 'w') as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_ta_org_note_creation(self, opencti_helper, tas, rf_client, tmp_path):
        note = StixNote(opencti_helper, tas, rf_client)
        with open(os.path.join(CWD, 'inputs/taorgnote.json'), 'r') as file:
            raw = json.load(file)
        note.from_json(raw, note.tlp.serialize())
        assert len(note.objects) > 2
        with open(os.path.join(tmp_path, 'taorgnote.json'), 'w') as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_ta_org_note_creation_flag(self, opencti_helper, tas, rf_client, tmp_path):
        note = StixNote(opencti_helper, tas, rf_client, ta_to_intrusion_set=True)
        with open(os.path.join(CWD, 'inputs/taorgnote.json'), 'r') as file:
            raw = json.load(file)
        note.from_json(raw, note.tlp.serialize())
        assert len(note.objects) > 2
        with open(os.path.join(tmp_path, 'taorgnoteflag.json'), 'w') as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_person_note_creation(self, opencti_helper, tas, rf_client, tmp_path):
        note = StixNote(opencti_helper, tas, rf_client)
        with open(os.path.join(CWD, 'inputs/personnote.json'), 'r') as file:
            raw = json.load(file)
        note.from_json(raw, note.tlp.serialize())
        assert len(note.objects) > 2
        with open(os.path.join(tmp_path, 'personnoteflag.json'), 'w') as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_person_note_creation_flag(self, opencti_helper, tas, rf_client, tmp_path):
        note = StixNote(opencti_helper, tas, rf_client, person_to_ta=True)
        with open(os.path.join(CWD, 'inputs/personnote.json'), 'r') as file:
            raw = json.load(file)
        note.from_json(raw, note.tlp.serialize())
        assert len(note.objects) > 2
        with open(os.path.join(tmp_path, 'personnoteflag.json'), 'w') as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_vuln_note_creation(self, opencti_helper, tas, rf_client, tmp_path):
        note = StixNote(opencti_helper, tas, rf_client)
        with open(os.path.join(CWD, 'inputs/vulnnote.json'), 'r') as file:
            raw = json.load(file)
        note.from_json(raw, note.tlp.serialize())
        assert len(note.objects) > 1
        with open(os.path.join(tmp_path, 'vulnnote.json'), 'w') as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_yara_note_creation(self, opencti_helper, tas, rf_client, tmp_path):
        note = StixNote(opencti_helper, tas, rf_client)
        with open(os.path.join(CWD, 'inputs/yaranote.json'), 'r') as file:
            raw = json.load(file)
        note.from_json(raw, note.tlp.serialize())
        assert len(note.objects) > 1
        with open(os.path.join(tmp_path, 'yaranote.json'), 'w+') as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_report_type_conversion(self, opencti_helper, tas, rf_client):
        topics = [
            {
                "id": "ZjnoP2",
                "name": "Hunting Package",
                "type": "Topic",
                "description": (
                    "Technical detection and mitigations for"
                    "specific malware, including YARA or Snort rules."
                ),
            },
            {
                "id": "VTrvnW",
                "name": "YARA Rule",
                "type": "Topic",
                "description": (
                    "Rules for identifying malware samples through " "pattern recognition."
                ),
            },
            {
                "id": "TXSFt4",
                "name": "Indicator",
                "type": "Topic",
                "description": (
                    "Used in conjunction with another Topic to capture"
                    "bulk indicators of compromise for a particular threat."
                ),
            },
        ]
        note = StixNote(opencti_helper, tas, rf_client)
        report_types = note._create_report_types(topics)
        assert len(report_types) == 2
        assert 'Indicator' in report_types
        assert 'Attack-Pattern' in report_types
