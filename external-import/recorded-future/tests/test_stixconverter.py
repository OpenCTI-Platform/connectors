
import json
import os
from pathlib import Path

import pytest
import stix2.v21

from src.rflib import URL, Domain, FileHash, IPAddress, StixNote

CWD = Path(__file__).parent

@pytest.fixture
def rf_identity():
    return stix2.v21.Identity(name="Recorded Future", identity_class="organization")


class TestStixObjects:
    def test_ip(self, rf_identity):
        obj = IPAddress("8.8.8.8", "IpAdress", rf_identity)
        js = json.loads(obj.to_json_bundle())
        assert len(js["objects"]) == 3
        with open(os.path.join(CWD, "outputs/iptest.json"), "w") as file:
            json.dump(js, file, indent=4)

    def test_domain(self, rf_identity):
        obj = Domain("google.com", "InternetDomainName", rf_identity)
        js = json.loads(obj.to_json_bundle())
        assert len(js["objects"]) == 3
        with open(os.path.join(CWD, "outputs/domaintest.json"), "w") as file:
            json.dump(js, file, indent=4)

    def test_url(self, rf_identity):
        obj = URL("https://google.com", "URL", rf_identity)
        js = json.loads(obj.to_json_bundle())
        assert len(js["objects"]) == 3
        with open(os.path.join(CWD, "outputs/urltest.json"), "w") as file:
            json.dump(js, file, indent=4)

    def test_md5_hash(self, rf_identity):
        obj = FileHash("846e27a652a5e1bfbd0ddd38a16dc865", "Hash", rf_identity)
        js = json.loads(obj.to_json_bundle())
        assert len(js["objects"]) == 3
        with open(os.path.join(CWD, "outputs/hashtest.json"), "w") as file:
            json.dump(js, file, indent=4)

    def test_note_creation(self, opencti_helper, tas, rf_client):
        note = StixNote(opencti_helper, tas, rfapi=rf_client)
        with open(os.path.join(CWD, "inputs/basicnote.json"), "r") as file:
            raw = json.load(file)
        note.from_json(raw)
        assert len(note.objects) > 2

        with open(os.path.join(CWD, "outputs/basicnote.json"), "w") as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_ta_note_creation(self, opencti_helper, tas, rf_client):
        note = StixNote(opencti_helper, tas, rfapi=rf_client)
        with open(os.path.join(CWD, "inputs/tanote.json"), "r") as file:
            raw = json.load(file)
        note.from_json(raw)
        assert len(note.objects) > 2

        with open(os.path.join(CWD, "outputs/tanote.json"), "w") as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_ta_org_note_creation(self, opencti_helper, tas, rf_client):
        note = StixNote(opencti_helper, tas, rfapi=rf_client)
        with open(os.path.join(CWD, "inputs/taorgnote.json"), "r") as file:
            raw = json.load(file)
        note.from_json(raw)
        assert len(note.objects) > 2

        with open(os.path.join(CWD, "outputs/taorgnote.json"), "w") as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_ta_org_note_creation_flag(self, opencti_helper, tas, rf_client):
        note = StixNote(opencti_helper, tas, ta_to_intrusion_set=True, rfapi=rf_client)
        with open(os.path.join(CWD, "inputs/taorgnote.json"), "r") as file:
            raw = json.load(file)
        note.from_json(raw)
        assert len(note.objects) > 2

        with open(os.path.join(CWD, "outputs/taorgnoteflag.json"), "w") as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_person_note_creation(self, opencti_helper, tas, rf_client):
        note = StixNote(opencti_helper, tas, rfapi=rf_client)
        with open(os.path.join(CWD, "inputs/personnote.json"), "r") as file:
            raw = json.load(file)
        note.from_json(raw)
        assert len(note.objects) > 2

        with open(os.path.join(CWD, "outputs/personnoteflag.json"), "w") as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_person_note_creation_flag(self, opencti_helper, tas, rf_client):
        note = StixNote(opencti_helper, tas, person_to_ta=True, rfapi=rf_client)
        with open(os.path.join(CWD, "inputs/personnote.json"), "r") as file:
            raw = json.load(file)
        note.from_json(raw)
        assert len(note.objects) > 2

        with open(os.path.join(CWD, "outputs/personnoteflag.json"), "w") as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_vuln_note_creation(self, opencti_helper, tas, rf_client):
        note = StixNote(opencti_helper, tas, rfapi=rf_client)
        with open(os.path.join(CWD, "inputs/vulnnote.json"), "r") as file:
            raw = json.load(file)
        note.from_json(raw)
        assert len(note.objects) > 1

        with open(os.path.join(CWD, "outputs/vulnnote.json"), "w") as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_yara_note_creation(self, opencti_helper, tas, rf_client):
        note = StixNote(opencti_helper, tas, rfapi=rf_client)
        with open(os.path.join(CWD, "inputs/yaranote.json"), "r") as file:
            raw = json.load(file)
        note.from_json(raw)
        assert len(note.objects) > 1

        with open(os.path.join(CWD, "outputs/yaranote.json"), "w") as file:
            json.dump(json.loads(note.to_json_bundle()), file, indent=4)

    def test_report_type_conversion(self, opencti_helper, tas, rf_client, rf_identity):
        obj = IPAddress('8.8.8.8', 'IpAdress', rf_identity)
        js = json.loads(obj.to_json_bundle())
        assert len(js['objects']) == 3
        with open(os.path.join(CWD, 'outputs/iptest.json'), 'w') as file:
            json.dump(js, file, indent=4)

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
                    "Rules for identifying malware samples through "
                    "pattern recognition."
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
        assert "Indicator" in report_types
        assert "Attack-Pattern" in report_types
