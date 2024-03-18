import json

import pytest
import requests.exceptions

from src.rflib import RFClient


class TestRFClient:
    def test_init(self, rf_token, opencti_helper):
        RFClient(rf_token, opencti_helper, header="OpenCTI-notes/1.0")

    @pytest.mark.vcr()
    def test_notes_basic(self, rf_client):
        res = rf_client.get_notes(10000, limit=100)
        assert len(res) >= 50

    @pytest.mark.vcr()
    def test_bad_token(self, opencti_helper):
        was_err = False
        try:
            rf_client = RFClient(
                "notarealtoken", opencti_helper, header="OpenCTI-notes/1.0"
            )
            rf_client.get_notes(100, limit=100)
        except requests.exceptions.HTTPError as err:
            assert "401" in str(err)
            was_err = True
        assert was_err

    @pytest.mark.vcr()
    def test_signatures(self, rf_client):
        res = rf_client.get_notes(1000, limit=10, pull_signatures=True)
        assert len(res) >= 5

    @pytest.mark.vcr()
    def test_signatures_with_topic(self, rf_client):
        res = rf_client.get_notes(1000, limit=10, topic="ZjnoP2", pull_signatures=True)
        for note in res:
            assert "attachment_type" in note["attributes"]
        assert len(res) >= 1

    @pytest.mark.vcr()
    def test_get_fusion_file(self, rf_client):
        res = rf_client.get_fusion_file("/public/opencti/threat_actors.json")
        json.loads(res)
        assert len(res) > 1

    @pytest.mark.vcr()
    def test_get_threat_actors(self, rf_client):
        res = rf_client.get_threat_actors()
        assert isinstance(res, set)
        assert len(res) > 1
