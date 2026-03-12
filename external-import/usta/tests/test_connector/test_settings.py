"""Unit tests for USTA Prodaft connector settings."""

from datetime import timedelta

import pytest
from connector.settings import ExternalImportConnectorConfig, UstaProdaftConfig


class TestUstaProdaftConfig:
    def test_default_page_size(self):
        assert UstaProdaftConfig(api_key="k").page_size == 100

    def test_default_import_start_date(self):
        assert UstaProdaftConfig(api_key="k").import_start_date == timedelta(days=90)

    def test_default_tlp(self):
        assert UstaProdaftConfig(api_key="k").tlp_level == "red"

    def test_default_confidence(self):
        assert UstaProdaftConfig(api_key="k").confidence_level == 99

    def test_all_feeds_enabled(self):
        c = UstaProdaftConfig(api_key="k")
        assert c.import_malicious_urls is True
        assert c.import_phishing_sites is True
        assert c.import_malware_hashes is True
        assert c.import_compromised_credentials is True
        assert c.import_credit_cards is True

    def test_invalid_confidence(self):
        with pytest.raises(Exception):
            UstaProdaftConfig(api_key="k", confidence_level=150)

    def test_invalid_tlp(self):
        with pytest.raises(Exception):
            UstaProdaftConfig(api_key="k", tlp_level="purple")

    def test_default_api_base_url(self):
        c = UstaProdaftConfig(api_key="k")
        assert "usta.prodaft.com" in str(c.api_base_url)


class TestExternalImportConnectorConfig:
    def test_default_name(self):
        assert ExternalImportConnectorConfig(id="1234").name == "USTA Prodaft"

    def test_default_duration(self):
        assert ExternalImportConnectorConfig(id="1234").duration_period == timedelta(minutes=30)

    def test_default_scope(self):
        c = ExternalImportConnectorConfig(id="1234")
        assert "indicator" in c.scope
        assert "incident" in c.scope
        assert "user-account" in c.scope
