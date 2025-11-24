from unittest.mock import Mock

import pytest
from sekoia_intel_connector.cti_converter import CTIConverter
from sekoia_intel_connector.models import opencti


@pytest.fixture
def mock_config():
    return Mock()


@pytest.fixture
def fake_stix_indicator():
    return opencti.Indicator(
        {
            "type": "Indicator",
            "id": "opencti-uuid",
            "name": "fake_stix_indicator",
            "description": "a fake stix indicator",
            "pattern_type": "stix",
            "pattern": "[ipv4-addr:value = '172.86.102.98']",
            "valid_from": "2024-01-01T00:00:00.000Z",
            "valid_until": "2024-12-31T00:00:00.000Z",
            "confidence": 70,
            "kill_chain_phases": "[]",
        }
    )


def test_cti_converter_create_ioc_rule(mock_config, fake_stix_indicator):
    # Given an instance of CTI converter
    # and a valid STIX indicator
    cti_converter = CTIConverter(config=mock_config)
    indicator = fake_stix_indicator
    # when calling create_ioc_rule
    ioc_rule = cti_converter.create_sekoia_ioc(indicator)
    assert ioc_rule is not None
    # then valid ioc_rule should be returned
    assert ioc_rule.format == "ipv4-addr.value"
    assert ioc_rule.indicators == "172.86.102.98"


def test_cti_converter_create_ioc_rule_should_have_none_type(mock_config):
    # Given an instance of CTI converter
    # and invalid STIX pattern
    cti_converter = CTIConverter(config=mock_config)
    indicator = opencti.Indicator(
        {
            "entity_type": "Indicator",
            "id": "opencti-uuid",
            "standard_id": "stix-uuid",
            "name": "fake_stix_indicator",
            "description": "a fake stix indicator",
            "pattern_type": "stix",
            "pattern": "[fake-type:value = '172.86.102.98']",
        }
    )
    # when calling create_ioc_rule
    ioc_rule = cti_converter.create_sekoia_ioc(indicator)
    assert ioc_rule is not None
    # then valid ioc_rule should be returned
    assert ioc_rule.format == "one_per_line"
    assert ioc_rule.indicators == "172.86.102.98"
