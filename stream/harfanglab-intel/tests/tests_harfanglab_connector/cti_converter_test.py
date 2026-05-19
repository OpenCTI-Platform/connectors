from unittest.mock import Mock

import pytest
from harfanglab_intel_connector.cti_converter import CTIConverter
from harfanglab_intel_connector.models import opencti


@pytest.fixture
def mock_config():
    return Mock()


@pytest.fixture
def fake_stix_indicator():
    return opencti.Indicator(
        {
            "entity_type": "Indicator",
            "id": "opencti-uuid",
            "standard_id": "stix-uuid",
            "name": "fake_stix_indicator",
            "description": "a fake stix indicator",
            "pattern_type": "stix",
            "pattern": "[ipv4-addr:value = '172.86.102.98']",
        }
    )


@pytest.fixture
def fake_sigma_indicator():
    return opencti.Indicator(
        {
            "entity_type": "Indicator",
            "id": "opencti-uuid",
            "standard_id": "sigma-uuid",
            "name": "fake_sigma_indicator",
            "description": "a fake sigma indicator",
            "pattern_type": "sigma",
            "pattern": """
                title: WEAXOR Ransomware File Create
                id: f84e3c51-6f12-48e4-97d1-b15b76ecf236
                description: Detects file create events appending the .rox file extension or the creation of a ransomnote by WEAXOR ransomware
                references:
                  - https://x.com/malwrhunterteam/status/1853427671381803344
                status: stable
                author: CNANCE, Insikt Group, Recorded Future
                date: 2024/11/08
                level: high
                tags:
                  - attack.t1486   # Data Encrypted for Impact
                logsource:
                  category: file_create
                  product: windows
                detection:
                  extension:
                    TargetFilename|endswith: .rox
                  ransom:
                    TargetFilename|endswith: \RECOVERY INFO.txt
                  condition: extension or ransom
                falsepositives:
                  - Other ransomware families using the same ransom note name
                  - Roxio Creator uses the .rox file extension for image files
            """,
        }
    )


@pytest.fixture
def fake_yara_indicator():
    return opencti.Indicator(
        {
            "entity_type": "Indicator",
            "id": "opencti-uuid",
            "standard_id": "yara-uuid",
            "name": "fake_yara_indicator",
            "description": "a fake yara indicator",
            "pattern_type": "yara",
            "pattern": """
                rule MAL_WEAXOR_Ransomware {
                meta:
                    author = "CNANCE, Insikt Group, Recorded Future"
                    date = "2024-11-08"
                    description = "Detects Linux and Windows WEAXOR ransomware samples"
                    version = "1.0"
                    hash = "e21cbdbf6414ffc0ef4175295c7e188800a66b7b83302bd35b7e3fd6fabfccde"
                    hash = "20e0e61d27762a524f6974fb9f4995062582db351d5576e62a214d6b5e5808e7"
                    reference = "https://x.com/malwrhunterteam/status/1853427671381803344"
                    malware = "WEAXOR"
                    category = "MALWARE"
                    malware_id = "0M3gOY"

                strings:
                    $ = "key_of_target: " fullword
                    $ = "external_IP: " fullword
                    $ = "internal_IP: " fullword
                    $ = "hostname: " fullword
                    $ = "username: " fullword
                    $ = "CPU_model_RAM_size: " fullword
                    $ = "common_backups_volume: " fullword

                condition:
                    (
                        uint16(0) == 0x5a4d or
                        uint32(0)== 0x464c457f
                    ) and
                    all of them
            }
            """,
        }
    )


def test_cti_converter_create_ioc_rule(mock_config, fake_stix_indicator):
    # Given an instance of CTI converter
    # and a valid STIX indicator
    cti_converter = CTIConverter(config=mock_config)
    indicator = fake_stix_indicator
    _, observable = fake_stix_indicator.observables[0]
    # when calling create_ioc_rule
    ioc_rule = cti_converter.create_ioc_rule(indicator, observable)
    # then valid ioc_rule should be returned
    assert ioc_rule.type == "ip_both"
    assert ioc_rule.value == observable.value


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
    _, observable = indicator.observables[0]
    # when calling create_ioc_rule
    ioc_rule = cti_converter.create_ioc_rule(indicator, observable)
    # then ioc_rule type should be None
    assert ioc_rule.type is None


def test_cti_converter_create_sigma_rule(mock_config, fake_sigma_indicator):
    # Given an instance of CTI converter
    # and a valid Sigma indicator
    cti_converter = CTIConverter(config=mock_config)
    indicator = fake_sigma_indicator
    # when calling create_sigma_rule
    sigma_rule = cti_converter.create_sigma_rule(indicator)
    # then valid sigma_rule should be returned
    assert sigma_rule.name == indicator.name
    assert sigma_rule.content == indicator.pattern


def test_cti_converter_create_yara_file(mock_config, fake_yara_indicator):
    # Given an instance of CTI converter
    # and a valid Yara indicator
    cti_converter = CTIConverter(config=mock_config)
    indicator = fake_yara_indicator
    # when calling create_yara_file
    yara_file = cti_converter.create_yara_file(indicator)
    # then valid yara_file should be returned
    assert yara_file.name == indicator.name
    assert yara_file.content == indicator.pattern
