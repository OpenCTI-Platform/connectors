from unittest.mock import MagicMock

import pytest
import stix2
from nti.converter_to_stix import ConverterToStix

MD5 = "44d88612fea8a8f36de82e1278abb02f"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def create_file_observable(hashes, names=None):
    converter = ConverterToStix(MagicMock(), MagicMock(tlp_level="clear"))
    entity = {
        "type": "indicator",
        "pattern": "[file:hashes.'MD5' = '" + MD5 + "']",
        "observables": [{"type": "file", "hashes": hashes}],
    }
    if names:
        entity["names"] = names
    converter.determine_indicator_type = lambda _: "File"
    return converter.create_obs(entity)


@pytest.mark.parametrize("hashes", [{"MD5": MD5}, {"SHA-256": SHA256}])
def test_file_without_name_is_identified_by_its_hashes(hashes):
    observable = create_file_observable(dict(hashes))

    assert "name" not in observable
    assert observable.id == stix2.File(hashes=hashes).id


def test_file_keeps_name_from_feed():
    observable = create_file_observable({"MD5": MD5}, names=["sample.exe"])

    assert observable.name == "sample.exe"
