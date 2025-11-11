import json
import os
import sys

# Make src importable (adjust path if your package layout differs)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from microsoft_defender_intel_synchronizer_connector.config_variables import (
    ConfigConnector,
)


def test_parse_csv():
    ids, overrides = ConfigConnector._parse_taxii_collections(None, "a,b,c")
    assert ids == ["a", "b", "c"]
    assert overrides == {}


def test_parse_json_list():
    ids, overrides = ConfigConnector._parse_taxii_collections(None, '["x","y"]')
    assert ids == ["x", "y"]
    assert overrides == {}


def test_parse_json_map_and_shorthand():
    raw = json.dumps(
        {
            "id1": {
                "action": "Block",
                "expire_time": 7,
                "rbac_group_names": ["G1", "G2"],
            },
            "id2": None,
            "id3": "",
        }
    )
    ids, overrides = ConfigConnector._parse_taxii_collections(None, raw)
    assert ids == ["id1", "id2", "id3"]
    assert "id1" in overrides and isinstance(overrides["id1"], dict)
    assert overrides["id2"] == {}
    assert overrides["id3"] == {}


def test_parse_python_dict_input():
    py = {"a": {"action": "Audit"}, "b": None}
    ids, overrides = ConfigConnector._parse_taxii_collections(None, py)
    assert ids == ["a", "b"]
    assert overrides["a"]["action"] == "Audit"
    assert overrides["b"] == {}
