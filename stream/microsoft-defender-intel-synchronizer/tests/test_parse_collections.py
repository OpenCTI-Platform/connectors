import json

from microsoft_defender_intel_synchronizer_connector.config_variables import (
    ConfigConnector,
)


def test_parse_csv():
    ids, overrides = ConfigConnector._parse_taxii_collections("a,b,c")
    assert ids == ["a", "b", "c"]
    assert overrides == {}


def test_parse_json_list():
    ids, overrides = ConfigConnector._parse_taxii_collections('["x","y"]')
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
    ids, overrides = ConfigConnector._parse_taxii_collections(raw)
    assert ids == ["id1", "id2", "id3"]
    assert "id1" in overrides and isinstance(overrides["id1"], dict)
    assert overrides["id2"] == {}
    assert overrides["id3"] == {}


def test_parse_python_dict_input():
    py = {"a": {"action": "Audit"}, "b": None}
    ids, overrides = ConfigConnector._parse_taxii_collections(py)
    assert ids == ["a", "b"]
    assert overrides["a"]["action"] == "Audit"
    assert overrides["b"] == {}


def test_parse_json_map_with_max_indicators():
    raw = json.dumps(
        {
            "id1": {"action": "Block", "max_indicators": 123},
            "id2": {"max_indicators": "50"},
        }
    )
    ids, overrides = ConfigConnector._parse_taxii_collections(raw)
    assert ids == ["id1", "id2"]
    assert overrides["id1"]["max_indicators"] == 123
    assert overrides["id2"]["max_indicators"] == 50


# --- Whitespace / blank normalisation on every input shape ----------------
#
# The CSV branch has always stripped + filtered empties, but the YAML list,
# YAML dict, JSON list and JSON dict branches used to forward whitespace and
# blank entries verbatim. A `taxii_collections: ['COLL1', '  ', '']` config
# could therefore reach the runtime layer with three "collection ids", bypass
# the empty-collections fail-fast guard added in `config_variables.__init__`,
# and feed a blank id to Defender on the next sync cycle — and on a
# `update_only_owned=true` deployment, that effectively means planning a
# deletion of every connector-owned Defender indicator. These cases pin the
# normalisation: every parsing branch must drop blank / whitespace-only
# entries the same way the CSV branch does.


def test_parse_python_list_strips_and_drops_blanks():
    # ``None`` is dropped (a bare ``-`` in a YAML list becomes Python ``None``)
    # rather than being stringified to the literal ``"None"``; whitespace-only
    # entries are dropped too.
    ids, overrides = ConfigConnector._parse_taxii_collections(
        ["COLL1", "  COLL2  ", "", "   ", None, "COLL3"]
    )
    assert ids == ["COLL1", "COLL2", "COLL3"]
    assert overrides == {}


def test_parse_python_list_all_blank_returns_empty():
    ids, overrides = ConfigConnector._parse_taxii_collections(["", "   ", "\t"])
    assert ids == []
    assert overrides == {}


def test_parse_python_dict_strips_and_drops_blank_keys():
    py = {"  COLL1  ": {"action": "Audit"}, "": {"action": "Block"}}
    ids, overrides = ConfigConnector._parse_taxii_collections(py)
    assert ids == ["COLL1"]
    assert overrides["COLL1"]["action"] == "Audit"
    assert "" not in overrides


def test_parse_json_list_strips_and_drops_blanks():
    raw = json.dumps(["COLL1", "  COLL2  ", "", "   ", "COLL3"])
    ids, overrides = ConfigConnector._parse_taxii_collections(raw)
    assert ids == ["COLL1", "COLL2", "COLL3"]
    assert overrides == {}


def test_parse_json_dict_strips_and_drops_blank_keys():
    raw = json.dumps({"  COLL1  ": {"action": "Audit"}, "": {"action": "Block"}})
    ids, overrides = ConfigConnector._parse_taxii_collections(raw)
    assert ids == ["COLL1"]
    assert overrides["COLL1"]["action"] == "Audit"
    assert "" not in overrides


# --- Duplicate-key dedup (after whitespace normalisation) -----------------
#
# When two map keys collapse to the same id after ``str(k).strip()`` (e.g.
# ``"COLL1"`` and ``"  COLL1  "`` in the same YAML / JSON map), the parser
# must keep the **first** occurrence and ignore subsequent duplicates. Without
# this, ``order`` would contain the same collection id twice (causing
# duplicated fetch passes against the OpenCTI TAXII stream) and the later
# entry would silently overwrite the first one's per-collection policy in
# ``overrides``. A typo in the config would then either double the work or
# silently drop the operator's intended ``action``/``expire_time``/etc.


def test_parse_python_dict_dedupes_normalised_keys(caplog):
    py = {
        "COLL1": {"action": "Audit"},
        "  COLL1  ": {"action": "Block"},
        "COLL2": None,
    }
    with caplog.at_level("WARNING"):
        ids, overrides = ConfigConnector._parse_taxii_collections(py)
    assert ids == ["COLL1", "COLL2"]
    # First occurrence wins; the later "Block" override is dropped.
    assert overrides["COLL1"]["action"] == "Audit"
    assert overrides["COLL2"] == {}
    assert any(
        "Duplicate taxii_collections key" in rec.message for rec in caplog.records
    )


def test_parse_json_dict_dedupes_normalised_keys(caplog):
    raw = json.dumps(
        {
            "COLL1": {"action": "Audit"},
            "  COLL1  ": {"action": "Block"},
            "COLL2": None,
        }
    )
    with caplog.at_level("WARNING"):
        ids, overrides = ConfigConnector._parse_taxii_collections(raw)
    assert ids == ["COLL1", "COLL2"]
    assert overrides["COLL1"]["action"] == "Audit"
    assert overrides["COLL2"] == {}
    assert any(
        "Duplicate taxii_collections key" in rec.message for rec in caplog.records
    )
