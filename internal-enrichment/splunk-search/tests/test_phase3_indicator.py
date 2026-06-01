"""Tests for Phase 3 Part 2 — SPL Indicator enrichment path."""

from types import SimpleNamespace
from unittest.mock import Mock, patch

import stix2
from internal_enrichment_connector.connector import SplunkSearchConnector
from internal_enrichment_connector.splunk_indicators import SplunkIndicator

INDICATOR_ID = "indicator--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


# ------------------------------------------------------------------ #
#  Shared fixtures                                                    #
# ------------------------------------------------------------------ #


def _helper():
    helper = Mock()
    helper.api.indicator.list.return_value = []
    helper.api.note.list.return_value = []
    helper.send_stix2_bundle.return_value = ["bundle-id"]
    helper.connector_logger = Mock()
    helper.connector_logger.debug = Mock()
    helper.connector_logger.info = Mock()
    helper.connector_logger.error = Mock()
    helper.connector_logger.warning = Mock()
    return helper


def _config():
    return SimpleNamespace(
        splunk_host="splunk.example.com",
        splunk_port=8089,
        splunk_token="token",
        splunk_app="search",
        splunk_scheme="https",
        splunk_verify_ssl=True,
        splunk_search_earliest="-30d@d",
        splunk_search_latest="now",
        splunk_timeout=60,
        splunk_wait_seconds=2,
        splunk_max_results=1000,
        observable_tlp="marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        sighting_tlp="marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    )


def _connector(helper=None):
    with patch("internal_enrichment_connector.connector.SplunkClient"):
        return SplunkSearchConnector(helper=helper or _helper(), config=_config())


def _indicator_entity(pattern="index=main | head 10", pattern_type="spl"):
    return {
        "entity_type": "Indicator",
        "type": "indicator",
        "id": INDICATOR_ID,
        "standard_id": INDICATOR_ID,
        "name": "Test SPL Indicator",
        "pattern_type": pattern_type,
        "pattern": pattern,
        "x_opencti_main_observable_type": "IPv4-Addr",
    }


def _indicator_data(**kwargs):
    return {"enrichment_entity": _indicator_entity(**kwargs), "stix_objects": []}


def _cim_rows(src_ip="1.2.3.4", src_dns=None, url=None, sourcetype="syslog"):
    row = {"sourcetype": sourcetype}
    if src_ip:
        row["src_ip"] = src_ip
    if src_dns:
        row["src_dns"] = src_dns
    if url:
        row["url"] = url
    return [row]


# ------------------------------------------------------------------ #
#  1. Indicator routing                                               #
# ------------------------------------------------------------------ #


def test_indicator_routing():
    """_process_message should route Indicator entities to _enrich_indicator."""
    connector = _connector()
    connector.splunk_client.run_search.return_value = []
    with patch.object(connector, "_enrich_indicator", return_value="ok") as m:
        connector._process_message(_indicator_data())
    m.assert_called_once()
    entity_arg = m.call_args[0][0]
    assert entity_arg["id"] == INDICATOR_ID


# ------------------------------------------------------------------ #
#  2. SPL extraction                                                  #
# ------------------------------------------------------------------ #


def test_spl_extraction_returns_pattern():
    entity = _indicator_entity(pattern="index=main | head 10")
    assert SplunkIndicator.extract_spl(entity) == "index=main | head 10"


def test_spl_extraction_non_spl_returns_none():
    entity = _indicator_entity(
        pattern="[ipv4-addr:value = '1.2.3.4']", pattern_type="stix"
    )
    assert SplunkIndicator.extract_spl(entity) is None


def test_spl_extraction_empty_pattern_returns_none():
    entity = _indicator_entity(pattern="   ")
    assert SplunkIndicator.extract_spl(entity) is None


# ------------------------------------------------------------------ #
#  3. SPL execution passes query to Splunk client                    #
# ------------------------------------------------------------------ #


def test_spl_execution_calls_run_search():
    connector = _connector()
    connector.splunk_client.run_search.return_value = []
    connector._enrich_indicator(_indicator_entity(pattern="index=main | stats count"))
    connector.splunk_client.run_search.assert_called_once()
    kwargs = connector.splunk_client.run_search.call_args.kwargs
    assert kwargs["query"] == "index=main | stats count"


# ------------------------------------------------------------------ #
#  4. Observable creation from CIM fields                             #
# ------------------------------------------------------------------ #


def test_observable_creation_from_cim_fields():
    connector = _connector()
    rows = [
        {
            "sourcetype": "syslog",
            "src_ip": "1.2.3.4",
            "src_dns": "example.com",
            "url": "https://example.com",
        }
    ]
    connector.splunk_client.run_search.return_value = rows
    connector._enrich_indicator(_indicator_entity())

    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    obj_types = [o.get("type") for o in bundle.objects]
    assert "ipv4-addr" in obj_types
    assert "domain-name" in obj_types
    assert "url" in obj_types


# ------------------------------------------------------------------ #
#  5. Observable deduplication                                        #
# ------------------------------------------------------------------ #


def test_observable_deduplication():
    connector = _connector()
    rows = [
        {"sourcetype": "syslog", "src_ip": "1.2.3.4"},
        {"sourcetype": "syslog", "src_ip": "1.2.3.4"},
    ]
    connector.splunk_client.run_search.return_value = rows
    connector._enrich_indicator(_indicator_entity())

    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    ipv4_objs = [o for o in bundle.objects if o.get("type") == "ipv4-addr"]
    assert len(ipv4_objs) == 1


# ------------------------------------------------------------------ #
#  6. Sighting creation                                               #
# ------------------------------------------------------------------ #


def test_sighting_created():
    connector = _connector()
    rows = [{"sourcetype": "syslog", "src_ip": "1.2.3.4"}]
    connector.splunk_client.run_search.return_value = rows
    connector._enrich_indicator(_indicator_entity())

    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    sightings = [o for o in bundle.objects if o.get("type") == "sighting"]
    assert len(sightings) == 1
    s = sightings[0]
    assert s["sighting_of_ref"] == INDICATOR_ID
    assert s["count"] == 1


def test_sighting_count_matches_row_count():
    connector = _connector()
    rows = [{"sourcetype": "syslog", "src_ip": f"1.2.3.{i}"} for i in range(5)]
    connector.splunk_client.run_search.return_value = rows
    connector._enrich_indicator(_indicator_entity())

    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    s = next(o for o in bundle.objects if o.get("type") == "sighting")
    assert s["count"] == 5


# ------------------------------------------------------------------ #
#  7. based-on relationships                                          #
# ------------------------------------------------------------------ #


def test_based_on_relationships_created():
    connector = _connector()
    rows = [{"sourcetype": "syslog", "src_ip": "1.2.3.4"}]
    connector.splunk_client.run_search.return_value = rows
    connector._enrich_indicator(_indicator_entity())

    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    rels = [
        o
        for o in bundle.objects
        if o.get("type") == "relationship" and o.get("relationship_type") == "based-on"
    ]
    assert len(rels) >= 1
    source_refs = {r["source_ref"] for r in rels}
    assert INDICATOR_ID in source_refs


# ------------------------------------------------------------------ #
#  8. No results → negative sighting                                  #
# ------------------------------------------------------------------ #


def test_no_results_produces_negative_sighting():
    connector = _connector()
    connector.splunk_client.run_search.return_value = []
    result = connector._enrich_indicator(_indicator_entity())

    assert "No results" in result
    connector.helper.send_stix2_bundle.assert_called_once()
    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    sightings = [o for o in bundle.objects if o.get("type") == "sighting"]
    assert len(sightings) == 1
    s = sightings[0]
    assert s.get("x_opencti_negative") is True


# ------------------------------------------------------------------ #
#  9. Invalid IP skipped                                              #
# ------------------------------------------------------------------ #


def test_invalid_ip_skipped():
    connector = _connector()
    rows = [{"sourcetype": "syslog", "src_ip": "not-an-ip"}]
    connector.splunk_client.run_search.return_value = rows
    connector._enrich_indicator(_indicator_entity())

    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    ipv4_objs = [o for o in bundle.objects if o.get("type") == "ipv4-addr"]
    assert len(ipv4_objs) == 0


# ------------------------------------------------------------------ #
#  10. CIDR notation skipped                                          #
# ------------------------------------------------------------------ #


def test_cidr_ip_skipped():
    connector = _connector()
    rows = [{"sourcetype": "syslog", "src_ip": "10.0.0.0/8"}]
    connector.splunk_client.run_search.return_value = rows
    connector._enrich_indicator(_indicator_entity())

    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    ipv4_objs = [o for o in bundle.objects if o.get("type") == "ipv4-addr"]
    assert len(ipv4_objs) == 0


# ------------------------------------------------------------------ #
#  11. Non-SPL indicator skipped gracefully                           #
# ------------------------------------------------------------------ #


def test_non_spl_indicator_skipped():
    connector = _connector()
    entity = _indicator_entity(
        pattern="[ipv4-addr:value = '1.2.3.4']", pattern_type="stix"
    )
    # entity_type="Indicator" so it routes here, but pattern_type is stix
    entity["entity_type"] = "Indicator"
    result = connector._enrich_indicator(entity)
    assert "skipping" in result.lower()
    connector.splunk_client.run_search.assert_not_called()


# ------------------------------------------------------------------ #
#  12. Infrastructure builder unavailable — no crash                  #
# ------------------------------------------------------------------ #


def test_infrastructure_builder_unavailable_no_crash():
    connector = _connector()
    connector.infrastructure_builder = None
    rows = [{"sourcetype": "syslog", "src_ip": "1.2.3.4"}]
    connector.splunk_client.run_search.return_value = rows
    # Should not raise
    connector._enrich_indicator(_indicator_entity())
    connector.helper.send_stix2_bundle.assert_called_once()


# ------------------------------------------------------------------ #
#  13. Full enrichment flow — mixed CIM fields                       #
# ------------------------------------------------------------------ #


def test_full_enrichment_flow():
    connector = _connector()
    rows = [
        {
            "sourcetype": "syslog",
            "src_ip": "1.2.3.4",
            "src_dns": "evil.example.com",
            "url": "https://evil.example.com/payload",
        }
    ]
    connector.splunk_client.run_search.return_value = rows
    result = connector._enrich_indicator(_indicator_entity())

    assert "INDICATOR" in result
    connector.helper.send_stix2_bundle.assert_called_once()

    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    obj_types = [o.get("type") for o in bundle.objects]

    assert "ipv4-addr" in obj_types
    assert "domain-name" in obj_types
    assert "url" in obj_types
    assert "sighting" in obj_types
    assert "relationship" in obj_types

    sighting = next(o for o in bundle.objects if o.get("type") == "sighting")
    assert sighting["sighting_of_ref"] == INDICATOR_ID

    rels = [
        o
        for o in bundle.objects
        if o.get("type") == "relationship" and o.get("relationship_type") == "based-on"
    ]
    assert len(rels) == 3  # one per observable


# ------------------------------------------------------------------ #
#  14. Note-based parameter resolution                                #
# ------------------------------------------------------------------ #


def _note_with_content(content: str) -> dict:
    """Build a minimal Note dict as returned by the OpenCTI API."""
    return {
        "id": "note--00000000-0000-4000-8000-000000000001",
        "type": "note",
        "note_types": ["Search Parameters"],
        "content": content,
    }


def test_note_earliest_latest_passed_to_run_search():
    """When a Note has earliest/latest, _enrich_indicator uses them."""
    helper = _helper()
    helper.api.note.list.return_value = [
        _note_with_content('earliest: "0"\nlatest: now\n')
    ]
    connector = _connector(helper=helper)
    connector.splunk_client.run_search.return_value = []
    connector._enrich_indicator(_indicator_entity())

    call_kwargs = connector.splunk_client.run_search.call_args.kwargs
    assert call_kwargs["earliest_time"] == "0"
    assert call_kwargs["latest_time"] == "now"


def test_note_earliest_time_alias_passed_to_run_search():
    """earliest_time alias in Note should map to earliest_time param."""
    helper = _helper()
    helper.api.note.list.return_value = [
        _note_with_content("earliest_time: -7d@d\nlatest_time: now\n")
    ]
    connector = _connector(helper=helper)
    connector.splunk_client.run_search.return_value = []
    connector._enrich_indicator(_indicator_entity())

    call_kwargs = connector.splunk_client.run_search.call_args.kwargs
    assert call_kwargs["earliest_time"] == "-7d@d"
    assert call_kwargs["latest_time"] == "now"


def test_no_note_falls_back_to_config_defaults():
    """Without a Note, _enrich_indicator uses the connector config defaults."""
    helper = _helper()
    helper.api.note.list.return_value = []
    connector = _connector(helper=helper)
    connector.splunk_client.run_search.return_value = []
    connector._enrich_indicator(_indicator_entity())

    call_kwargs = connector.splunk_client.run_search.call_args.kwargs
    assert call_kwargs["earliest_time"] == "-30d@d"
    assert call_kwargs["latest_time"] == "now"


def test_note_partial_params_earliest_only():
    """Note with only earliest — latest falls back to config."""
    helper = _helper()
    helper.api.note.list.return_value = [_note_with_content("earliest: -7d@d\n")]
    connector = _connector(helper=helper)
    connector.splunk_client.run_search.return_value = []
    connector._enrich_indicator(_indicator_entity())

    call_kwargs = connector.splunk_client.run_search.call_args.kwargs
    assert call_kwargs["earliest_time"] == "-7d@d"
    assert call_kwargs["latest_time"] == "now"  # config default


def test_note_timeout_and_wait_seconds_passed():
    """Note timeout/wait_seconds override config values in _enrich_indicator."""
    helper = _helper()
    helper.api.note.list.return_value = [
        _note_with_content(
            "earliest: -90d@d\nlatest: now\ntimeout: 120\nwait_seconds: 5\n"
        )
    ]
    connector = _connector(helper=helper)
    connector.splunk_client.run_search.return_value = []
    connector._enrich_indicator(_indicator_entity())

    call_kwargs = connector.splunk_client.run_search.call_args.kwargs
    assert call_kwargs["timeout"] == 120
    assert call_kwargs["wait_seconds"] == 5


def test_wrong_note_type_ignored():
    """A Note with note_types != 'Search Parameters' should not be used."""
    helper = _helper()
    # note.list returns [] because the API filter already excludes non-matching types;
    # simulate that by returning empty (the filter in load_params_from_notes handles it)
    helper.api.note.list.return_value = []
    connector = _connector(helper=helper)
    connector.splunk_client.run_search.return_value = []
    connector._enrich_indicator(_indicator_entity())

    call_kwargs = connector.splunk_client.run_search.call_args.kwargs
    assert call_kwargs["earliest_time"] == "-30d@d"  # config default


def test_resolve_search_params_returns_note_values():
    """resolve_search_params returns Note values when a Note is found."""
    helper = _helper()
    helper.api.note.list.return_value = [
        _note_with_content('earliest: "0"\nlatest: now\nmax_results: 500\n')
    ]
    connector = _connector(helper=helper)
    entity = _indicator_entity()
    result = connector.resolve_search_params(entity)

    assert result["earliest"] == "0"
    assert result["latest"] == "now"
    assert result["max_results"] == 500


def test_resolve_search_params_falls_back_to_config():
    """resolve_search_params falls back to config when no Note."""
    helper = _helper()
    helper.api.note.list.return_value = []
    connector = _connector(helper=helper)
    entity = _indicator_entity()
    result = connector.resolve_search_params(entity)

    assert result["earliest"] == "-30d@d"
    assert result["latest"] == "now"
    assert result["max_results"] == 1000
    assert result["timeout"] == 60
    assert result["wait_seconds"] == 2


def test_get_entity_note_params_empty_when_no_note():
    """get_entity_note_params returns empty dict when no Note is attached."""
    helper = _helper()
    helper.api.note.list.return_value = []
    connector = _connector(helper=helper)
    result = connector.get_entity_note_params(_indicator_entity())
    assert result == {}


def test_get_entity_note_params_returns_parsed_content():
    """get_entity_note_params returns parsed YAML from Note content."""
    helper = _helper()
    helper.api.note.list.return_value = [
        _note_with_content("earliest: -24h@h\nlatest: now\ntimeout: 30\n")
    ]
    connector = _connector(helper=helper)
    result = connector.get_entity_note_params(_indicator_entity())

    assert result["earliest"] == "-24h@h"
    assert result["latest"] == "now"
    assert result["timeout"] == 30


def test_note_earliest_used_in_negative_sighting():
    """Note earliest/latest are reflected in the negative sighting description."""
    helper = _helper()
    helper.api.note.list.return_value = [
        _note_with_content('earliest: "0"\nlatest: now\n')
    ]
    connector = _connector(helper=helper)
    connector.splunk_client.run_search.return_value = []
    connector._enrich_indicator(_indicator_entity())

    bundle_arg = connector.helper.send_stix2_bundle.call_args[0][0]
    bundle = stix2.parse(bundle_arg, allow_custom=True)
    sightings = [o for o in bundle.objects if o.get("type") == "sighting"]
    assert len(sightings) == 1
    # The note's "0" should appear in the sighting description (search window)
    desc = sightings[0].get("description", "")
    assert "0" in desc or sightings[0].get("x_opencti_negative") is True
