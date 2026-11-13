"""Tests for ConnectorState checkpoint helpers."""

from __future__ import annotations

from connector.state import ConnectorState


def test_state_threat_feed_defaults():
    state = ConnectorState()
    assert state.get_next_date("malware", "") == ""
    assert state.get_threat_offset("malware") == 0


def test_state_set_and_get_threat_date():
    state = ConnectorState()
    state.set_next_date("malware", "2026-09-27")
    assert state.get_next_date("malware", "") == "2026-09-27"


def test_state_set_next_date_clears_offset():
    state = ConnectorState()
    state.set_threat_offset("malware", 5000, snapshot_date="2026-09-27")
    assert state.get_threat_offset("malware") == 5000
    # Setting a new date must clear the offset so the next run starts at 0.
    state.set_next_date("malware", "2026-09-28")
    assert state.get_threat_offset("malware") == 0
    assert state.get_threat_offset_date("malware") == ""


def test_state_set_and_get_threat_offset():
    state = ConnectorState()
    state.set_threat_offset("phishing", 12345, snapshot_date="2026-09-27")
    assert state.get_threat_offset("phishing") == 12345
    assert state.get_threat_offset_date("phishing") == "2026-09-27"


def test_state_threat_offset_cannot_go_negative():
    state = ConnectorState()
    state.set_threat_offset("spam", -100)
    assert state.get_threat_offset("spam") == 0


def test_state_nrd_defaults():
    state = ConnectorState()
    assert state.get_next_nrd_date("nrd_gtld_with_whois", "2026-01-01") == "2026-01-01"
    assert state.get_nrd_offset("nrd_gtld_with_whois") == 0


def test_state_set_and_get_nrd_date():
    state = ConnectorState()
    state.set_next_nrd_date("nrd_gtld_with_whois", "2026-09-27")
    assert state.get_next_nrd_date("nrd_gtld_with_whois", "") == "2026-09-27"


def test_state_set_nrd_date_clears_offset():
    state = ConnectorState()
    state.set_nrd_offset(
        "nrd_cctld_with_whois",
        9999,
        snapshot_date="2026-09-27",
    )
    assert state.get_nrd_offset("nrd_cctld_with_whois") == 9999
    # Setting a new date must clear the offset.
    state.set_next_nrd_date("nrd_cctld_with_whois", "2026-09-28")
    assert state.get_nrd_offset("nrd_cctld_with_whois") == 0
    assert state.get_nrd_offset_date("nrd_cctld_with_whois") == ""


def test_state_set_and_get_nrd_offset():
    state = ConnectorState()
    state.set_nrd_offset(
        "nrd_gtld_without_whois",
        42,
        snapshot_date="2026-09-27",
    )
    assert state.get_nrd_offset("nrd_gtld_without_whois") == 42
    assert state.get_nrd_offset_date("nrd_gtld_without_whois") == "2026-09-27"


def test_state_nrd_offset_cannot_go_negative():
    state = ConnectorState()
    state.set_nrd_offset("nrd_cctld_without_whois", -1)
    assert state.get_nrd_offset("nrd_cctld_without_whois") == 0


def test_state_multiple_feeds_are_independent():
    state = ConnectorState()
    state.set_next_date("malware", "2026-09-25")
    state.set_next_date("phishing", "2026-09-26")
    state.set_threat_offset("spam", 100)

    assert state.get_next_date("malware", "") == "2026-09-25"
    assert state.get_next_date("phishing", "") == "2026-09-26"
    assert state.get_next_date("spam", "") == ""
    assert state.get_threat_offset("spam") == 100
    assert state.get_threat_offset("malware") == 0


def test_state_nrd_and_threat_namespaces_do_not_collide():
    state = ConnectorState()
    state.set_next_date("malware", "2026-09-25")
    state.set_next_nrd_date("malware", "2026-10-01")  # same key, different namespace

    assert state.get_next_date("malware", "") == "2026-09-25"
    assert state.get_next_nrd_date("malware", "") == "2026-10-01"
