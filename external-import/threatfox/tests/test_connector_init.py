"""Tests for ThreatFox.__init__().

__init__ talks to a live OpenCTI instance (OpenCTIConnectorHelper construction,
identity creation), so OpenCTIConnectorHelper is monkeypatched to a stand-in
that only implements the bits __init__ actually uses: api.identity.create().
"""

from unittest.mock import MagicMock

from src.__main__ import ThreatFox


def _make_fake_helper_class():
    fake_helper = MagicMock()
    fake_helper.api.identity.create.return_value = {
        "id": "identity--internal-0000-0000-000000000000",
        "standard_id": "identity--d7f1c1a0-0000-4000-8000-000000000000",
    }
    return MagicMock(return_value=fake_helper)


def test_init_builds_score_override_by_type_from_config(minimal_env, monkeypatch):
    monkeypatch.setenv("THREATFOX_X_OPENCTI_SCORE_IP", "90")
    monkeypatch.setenv("THREATFOX_X_OPENCTI_SCORE_DOMAIN", "80")
    monkeypatch.setenv("THREATFOX_X_OPENCTI_SCORE_URL", "70")
    monkeypatch.setenv("THREATFOX_X_OPENCTI_SCORE_HASH", "60")
    monkeypatch.setattr(
        "src.__main__.OpenCTIConnectorHelper", _make_fake_helper_class()
    )

    connector = ThreatFox()

    assert connector._score_override_by_type == {
        "ip:port": 90,
        "domain": 80,
        "url": 70,
        "md5_hash": 60,
        "sha1_hash": 60,
        "sha256_hash": 60,
    }


def test_init_score_overrides_default_to_none_when_unset(minimal_env, monkeypatch):
    monkeypatch.setattr(
        "src.__main__.OpenCTIConnectorHelper", _make_fake_helper_class()
    )

    connector = ThreatFox()

    assert all(v is None for v in connector._score_override_by_type.values())


def test_init_ioc_to_import_defaults_to_all_types(minimal_env, monkeypatch):
    monkeypatch.setattr(
        "src.__main__.OpenCTIConnectorHelper", _make_fake_helper_class()
    )

    connector = ThreatFox()

    assert connector.ioc_to_import == ["all_types"]


def test_init_ioc_to_import_parses_comma_separated_list(minimal_env, monkeypatch):
    monkeypatch.setenv("THREATFOX_IOC_TO_IMPORT", "ip:port, domain ,url")
    monkeypatch.setattr(
        "src.__main__.OpenCTIConnectorHelper", _make_fake_helper_class()
    )

    connector = ThreatFox()

    assert connector.ioc_to_import == ["ip:port", "domain", "url"]


def test_init_uses_standard_id_for_identity_id(minimal_env, monkeypatch):
    monkeypatch.setattr(
        "src.__main__.OpenCTIConnectorHelper", _make_fake_helper_class()
    )

    connector = ThreatFox()

    assert connector.identity_id == "identity--d7f1c1a0-0000-4000-8000-000000000000"
