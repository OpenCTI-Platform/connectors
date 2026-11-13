"""Pydantic validation tests; require connectors-sdk installed as in production."""

import pytest
from pydantic import ValidationError

pytest.importorskip("connectors_sdk")
from src.bitdefender_import_feed.settings import BitdefenderConfig


def test_required_default_fields():
    settings = BitdefenderConfig.model_validate(
        {"api_key": "test-key", "feeds": ["ip"]}
    )
    assert settings.feeds == ["ip"]
    assert settings.detection is False
    assert settings.tlp_level == "red"


@pytest.mark.parametrize("feeds", [[], ["not-a-feed"]])
def test_empty_or_unknown_feeds_rejected(feeds):
    with pytest.raises(ValidationError):
        BitdefenderConfig.model_validate({"api_key": "test-key", "feeds": feeds})


def test_missing_feeds_rejected():
    with pytest.raises(ValidationError):
        BitdefenderConfig.model_validate({"api_key": "test-key"})


@pytest.mark.parametrize(
    "level", ["clear", "white", "green", "amber", "amber+strict", "red"]
)
def test_tlp_levels_accepted(level):
    settings = BitdefenderConfig.model_validate(
        {"api_key": "test-key", "feeds": ["ip"], "tlp_level": level}
    )
    assert settings.tlp_level == level


def test_unknown_tlp_level_rejected():
    with pytest.raises(ValidationError):
        BitdefenderConfig.model_validate(
            {"api_key": "test-key", "feeds": ["ip"], "tlp_level": "purple"}
        )


def test_malware_object_default_and_opt_out():
    enabled = BitdefenderConfig.model_validate(
        {"api_key": "test-key", "feeds": ["file"]}
    )
    disabled = BitdefenderConfig.model_validate(
        {"api_key": "test-key", "feeds": ["file"], "create_malware_objects": False}
    )
    assert enabled.create_malware_objects is True
    assert disabled.create_malware_objects is False
