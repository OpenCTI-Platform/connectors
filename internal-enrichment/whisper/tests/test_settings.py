"""Tests for ``connector.settings.WhisperSettings``.

The model replaces PR #66's ``ConfigConnector`` shim with a Pydantic
``BaseSettings`` instance — issue #67. These tests pin down the four
guarantees the model has to provide:

1. Required fields raise ``ValidationError`` when missing or empty.
2. ``max_tlp`` is constrained to the canonical TLP marking strings.
3. The instance is frozen post-construction (catches "config drift"
   bugs in tests / refactors).
4. ``from_environment`` composes a YAML ``whisper:`` block with env vars,
   env vars winning.
"""

import os

import pytest
from connector.settings import WhisperSettings, load_yaml_config
from pydantic import ValidationError

# --- Field validation ------------------------------------------------------


def test_construction_succeeds_with_required_fields():
    s = WhisperSettings(api_url="https://api.whisper.test", api_key="k")
    assert s.api_url == "https://api.whisper.test"
    assert s.api_key == "k"
    # Default TLP ceiling: AMBER+STRICT — strict-by-default keeps customer
    # intel out of the Whisper API unless the operator opts in.
    assert s.max_tlp == "TLP:AMBER+STRICT"


def test_construction_strips_whitespace_per_str_strip_whitespace():
    # ``SettingsConfigDict(str_strip_whitespace=True)`` should clean up
    # accidental trailing whitespace from .env / config.yml values.
    s = WhisperSettings(api_url="  https://api.whisper.test  ", api_key="  k  ")
    assert s.api_url == "https://api.whisper.test"
    assert s.api_key == "k"


def test_construction_fails_when_api_url_missing():
    with pytest.raises(ValidationError) as exc:
        WhisperSettings(api_key="k")
    assert "api_url" in str(exc.value)


def test_construction_fails_when_api_key_missing():
    with pytest.raises(ValidationError) as exc:
        WhisperSettings(api_url="https://x")
    assert "api_key" in str(exc.value)


def test_construction_fails_when_api_url_empty():
    with pytest.raises(ValidationError):
        WhisperSettings(api_url="", api_key="k")


def test_construction_fails_when_api_key_empty():
    with pytest.raises(ValidationError):
        WhisperSettings(api_url="https://x", api_key="")


def test_construction_fails_on_invalid_max_tlp():
    # Literal[...] rejects anything outside the canonical TLP marking set.
    with pytest.raises(ValidationError) as exc:
        WhisperSettings(api_url="https://x", api_key="k", max_tlp="TLP:BANANA")
    assert "max_tlp" in str(exc.value)


@pytest.mark.parametrize(
    "tlp",
    [
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ],
)
def test_construction_accepts_every_canonical_tlp(tlp):
    s = WhisperSettings(api_url="https://x", api_key="k", max_tlp=tlp)
    assert s.max_tlp == tlp


# --- Immutability ----------------------------------------------------------


def test_settings_are_frozen_post_construction():
    # ``frozen=True`` is what stops a test from drifting the default
    # ``TLP:RED`` ceiling out from under another test sharing the same
    # fixture instance.
    s = WhisperSettings(api_url="https://x", api_key="k")
    with pytest.raises(ValidationError):
        s.max_tlp = "TLP:RED"


# --- ``extra="ignore"`` ----------------------------------------------------


def test_extra_fields_are_ignored():
    # ``model_config["extra"] == "ignore"`` is what lets a config.yml
    # whisper: block carry forward-compat keys that this connector version
    # doesn't yet understand without blowing up at startup.
    s = WhisperSettings(
        api_url="https://x",
        api_key="k",
        future_unknown_field="some_value",
    )
    assert not hasattr(s, "future_unknown_field")


# --- ``from_environment`` source priority ---------------------------------


@pytest.fixture
def clean_env(monkeypatch):
    """Clear any ``WHISPER_*`` env vars so each test starts hermetic."""
    for key in list(os.environ):
        if key.startswith("WHISPER_"):
            monkeypatch.delenv(key, raising=False)


def test_from_environment_uses_yaml_block_when_no_env(clean_env):
    s = WhisperSettings.from_environment(
        {
            "whisper": {
                "api_url": "https://from-yaml.test",
                "api_key": "yaml-key",
                "max_tlp": "TLP:GREEN",
            }
        }
    )
    assert s.api_url == "https://from-yaml.test"
    assert s.api_key == "yaml-key"
    assert s.max_tlp == "TLP:GREEN"


def test_from_environment_env_overrides_yaml(clean_env, monkeypatch):
    monkeypatch.setenv("WHISPER_API_URL", "https://from-env.test")
    monkeypatch.setenv("WHISPER_API_KEY", "env-key")
    monkeypatch.setenv("WHISPER_MAX_TLP", "TLP:RED")
    s = WhisperSettings.from_environment(
        {
            "whisper": {
                "api_url": "https://from-yaml.test",
                "api_key": "yaml-key",
                "max_tlp": "TLP:GREEN",
            }
        }
    )
    assert s.api_url == "https://from-env.test"
    assert s.api_key == "env-key"
    assert s.max_tlp == "TLP:RED"


def test_from_environment_env_only(clean_env, monkeypatch):
    monkeypatch.setenv("WHISPER_API_URL", "https://from-env.test")
    monkeypatch.setenv("WHISPER_API_KEY", "env-key")
    s = WhisperSettings.from_environment({})
    assert s.api_url == "https://from-env.test"
    assert s.api_key == "env-key"
    assert s.max_tlp == "TLP:AMBER+STRICT"  # default


def test_from_environment_none_yaml_no_env_raises(clean_env):
    # No YAML AND no env vars → required fields are missing.
    with pytest.raises(ValidationError):
        WhisperSettings.from_environment(None)


# --- ``load_yaml_config`` helper ------------------------------------------


def test_load_yaml_config_returns_empty_when_file_missing(tmp_path):
    missing = tmp_path / "does-not-exist.yml"
    assert load_yaml_config(missing) == {}


def test_load_yaml_config_parses_existing_file(tmp_path):
    yaml_file = tmp_path / "config.yml"
    yaml_file.write_text(
        "whisper:\n"
        "  api_url: https://from-disk.test\n"
        "  api_key: disk-key\n"
        "  max_tlp: TLP:AMBER\n"
        "opencti:\n"
        "  url: http://opencti:8080\n"
    )
    loaded = load_yaml_config(yaml_file)
    assert loaded["whisper"]["api_url"] == "https://from-disk.test"
    assert loaded["opencti"]["url"] == "http://opencti:8080"


def test_load_yaml_config_handles_empty_file_gracefully(tmp_path):
    yaml_file = tmp_path / "config.yml"
    yaml_file.write_text("")
    assert load_yaml_config(yaml_file) == {}
