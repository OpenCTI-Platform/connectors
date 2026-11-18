"""Module to test the startup logging of the connector entry point."""

import logging
from os import environ as os_environ
from uuid import uuid4

import pytest
from connector.__main__ import load_conf

from tests.conftest import mock_env_vars


def test_load_conf_should_log_the_gti_configuration_error_message(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that the startup log names the invalid option and its allowed values."""
    # Given the real logging methods: the autouse `patch_logger_for_tests` fixture
    # renders a dict argument into the message, which the real logger never does
    monkeypatch.undo()
    # And a configuration with a sub-entity that malware families do not support
    mock_env = mock_env_vars(
        os_environ,
        {
            "OPENCTI_URL": "http://fake:8080/",
            "OPENCTI_TOKEN": f"{uuid4()}",
            "CONNECTOR_ID": f"{uuid4()}",
            "GTI_API_KEY": f"{uuid4()}",
            "GTI_MALWARE_FAMILY_SUBENTITIES": "threat_actor",
        },
    )

    # When the configuration is loaded at startup
    with caplog.at_level(logging.ERROR, logger="connector.__main__"):
        load_conf()
    mock_env.stop()

    # Then the error log carries the GTIConfigurationError message
    assert caplog.messages == [  # noqa: S101
        "Failed to load GTI configuration: Invalid malware family subentity: "
        "threat_actor. Allowed values: threat_actors, attack_techniques, "
        "vulnerabilities."
    ]
