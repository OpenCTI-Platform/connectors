from unittest.mock import MagicMock, patch

import pytest
import requests
from connectors_sdk import (
    ApiForbiddenError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from malpedia_connector import MalpediaConnector
from malpedia_connector.connector import (
    API_KEY_CHECK_ATTEMPTS,
    API_KEY_CHECK_RETRY_DELAY,
)
from malpedia_services import MalpediaClient

FAMILY_NAME = "win.test"
FAMILIES = {
    FAMILY_NAME: {
        "updated": "2024-01-01",
        "library_entries": [],
        "attribution": ["APT Test"],
        "description": "Test family",
        "notes": [],
        "alt_names": [],
        "sources": [],
        "urls": [],
        "common_name": "Test",
        "uuid": "4d2b3fb1-36e9-4b3c-9d4f-9c3b0d0a5a11",
    }
}
NETWORK_ERROR = requests.exceptions.ProxyError("Unable to connect to proxy")


def make_config(auth_key: str | None = "test-api-key") -> MagicMock:
    """Build a connector config with every import enabled."""
    config = MagicMock()
    if auth_key is None:
        config.malpedia.auth_key = None
    else:
        config.malpedia.auth_key.get_secret_value.return_value = auth_key
    config.malpedia.default_marking = "TLP:AMBER"
    config.malpedia.import_yara = True
    config.malpedia.import_intrusion_sets = True
    config.malpedia.create_indicators = True
    config.malpedia.create_observables = True
    config.connector.duration_period.total_seconds.return_value = 300
    return config


def warning_messages(helper: MagicMock) -> list[str]:
    """Return the messages of the warnings the connector logged."""
    return [c.args[0] for c in helper.connector_logger.warning.call_args_list]


class TestConnectorStartup:

    def test_no_api_key_skips_check(self):
        with patch.object(MalpediaClient, "check_api_key") as mock_check:
            connector = MalpediaConnector(config=make_config(None), helper=MagicMock())

        mock_check.assert_not_called()
        assert connector.api_client.unauthenticated is True

    def test_valid_api_key(self):
        with patch.object(MalpediaClient, "check_api_key") as mock_check:
            connector = MalpediaConnector(config=make_config(), helper=MagicMock())

        mock_check.assert_called_once()
        assert connector.api_client.unauthenticated is False

    def test_rejected_api_key_stops_connector(self):
        with patch.object(
            MalpediaClient,
            "check_api_key",
            side_effect=ApiForbiddenError("Forbidden (403)"),
        ) as mock_check:
            with pytest.raises(ApiForbiddenError, match="token is invalid"):
                MalpediaConnector(config=make_config(), helper=MagicMock())

        mock_check.assert_called_once()

    @pytest.mark.parametrize(
        "error",
        [
            NETWORK_ERROR,
            requests.exceptions.ConnectTimeout("Connection timed out"),
            ApiServerError("Server error (502)"),
            ApiRateLimitError("Rate limited (429)"),
        ],
        ids=["--Proxy", "--Timeout", "--Server", "--RateLimit"],
    )
    def test_unreachable_api_retries_then_starts(self, error):
        helper = MagicMock()
        with (
            patch.object(
                MalpediaClient, "check_api_key", side_effect=[error, error, None]
            ) as mock_check,
            patch("malpedia_connector.connector.time.sleep") as mock_sleep,
        ):
            MalpediaConnector(config=make_config(), helper=helper)

        assert mock_check.call_count == 3
        assert mock_sleep.call_count == 2
        mock_sleep.assert_called_with(API_KEY_CHECK_RETRY_DELAY)
        assert (
            warning_messages(helper)
            == ["[API] Could not reach the Malpedia API to check the API key, retrying"]
            * 2
        )

    def test_unreachable_api_stops_after_last_try(self):
        with (
            patch.object(
                MalpediaClient, "check_api_key", side_effect=NETWORK_ERROR
            ) as mock_check,
            patch("malpedia_connector.connector.time.sleep") as mock_sleep,
        ):
            with pytest.raises(DataRetrievalError, match="Could not reach") as exc:
                MalpediaConnector(config=make_config(), helper=MagicMock())

        assert mock_check.call_count == API_KEY_CHECK_ATTEMPTS
        assert mock_sleep.call_count == API_KEY_CHECK_ATTEMPTS - 1
        assert exc.value.__cause__ is NETWORK_ERROR

    def test_rejected_api_key_after_network_error_is_not_retried(self):
        with (
            patch.object(
                MalpediaClient,
                "check_api_key",
                side_effect=[NETWORK_ERROR, ApiForbiddenError("Forbidden (403)")],
            ) as mock_check,
            patch("malpedia_connector.connector.time.sleep"),
        ):
            with pytest.raises(ApiForbiddenError, match="token is invalid"):
                MalpediaConnector(config=make_config(), helper=MagicMock())

        assert mock_check.call_count == 2


class TestProcessFamilies:

    @pytest.fixture
    def helper(self):
        helper = MagicMock()
        helper.connect_name = "Malpedia"
        return helper

    @pytest.fixture
    def connector(self, helper):
        with patch.object(MalpediaClient, "check_api_key"):
            connector = MalpediaConnector(config=make_config(), helper=helper)
        # The run creates the author before it processes the families.
        connector.converter.generate_malpedia_stix_identity()
        client = MagicMock(spec=MalpediaClient)
        client.unauthenticated = False
        client.get_families.return_value = FAMILIES
        client.get_yara_rules.return_value = {}
        client.get_samples.return_value = []
        client.get_actor.side_effect = ApiNotFoundError("Not found (404)")
        connector.api_client = client
        return connector

    def malware_names(self, connector) -> list[str]:
        return [o.name for o in connector.stix_objects if o.type == "malware"]

    def test_families_error_stops_run(self, connector):
        connector.api_client.get_families.side_effect = NETWORK_ERROR

        with pytest.raises(requests.exceptions.ProxyError):
            connector._process_families()

    @pytest.mark.parametrize(
        "error",
        [NETWORK_ERROR, ApiServerError("Server error (500)")],
        ids=["--Network", "--Server"],
    )
    def test_yara_error_skips_yara_only(self, connector, helper, error):
        connector.api_client.get_yara_rules.side_effect = error

        connector._process_families()

        assert self.malware_names(connector) == ["Test"]
        connector.api_client.get_samples.assert_called_once_with(FAMILY_NAME)
        connector.api_client.get_actor.assert_called_once()
        assert warning_messages(helper) == [
            "[API] Could not get family data from Malpedia, skipping it"
        ]
        helper.metric.inc.assert_any_call("error_count")

    def test_yara_not_found_is_not_an_error(self, connector, helper):
        connector.api_client.get_yara_rules.side_effect = ApiNotFoundError(
            "Not found (404)"
        )

        connector._process_families()

        assert self.malware_names(connector) == ["Test"]
        helper.connector_logger.warning.assert_not_called()

    def test_yara_rules_are_imported(self, connector):
        connector.api_client.get_yara_rules.return_value = {
            "tlp_white": {"rule.yar": "rule test { condition: true }"}
        }

        connector._process_families()

        indicators = [o for o in connector.stix_objects if o.type == "indicator"]
        assert [i.pattern_type for i in indicators] == ["yara"]

    def test_samples_error_skips_samples_only(self, connector, helper):
        connector.api_client.get_samples.side_effect = NETWORK_ERROR

        connector._process_families()

        assert self.malware_names(connector) == ["Test"]
        connector.api_client.get_actor.assert_called_once()
        assert warning_messages(helper) == [
            "[API] Could not get family data from Malpedia, skipping it"
        ]

    def test_unknown_actor_is_skipped(self, connector, helper):
        connector._process_families()

        connector.api_client.get_actor.assert_called_once_with("apt_test")
        assert not [o for o in connector.stix_objects if o.type == "intrusion-set"]
        helper.connector_logger.warning.assert_not_called()

    def test_actor_error_skips_actor(self, connector, helper):
        connector.api_client.get_actor.side_effect = NETWORK_ERROR

        connector._process_families()

        assert self.malware_names(connector) == ["Test"]
        assert warning_messages(helper) == [
            "[API] Could not get the actor from Malpedia, skipping it"
        ]
        helper.metric.inc.assert_any_call("client_error_count")
