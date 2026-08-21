from unittest.mock import Mock

import pytest
from pytest_mock.plugin import MockerFixture
from tweetfeed import TweetFeed

# ---------------------------------------------------------------------------
# These tests exercise TweetFeed's own configuration wiring: given env vars
# are set (the connector's real config source), does `TweetFeed.__init__`
# correctly read `ConnectorSettings` and map values onto the attributes the
# rest of the connector's code relies on, and do the connector's own methods
# that derive from those attributes (`get_interval`, `is_scheduled`) behave
# accordingly.
# ---------------------------------------------------------------------------


@pytest.fixture
def required_env(monkeypatch):
    """Minimal env vars required to build a valid `ConnectorSettings`."""
    monkeypatch.setenv("OPENCTI_URL", "http://opencti:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "test-connector-id")


@pytest.fixture
def mocked_helper_class(mocker: MockerFixture):
    """Patch the `OpenCTIConnectorHelper` used by `tweetfeed.py` so `TweetFeed()`
    can be instantiated without any real network/API calls."""
    mocked_class = mocker.patch("tweetfeed.OpenCTIConnectorHelper")
    instance = mocked_class.return_value
    instance.api = Mock()
    instance.api.external_reference.create.return_value = {
        "id": "external-reference--id"
    }
    instance.api.identity.create.return_value = {"id": "identity--id"}
    return mocked_class


class TestTweetFeedInit:
    def test_maps_env_vars_to_instance_attributes(
        self, required_env, monkeypatch, mocked_helper_class
    ):
        monkeypatch.setenv("TWEETFEED_INTERVAL", "5")
        monkeypatch.setenv("TWEETFEED_DAYS_BACK_IN_TIME", "10")
        monkeypatch.setenv("TWEETFEED_CONFIDENCE_LEVEL", "50")
        monkeypatch.setenv("TWEETFEED_CREATE_INDICATORS", "false")
        monkeypatch.setenv("TWEETFEED_CREATE_OBSERVABLES", "false")
        monkeypatch.setenv("TWEETFEED_UPDATE_EXISTING_DATA", "false")
        monkeypatch.setenv("TWEETFEED_ORG_NAME", "My Custom Org")
        monkeypatch.setenv("TWEETFEED_ORG_DESCRIPTION", "My Custom Org Description")
        monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "debug")

        connector = TweetFeed()

        assert connector.tweetfeed_interval == 5
        assert connector.tweetfeed_days_back_in_time == 10
        assert connector.score == 50
        assert connector.create_indicators is False
        assert connector.create_observables is False
        assert connector.update is False
        assert connector.org_name == "My Custom Org"
        assert connector.org_desc == "My Custom Org Description"

        # TweetFeed.__init__ must build the helper with the mapped config
        # (including the CONNECTOR_LOG_LEVEL override), since the rest of the
        # connector relies on `self.helper` being wired from `self.config`.
        _, kwargs = mocked_helper_class.call_args
        helper_config = kwargs["config"]
        assert helper_config["connector"]["log_level"] == "debug"
        assert helper_config["connector"]["name"] == "TweetFeed"

    def test_default_env_vars_are_mapped(self, required_env, mocked_helper_class):
        connector = TweetFeed()

        assert connector.tweetfeed_interval == 1
        assert connector.tweetfeed_days_back_in_time == 30
        assert connector.score == 25
        assert connector.create_indicators is True
        assert connector.create_observables is True
        assert connector.update is True

    def test_organization_created_from_configured_org_name_and_description(
        self, required_env, monkeypatch, mocked_helper_class
    ):
        monkeypatch.setenv("TWEETFEED_ORG_NAME", "My Custom Org")
        monkeypatch.setenv("TWEETFEED_ORG_DESCRIPTION", "My Custom Org Description")

        TweetFeed()

        instance = mocked_helper_class.return_value
        _, kwargs = instance.api.identity.create.call_args
        assert kwargs["name"] == "My Custom Org"
        assert kwargs["description"] == "My Custom Org Description"


class TestTweetFeedIntervalBehavior:
    """`get_interval`/`is_scheduled` are TweetFeed's own scheduling logic,
    built on top of the `TWEETFEED_INTERVAL` config value."""

    def test_get_interval_converts_configured_days_to_seconds(
        self, required_env, monkeypatch, mocked_helper_class
    ):
        monkeypatch.setenv("TWEETFEED_INTERVAL", "2")

        connector = TweetFeed()

        assert connector.get_interval() == 2 * 60 * 60 * 24

    def test_is_scheduled_true_on_first_run(self, required_env, mocked_helper_class):
        connector = TweetFeed()
        connector.helper.log_info = Mock()

        assert connector.is_scheduled(last_run=None, current_time=0) is True

    def test_is_scheduled_false_before_interval_elapsed(
        self, required_env, monkeypatch, mocked_helper_class
    ):
        monkeypatch.setenv("TWEETFEED_INTERVAL", "1")
        connector = TweetFeed()

        one_day_in_seconds = 60 * 60 * 24
        assert (
            connector.is_scheduled(last_run=0, current_time=one_day_in_seconds - 1)
            is False
        )

    def test_is_scheduled_true_after_interval_elapsed(
        self, required_env, monkeypatch, mocked_helper_class
    ):
        monkeypatch.setenv("TWEETFEED_INTERVAL", "1")
        connector = TweetFeed()

        one_day_in_seconds = 60 * 60 * 24
        assert (
            connector.is_scheduled(last_run=0, current_time=one_day_in_seconds) is True
        )
