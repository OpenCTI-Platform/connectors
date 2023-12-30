import logging

import pytest
from intelfinder.api import Intelfinder
from intelfinder.tests.constants import generate_random_key, load_fixture
from intelfinder.utils import create_author, get_cursor_id, get_tlp_marking
from pycti import CustomObjectCaseIncident, CustomObjectTask
from stix2 import URL, DomainName, IPv4Address, IPv6Address, Note

LOGGER = logging.getLogger(__name__)
DEFAULT_TLP = "TLP:WHITE"
DEFAULT_LABELS = ["intelfinder", "osint"]
AUTHOR = create_author()


def validate_stix_objects(stix_objects, stix_object_type_list):
    """Validate that the STIX objects are of the correct type."""
    # # Tested types
    type_list = list(stix_object_type_list)
    pop_list = list(stix_object_type_list)

    # Test that all objects are of the correct type
    for stix_obj in stix_objects:
        LOGGER.info(f"Testing STIX object: {stix_obj}")
        assert type(stix_obj) in type_list
        if type(stix_obj) in pop_list:
            LOGGER.info(f"Removing STIX object: {type(stix_obj)}")
            pop_list.pop(pop_list.index(type(stix_obj)))
        assert stix_obj.object_marking_refs
        if stix_obj.object_marking_refs:
            assert (
                get_tlp_marking(DEFAULT_TLP).get("id")
                is stix_obj.object_marking_refs[0]
            )
    assert pop_list == []


@pytest.fixture
def client():
    """Create a RecordedFutureClient instance with a mock token."""
    # Use a mock token for testing
    return Intelfinder(
        author=AUTHOR,
        api_key=generate_random_key(),
        labels=DEFAULT_LABELS,
        object_marking_refs=DEFAULT_TLP,
        rate_limit=1,
    )


@pytest.fixture
def error_frequency():
    """Return error when rate limit is hit."""
    return load_fixture("response_request_frequency.json")


@pytest.fixture
def alert():
    """Return a single alert for domain hijacking."""
    return load_fixture("response_domain_hijacking.json")


@pytest.fixture
def alerts_multiple():
    """Return multiple alerts for domain hijacking."""
    return load_fixture("response_alerts_multiple.json")


@pytest.fixture
def empty():
    """Return empty response."""
    return load_fixture("reponse_empty.json")


class TestIntelfinder:
    """Class to support tests for IntelFinder API."""

    def test_init(self, client):
        """Test that the client is initialized with a valid token."""
        assert client.alerts_post_data.get("key") is not None

    def test_invalid_token(self):
        """Test that an invalid token raises an error."""
        with pytest.raises(ValueError):
            Intelfinder(author=AUTHOR, api_key="invalid")

    def test_get_alerts(self, client: Intelfinder, alert, mocker):
        """Test that a valid alert is returned."""
        mocker.patch.object(client, "_request_data", return_value=alert)
        alerts = client.get_alerts()
        assert alerts == alert.get("alerts")
        assert not client.has_next
        assert client.get_index() == 8

    def test_get_stix_objects(self, client: Intelfinder, alert, mocker):
        """Test that a valid alert is returned."""
        mocker.patch.object(client, "_request_data", return_value=alert)
        stix_objects = client.get_stix_objects()
        assert stix_objects
        assert len(stix_objects) == 54
        stix_object_type_list = [
            Note,
            IPv4Address,
            IPv6Address,
            DomainName,
            CustomObjectCaseIncident,
            CustomObjectTask,
            URL,
        ]
        validate_stix_objects(stix_objects, stix_object_type_list)
        client.get_cursor() == get_cursor_id(alert["alerts"][-1])
        assert client.get_index() == 8

    def test_get_alerts_multiple(self, client: Intelfinder, alerts_multiple, mocker):
        """Test that multiple alerts are handled."""
        mocker.patch.object(client, "_request_data", return_value=alerts_multiple)
        alerts = client.get_alerts()
        assert alerts == alerts_multiple.get("alerts")
        assert client.has_next
        assert client.get_index() == 20

    def test_get_alerts_rate_limit(
        self, client: Intelfinder, error_frequency, alert, mocker
    ):
        """Test that a rate limit error is handled."""
        mocker.patch.object(
            client, "_request_data", side_effect=[error_frequency, alert]
        )
        alerts = client.get_alerts()
        assert alerts == alert.get("alerts")
        assert not client.has_next
        assert client.get_index() == 8

    def test_get_alerts_rate_limit_empty(
        self, client: Intelfinder, error_frequency, empty, mocker
    ):
        """Test that a rate limit error is handled."""
        mocker.patch.object(
            client, "_request_data", side_effect=[error_frequency, empty]
        )
        alerts = client.get_alerts()
        assert alerts == []
        assert not client.has_next
        assert client.get_index() == 0

    def test_get_alerts_empty(self, client: Intelfinder, empty, mocker):
        """Test that an empty response is handled."""
        mocker.patch.object(client, "_request_data", return_value=empty)
        alerts = client.get_alerts()
        assert alerts == []
        assert not client.has_next
        assert client.get_index() == 0

    def test_get_alerts_invalid(self, client: Intelfinder, mocker):
        """Test that an invalid response is handled."""
        mocker.patch.object(
            client, "_request_data", return_value={"code": 1, "error": "Invalid"}
        )
        with pytest.raises(Exception):
            client.get_alerts()
        assert client.has_next

    def test_get_alerts_invalid_code(self, client: Intelfinder, mocker):
        """Test that an invalid response code is handled."""
        mocker.patch.object(
            client, "_request_data", return_value={"code": 100, "error": "Invalid"}
        )
        with pytest.raises(Exception):
            client.get_alerts()
        assert client.has_next
