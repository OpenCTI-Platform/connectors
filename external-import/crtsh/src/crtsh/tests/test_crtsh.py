import json
import os
from datetime import datetime

import pytest

# import crtsh core api to test
from crtsh.core.crtsh import CrtSHClient
from crtsh.core.crtsh_utils import configure_logger
from stix2 import TLP_WHITE, DomainName, EmailAddress, Relationship, X509Certificate

LOGGER = configure_logger(__name__)
DEFAULT_LABEL = "crt_sh"
DEFAULT_MARKING_DEFINITION = "TLP:WHITE"
DEFAULT_DOMAIN = "example.com"
INVALID_DOMAIN = "invalid_domain_string"
DEFAULT_CERTIFICATE_STIX = X509Certificate(
    type="x509-certificate", issuer=DEFAULT_DOMAIN
)
DEFAULT_DOMAIN_STIX = DomainName(value=DEFAULT_DOMAIN)


def convert_to_datetime(date_str):
    """Convert a date string to a datetime object."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
    except ValueError as e:
        LOGGER.error(f"Error converting date string: {date_str}:\n{e}")
        return None
    except TypeError as e:
        LOGGER.error(f"Error converting date string: {date_str}:\n{e}")
        return None
    except Exception as e:
        LOGGER.error(f"Error converting date string: {date_str}:\n{e}")
        return None


def load_fixture(filename):
    """Load a fixture file and return its content."""
    filepath = os.path.join(os.path.dirname(__file__), "fixtures", filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fixture {filename} not found.")
    with open(filepath, "r") as file:
        content = file.read()
        if not content.strip():
            raise ValueError(f"Fixture {filename} is empty.")
        return json.loads(content)


@pytest.fixture
def client():
    """Create a CrtSHClient instance with default parameters."""
    return CrtSHClient(
        marking_refs=DEFAULT_MARKING_DEFINITION,
        labels=DEFAULT_LABEL,
        domain=DEFAULT_DOMAIN,
        is_expired=False,
        is_wildcard=False,
    )


@pytest.fixture
def client_wildcard():
    """Create a CrtSHClient instance with default parameters."""
    return CrtSHClient(
        marking_refs=DEFAULT_MARKING_DEFINITION,
        labels=DEFAULT_LABEL,
        domain=DEFAULT_DOMAIN,
        is_expired=False,
        is_wildcard=True,
    )


@pytest.fixture
def client_expired():
    """Create a CrtSHClient instance with default parameters."""
    return CrtSHClient(
        marking_refs=DEFAULT_MARKING_DEFINITION,
        labels=DEFAULT_LABEL,
        domain=DEFAULT_DOMAIN,
        is_expired=True,
        is_wildcard=False,
    )


@pytest.fixture
def client_wildcard_expired():
    """Create a CrtSHClient instance with default parameters."""
    return CrtSHClient(
        marking_refs=DEFAULT_MARKING_DEFINITION,
        labels=DEFAULT_LABEL,
        domain=DEFAULT_DOMAIN,
        is_expired=True,
        is_wildcard=True,
    )


class TestCrtSHClient:
    def test_invalid_domain(self):
        """Test initialization with an invalid domain."""
        with pytest.raises(ValueError, match="Domain provided failed validation"):
            CrtSHClient(
                marking_refs=DEFAULT_MARKING_DEFINITION,
                labels=DEFAULT_LABEL,
                domain=INVALID_DOMAIN,
                is_expired=False,
                is_wildcard=False,
            )

    def test_request_data_success(self, client: CrtSHClient, mocker):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        # for all iterations in the loop.
        mock_request = mocker.patch.object(client, "_request_data")
        FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}.json")
        mock_request.return_value = (
            FIXTURE_RESPONSE  # Set the return value for this iteration
        )
        result = client._request_data()
        assert result == FIXTURE_RESPONSE

    def test_request_data_success_wildcard(self, client_wildcard: CrtSHClient, mocker):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        # for all iterations in the loop.
        mock_request = mocker.patch.object(client_wildcard, "_request_data")
        FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}_wildcard.json")
        mock_request.return_value = (
            FIXTURE_RESPONSE  # Set the return value for this iteration
        )
        result = client_wildcard._request_data()
        assert result == FIXTURE_RESPONSE

    def test_request_data_success_expired(self, client_expired: CrtSHClient, mocker):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        # for all iterations in the loop.
        mock_request = mocker.patch.object(client_expired, "_request_data")
        FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}_expired.json")
        mock_request.return_value = (
            FIXTURE_RESPONSE  # Set the return value for this iteration
        )
        result = client_expired._request_data()
        assert result == FIXTURE_RESPONSE

    def test_request_data_success_wildcard_expired(
        self, client_wildcard_expired: CrtSHClient, mocker
    ):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        # for all iterations in the loop.
        mock_request = mocker.patch.object(client_wildcard_expired, "_request_data")
        FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}_wildcard_expired.json")
        mock_request.return_value = (
            FIXTURE_RESPONSE  # Set the return value for this iteration
        )
        result = client_wildcard_expired._request_data()
        assert result == FIXTURE_RESPONSE

    # def test_get_response(self, client: CrtSHClient, mocker):
    #     """Test fetching data with an invalid dataset key."""
    #     FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}.json")
    #     mocker.patch.object(client, "_request_data", return_value=FIXTURE_RESPONSE)
    #     result = client.get_response()
    #     assert result == FIXTURE_RESPONSE

    # def test_get_response_wildcard(self, client_wildcard: CrtSHClient, mocker):
    #     """Test fetching data with an invalid dataset key."""
    #     FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}_wildcard.json")
    #     mocker.patch.object(
    #         client_wildcard, "_request_data", return_value=FIXTURE_RESPONSE
    #     )
    #     result = client_wildcard.get_response()
    #     assert result == FIXTURE_RESPONSE

    # def test_get_response_expired(self, client_expired: CrtSHClient, mocker):
    #     """Test fetching data with an invalid dataset key."""
    #     FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}_expired.json")
    #     mocker.patch.object(
    #         client_expired, "_request_data", return_value=FIXTURE_RESPONSE
    #     )
    #     result = client_expired.get_response()
    #     assert result == FIXTURE_RESPONSE

    # def test_get_response_wildcard_expired(
    #     self, client_wildcard_expired: CrtSHClient, mocker
    # ):
    #     """Test fetching data with an invalid dataset key."""
    #     FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}_wildcard_expired.json")
    #     mocker.patch.object(
    #         client_wildcard_expired, "_request_data", return_value=FIXTURE_RESPONSE
    #     )
    #     result = client_wildcard_expired.get_response()
    #     assert result == FIXTURE_RESPONSE

    def test_process_certificate(self, client: CrtSHClient, mocker):
        """Test processing a certificate."""
        FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}.json")
        mocker.patch.object(client, "_request_data", return_value=FIXTURE_RESPONSE)
        stix_object = []
        result = client.process_certificate(FIXTURE_RESPONSE[0], stix_object)
        assert result is not None
        assert isinstance(stix_object[0], X509Certificate)
        assert stix_object[0].type == "x509-certificate"
        assert (
            stix_object[0].issuer
            == "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1"
        )
        assert stix_object[0].validity_not_before == convert_to_datetime(
            "2023-01-13T00:00:00"
        )
        assert stix_object[0].validity_not_after == convert_to_datetime(
            "2024-02-13T23:59:59"
        )
        assert stix_object[0].subject == "www.example.org"
        assert stix_object[0].serial_number == "0c1fcb184518c7e3866741236d6b73f1"
        assert stix_object[0].labels == [DEFAULT_LABEL]
        assert stix_object[0].object_marking_refs == [TLP_WHITE.id]

    def test_invalid_process_certificate(self, client: CrtSHClient, mocker):
        """Test processing a certificate."""
        FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}.json")
        mocker.patch.object(client, "_request_data", return_value=FIXTURE_RESPONSE)
        stix_object = []
        result = client.process_certificate({}, stix_object)
        assert result is None
        assert len(stix_object) == 0
        result = client.process_certificate({"issuer": []}, stix_object)
        assert result is None
        assert len(stix_object) == 0
        result = client.process_certificate(None, stix_object)
        assert result is None
        result = client.process_certificate("", stix_object)
        assert result is None
        result = client.process_certificate([], stix_object)
        assert result is None
        result = client.process_certificate(0, stix_object)
        assert result is None
        result = client.process_certificate("test", stix_object)
        assert result is None
        result = client.process_certificate(FIXTURE_RESPONSE[0], None)
        assert result is None
        result = client.process_certificate(FIXTURE_RESPONSE[0], "")
        assert result is None
        result = client.process_certificate(FIXTURE_RESPONSE[0], 0)
        assert result is None
        result = client.process_certificate(FIXTURE_RESPONSE[0], "test")
        assert result is None

    def test_process_domain_name(self, client: CrtSHClient):
        """Test processing a domain name."""
        result = client.process_domain_name(DEFAULT_DOMAIN)
        assert result is not None
        assert isinstance(result, DomainName)
        assert result.type == "domain-name"
        assert result.value == DEFAULT_DOMAIN
        assert result.labels == [DEFAULT_LABEL]
        assert result.object_marking_refs == [TLP_WHITE.id]

    def test_process_domain_name_wildcard(self, client: CrtSHClient):
        """Test processing a domain name."""
        result = client.process_domain_name(f"*.{DEFAULT_DOMAIN}")
        assert result is not None
        assert isinstance(result, DomainName)
        assert result.type == "domain-name"
        assert result.value == DEFAULT_DOMAIN
        assert result.labels == [DEFAULT_LABEL]
        assert result.object_marking_refs == [TLP_WHITE.id]

    def test_invalid_process_domain_name(self, client: CrtSHClient):
        """Test processing a domain name."""
        result = client.process_domain_name(None)
        assert result is None
        result = client.process_domain_name("")
        assert result is None
        result = client.process_domain_name(0)
        assert result is None
        result = client.process_domain_name("test")
        assert result is None
        result = client.process_domain_name([])
        assert result is None
        result = client.process_domain_name({})
        assert result is None

    def test_process_email_address(self, client: CrtSHClient):
        """Test processing an email address."""
        result = client.process_email_address("test@email.com")
        assert result is not None
        assert isinstance(result, EmailAddress)
        assert result.type == "email-addr"
        assert result.value == "test@email.com"
        assert result.labels == [DEFAULT_LABEL]
        assert result.object_marking_refs == [TLP_WHITE.id]

    def test_invalid_process_email_address(self, client: CrtSHClient):
        """Test processing an email address."""
        result = client.process_email_address(None)
        assert result is None
        result = client.process_email_address("")
        assert result is None
        result = client.process_email_address(0)
        assert result is None
        result = client.process_email_address("test")
        assert result is None
        result = client.process_email_address([])
        assert result is None
        result = client.process_email_address({})
        assert result is None

    def test_stix_relationship(self, client: CrtSHClient):
        """Test creating a STIX relationship."""
        relationship = client.stix_relationship(
            DEFAULT_DOMAIN_STIX.id, DEFAULT_CERTIFICATE_STIX.id
        )
        assert relationship is not None
        assert isinstance(relationship, Relationship)

    def test_invalid_stix_relationship(self, client: CrtSHClient):
        """Test invalid input for creating a STIX relationship."""
        relationship = client.stix_relationship(None, None)
        assert relationship is None

    # def test_process_name_value(self, client: CrtSHClient, mocker):
    #     """Test processing a name value."""
    #     TEST_ITEM = {
    #         "issuer_ca_id": -1,
    #         "issuer_name": "Issuer Not Found",
    #         "common_name": "example.com",
    #         "name_value": "example.com\nuser@example.com",
    #         "id": 8506962125,
    #         "entry_timestamp": None,
    #         "not_before": "2023-01-27T01:21:18",
    #         "not_after": "2033-01-24T01:21:18",
    #         "serial_number": "1ac1e693c87d36563a92ca145c87bbc26fd49f4c",
    #     }
    #     stix_object = []
    #     client.process_name_value(TEST_ITEM, stix_object, DEFAULT_CERTIFICATE_STIX.id)
    #     assert len(stix_object) == 2
    #     assert isinstance(stix_object[0], DomainName)
    #     assert isinstance(stix_object[1], EmailAddress)

    def test_invalid_process_name_value(self, client: CrtSHClient, mocker):
        """Test processing a name value."""
        FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}.json")
        mocker.patch.object(client, "_request_data", return_value=FIXTURE_RESPONSE)
        stix_object = []
        result = client.process_name_value({}, stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert result is None
        assert len(stix_object) == 0
        result = client.process_name_value(
            None, stix_object, DEFAULT_CERTIFICATE_STIX.id
        )
        assert result is None
        assert len(stix_object) == 0
        result = client.process_name_value("", stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert result is None
        assert len(stix_object) == 0
        result = client.process_name_value(0, stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert result is None
        assert len(stix_object) == 0
        result = client.process_name_value(
            "test", stix_object, DEFAULT_CERTIFICATE_STIX.id
        )
        assert result is None
        assert len(stix_object) == 0
        result = client.process_name_value([], stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert result is None
        assert len(stix_object) == 0
        result = client.process_name_value(
            FIXTURE_RESPONSE[0], None, DEFAULT_CERTIFICATE_STIX.id
        )
        assert result is None
        result = client.process_name_value(
            FIXTURE_RESPONSE[0], "", DEFAULT_CERTIFICATE_STIX.id
        )
        assert result is None
        result = client.process_name_value(
            FIXTURE_RESPONSE[0], 0, DEFAULT_CERTIFICATE_STIX.id
        )
        assert result is None
        result = client.process_name_value(
            FIXTURE_RESPONSE[0], "test", DEFAULT_CERTIFICATE_STIX.id
        )
        assert result is None
        result = client.process_name_value(
            FIXTURE_RESPONSE[0], [], DEFAULT_CERTIFICATE_STIX.id
        )
        assert result is None
        result = client.process_name_value(
            FIXTURE_RESPONSE[0], {}, DEFAULT_CERTIFICATE_STIX.id
        )
        assert result is None
        result = client.process_name_value(FIXTURE_RESPONSE[0], stix_object, None)
        assert result is None
        assert len(stix_object) == 0
        result = client.process_name_value(FIXTURE_RESPONSE[0], stix_object, "")
        assert result is None
        assert len(stix_object) == 0

    # def test_process_common_name(self, client: CrtSHClient, mocker):
    #     """Test processing a common name."""
    #     TEST_ITEM = {
    #         "issuer_ca_id": -1,
    #         "issuer_name": "Issuer Not Found",
    #         "common_name": "example.com",
    #         "name_value": "example.com\ntest@example.com",
    #     }
    #     stix_object = []
    #     client.process_common_name(TEST_ITEM, stix_object, DEFAULT_CERTIFICATE_STIX.id)
    #     assert len(stix_object) == 1
    #     assert isinstance(stix_object[0], DomainName)

    def test_invalid_process_common_name(self, client: CrtSHClient, mocker):
        """Test processing a common name."""
        TEST_ITEM = {
            "issuer_ca_id": -1,
            "issuer_name": "Issuer Not Found",
            "common_name": "example.com",
            "name_value": "example.com",
        }
        stix_object = []
        client.process_common_name({}, stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name(None, stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name("", stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name(0, stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name("test", stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name([], stix_object, DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name(TEST_ITEM, None, DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name(TEST_ITEM, "", DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name(TEST_ITEM, 0, DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name(TEST_ITEM, "test", DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name(TEST_ITEM, [], DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name(TEST_ITEM, {}, DEFAULT_CERTIFICATE_STIX.id)
        assert len(stix_object) == 0
        client.process_common_name(TEST_ITEM, stix_object, None)
        assert len(stix_object) == 0
        client.process_common_name(TEST_ITEM, stix_object, "")
        assert len(stix_object) == 0

    # def test_get_stix_objects(self, client: CrtSHClient, mocker):
    #     """Test fetching STIX objects."""
    #     FIXTURE_RESPONSE = load_fixture(f"{DEFAULT_DOMAIN}.json")
    #     mocker.patch.object(client, "_request_data", return_value=FIXTURE_RESPONSE)
    #     result = client.get_stix_objects()
    #     assert result is not None
    #     assert isinstance(result, list)
    #     assert len(result) == 76
    #     # Check that all items in list are STIX objects
    #     for item in result:
    #         assert (
    #             isinstance(item, X509Certificate)
    #             or isinstance(item, DomainName)
    #             or isinstance(item, EmailAddress)
    #             or isinstance(item, Relationship)
    #         )
    #     # Validate all STIX objects are unique
    #     uniq_stix_objects = []
    #     for item in result:
    #         if item not in uniq_stix_objects:
    #             uniq_stix_objects.append(item)
    #     assert len(uniq_stix_objects) == len(result)
    #     # Validate that all STIX objects have the correct labels and marking definitions
    #     for item in uniq_stix_objects:
    #         assert item.labels == [DEFAULT_LABEL]
    #         assert item.object_marking_refs == [TLP_WHITE.id]
