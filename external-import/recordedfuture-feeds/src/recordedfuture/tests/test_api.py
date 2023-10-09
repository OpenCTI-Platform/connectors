import pytest
import json
import os
import uuid
import hashlib
from recordedfuture.core import RecordedFutureClient
from recordedfuture.core.constants import DATASET

DEFAULT_LABEL = ["recordedfuture"]


def generate_random_md5():
    """Generate a random MD5 for token"""
    # Generate a random UUID (which is 128-bit number), convert it to a string
    random_string = str(uuid.uuid4())

    # Compute its MD5 hash
    result = hashlib.md5(random_string.encode()).hexdigest()
    return result


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
    """Create a RecordedFutureClient instance with a mock token."""
    # Use a mock token for testing
    return RecordedFutureClient(api_token=generate_random_md5(), labels=DEFAULT_LABEL)


class TestRecordedFutureClient:
    def test_invalid_api_token(self):
        """Test initialization with an invalid MD5 format token."""
        invalid_token = "invalid_token_string"
        with pytest.raises(ValueError, match="API token is not a valid token."):
            RecordedFutureClient(api_token=invalid_token, labels=DEFAULT_LABEL)

    def test_fetch_data_invalid_key(self, client: RecordedFutureClient, mocker):
        """Test fetching data with an invalid dataset key."""
        INVALID_KEY = "INVALID_KEY"
        mocker.patch.object(client, "_request_data", return_value=None)
        result = client.fetch_data(INVALID_KEY)
        assert result is None

    def test_fetch_data_success(self, client: RecordedFutureClient, mocker):
        """Test successful fetching of data for valid dataset keys."""
        # Patch the _request_data method to return mock data. The mock will be applied
        # for all iterations in the loop.
        mock_request = mocker.patch.object(client, "_request_data")

        for dataset in DATASET.keys():
            FIXTURE_RESPONSE = load_fixture(f"{dataset}.json")
            mock_request.return_value = (
                FIXTURE_RESPONSE  # Set the return value for this iteration
            )
            result = client.fetch_data(dataset)
            assert result == FIXTURE_RESPONSE
