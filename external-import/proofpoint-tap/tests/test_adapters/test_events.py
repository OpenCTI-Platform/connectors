# isort:skip_file
# pragma: no cover # do not include tests modules in coverage metrics
"""Test the events adapters."""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock

import pytest
from aiohttp import ClientResponse
from pydantic import SecretStr
from yarl import URL

from proofpoint_tap.adapters.events import EventsAPIV2
from proofpoint_tap.client_api.v2.siem import SIEMClient


def make_fake_get_client_response() -> ClientResponse:
    """Return a fake ClientResponse object."""
    return ClientResponse(
        method="GET",
        url=URL("/dummy"),
        writer=Mock(),
        continue100=None,
        timer=Mock(),
        request_info=Mock(),
        traces=[],
        loop=Mock(),
        session=Mock(),
    )


def mock_siem_v2_client_instance() -> SIEMClient:
    """Return a mock Client instance."""
    client = SIEMClient(
        base_url=URL("http://example.com"),
        principal=SecretStr("principal"),
        secret=SecretStr("*****"),  # noqa: S106  # we indeed harcode a secret here...
        timeout=timedelta(seconds=1),
        retry=1,
        backoff=timedelta(seconds=1),
    )
    # For safety, we deactivate _get method.
    client._get = AsyncMock()
    return client

@pytest.fixture(scope="function")
def siem_v2_client_instance():
    """Return a mock Client instance."""
    return mock_siem_v2_client_instance()

def mock_events_api_v2_adapter():
    """Return a mock Client instance."""
    adapter =  EventsAPIV2(
        base_url=URL("http://example.com"),
        principal=SecretStr("principal"),
        secret=SecretStr("*****"),  # noqa: S106  # we indeed harcode a secret here...
        timeout=timedelta(seconds=1),
        retry=1,
        backoff=timedelta(seconds=1)
    )
    adapter._client = mock_siem_v2_client_instance()
    return adapter

@pytest.fixture(scope="function")
def events_api_v2_adapter():
    """Return a mock Client instance."""
    return mock_events_api_v2_adapter()


# test interval is splited correctly
@pytest.mark.parametrize(
    "start_time, stop_time",
    [
        pytest.param(
            datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            datetime(1970, 1, 1, 0, 30, 0, tzinfo=timezone.utc),
            id="prefered_duration",
        ),
        pytest.param(
            datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            datetime(1970, 1, 1, 0, 15, 0, tzinfo=timezone.utc),
            id="shorter_than_prefered_interval",
        ),
        pytest.param(
            datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            datetime(1970, 1, 1, 1, 0, 0, tzinfo=timezone.utc),
            id="2_times_prefered_duration",
        ),
        pytest.param(
            datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            datetime(1970, 1, 1, 1, 15, 0, tzinfo=timezone.utc),
            id="2.5_times_prefered_duration",
        )
    ]
)
def test_events_api_v2_splits_interval_correctly(start_time, stop_time):
    """Test interval computation."""
    # Given time range to split
    # When splitting time into 30 minutes chunks
    iterable = EventsAPIV2._chunk_30_minutes_intervals(
        start_time=start_time,
        stop_time=stop_time,
    )
    intervals = list(iterable)
    # Then the correct intervals should be present
    assert ( # noqa: S101
        # start_time is contained in the first list item
        # stop_time is contained in the last list item
        # all intervals last the same amount of time
        intervals[0][0] <= start_time <= intervals[0][1]
    )
    assert ( # noqa: S101
        intervals[-1][0] <= stop_time <= intervals[-1][1]
    )
    duration_seconds = (intervals[0][1]-intervals[0][0]).total_seconds()
    assert ( # noqa: S101
        60 <= duration_seconds <= 3600
    )
    assert ( # noqa: S101
        all((interval[1]-interval[0]).total_seconds()==duration_seconds for interval in intervals)
    )
