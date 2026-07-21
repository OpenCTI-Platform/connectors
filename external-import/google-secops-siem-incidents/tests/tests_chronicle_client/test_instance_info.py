"""Tests — Instance Info API: URL construction and fetch_instance_info.

Tests that GoogleSecOpsApiClient builds the correct instance URL and
that fetch_instance_info returns a parsed InstanceInfoResponse.
"""

import pytest
from google_secops_siem_incidents.models.instance_info_response import (
    InstanceInfoResponse,
)

from tests.tests_chronicle_client.factories import make_client, make_config


# ---------------------------------------------------------------------------
# Scenario: Instance URL combines regionalized hostname and instance path
# ---------------------------------------------------------------------------
def test_instance_url_combines_region_and_instance():
    """Instance URL is {regionalized}/v1alpha/{instance_path} (no trailing endpoint)."""

    def _given_eu_config():
        return make_config(
            project_id="proj-42",
            project_region="eu",
            project_instance="inst-7",
        )

    def _when_instance_url_is_constructed(client):
        return client._instance_url()

    def _then_url_is_correct(url):
        expected = (
            "https://eu-chronicle.googleapis.com"
            "/v1alpha"
            "/projects/proj-42/locations/eu/instances/inst-7"
        )
        assert url == expected

    config = _given_eu_config()
    client, _ = make_client(config)
    url = _when_instance_url_is_constructed(client)
    _then_url_is_correct(url)


@pytest.mark.parametrize("region", ["us", "eu", "asia"])
def test_instance_url_region_prefix(region):
    """Instance URL picks up the correct region prefix."""
    config = make_config(project_region=region)
    client, _ = make_client(config)
    url = client._instance_url()
    assert url.startswith(f"https://{region}-chronicle.googleapis.com")


# ---------------------------------------------------------------------------
# Scenario: fetch_instance_info returns parsed InstanceInfoResponse
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_instance_info_returns_parsed_response():
    """fetch_instance_info delegates to call_api and returns InstanceInfoResponse."""
    client, _ = make_client()

    expected = InstanceInfoResponse(
        name="projects/test/locations/us/instances/abc",
        state="ACTIVE",
        display_name="My Instance",
        secops_urls=["https://my.backstory.chronicle.security"],
    )
    client._api_client.call_api = pytest.importorskip("unittest.mock").AsyncMock(
        return_value=expected,
    )

    result = await client.fetch_instance_info()

    assert result is expected
    client._api_client.call_api.assert_awaited_once()
    call_kwargs = client._api_client.call_api.call_args
    assert (
        call_kwargs.kwargs.get("method") == "GET"
        or call_kwargs[1].get("method") == "GET"
    )


# ---------------------------------------------------------------------------
# Scenario: InstanceInfoResponse model parses secopsUrls from JSON alias
# ---------------------------------------------------------------------------
def test_instance_info_response_parses_secops_urls():
    """InstanceInfoResponse correctly parses the secopsUrls field from API JSON."""
    raw = {
        "name": "projects/xxx/locations/us/instances/yyy",
        "state": "ACTIVE",
        "displayName": "Test",
        "secopsUrls": [
            "https://abc.backstory.chronicle.security",
            "https://def.backstory.chronicle.security",
        ],
    }
    response = InstanceInfoResponse(**raw)

    assert response.secops_urls == [
        "https://abc.backstory.chronicle.security",
        "https://def.backstory.chronicle.security",
    ]
    assert response.display_name == "Test"


def test_instance_info_response_defaults_empty_secops_urls():
    """InstanceInfoResponse defaults secops_urls to empty list when not present."""
    response = InstanceInfoResponse(name="projects/x/locations/y/instances/z")
    assert response.secops_urls == []
