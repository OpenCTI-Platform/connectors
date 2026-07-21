"""RED tests — Chronicle alert service URL construction.

Tests that GoogleSecOpsApiClient builds correct regionalized URLs,
instance paths, and composite alert endpoints.
"""

import pytest

from tests.tests_chronicle_client.factories import make_client, make_config


# ---------------------------------------------------------------------------
# Scenario Outline: Regionalized base URL prepends region to the hostname
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("region", ["us", "eu", "asia"])
def test_regionalized_base_url_prepends_region(region):
    """Region '<region>' produces https://<region>-chronicle.googleapis.com."""

    def _given_config_with_region(r):
        return make_config(project_region=r)

    def _when_regionalized_url_is_constructed(client):
        return client._regionalized_url()

    def _then_url_has_region_prefix(url, r):
        assert url == f"https://{r}-chronicle.googleapis.com"

    config = _given_config_with_region(region)
    client, _ = make_client(config)
    url = _when_regionalized_url_is_constructed(client)
    _then_url_has_region_prefix(url, region)


# ---------------------------------------------------------------------------
# Scenario: Instance path reflects project identifiers
# ---------------------------------------------------------------------------
def test_instance_path_reflects_project_identifiers():
    """Instance path is projects/{pid}/locations/{region}/instances/{inst}."""

    def _given_config_with_project_ids():
        return make_config(
            project_id="my-project-123",
            project_region="us",
            project_instance="instance-abc",
        )

    def _when_instance_path_is_constructed(client):
        return client._instance_path()

    def _then_path_matches(path):
        assert path == "projects/my-project-123/locations/us/instances/instance-abc"

    config = _given_config_with_project_ids()
    client, _ = make_client(config)
    path = _when_instance_path_is_constructed(client)
    _then_path_matches(path)


# ---------------------------------------------------------------------------
# Scenario: Alerts URL combines regionalized hostname and instance path
# ---------------------------------------------------------------------------
def test_alerts_url_combines_region_and_instance():
    """Alerts URL is {regionalized}/v1alpha/{instance_path}/legacy:legacySearchRulesAlerts."""

    def _given_eu_config():
        return make_config(
            project_id="proj-42",
            project_region="eu",
            project_instance="inst-7",
        )

    def _when_alerts_url_is_constructed(client):
        return client._alerts_url()

    def _then_url_is_correct(url):
        expected = (
            "https://eu-chronicle.googleapis.com"
            "/v1alpha"
            "/projects/proj-42/locations/eu/instances/inst-7"
            "/legacy:legacySearchRulesAlerts"
        )
        assert url == expected

    config = _given_eu_config()
    client, _ = make_client(config)
    url = _when_alerts_url_is_constructed(client)
    _then_url_is_correct(url)
