"""Tests for the Wiz vulnerabilities processor."""

import pytest
from connectors_sdk.models import Relationship, System, Vulnerability
from wiz_cloud.client_api import WizGraphQLError
from wiz_cloud.settings import WizCloudConfig


def _of_type(objects: list, kind: type) -> list:
    return [item for item in objects if isinstance(item, kind)]


def _filter_of(vulnerabilities_processor) -> dict:
    """Return the filterBy of the first paginate() call.

    Args:
        vulnerabilities_processor: The processor whose client was called.

    Returns:
        The filterBy mapping sent to Wiz.
    """
    return vulnerabilities_processor._client.paginate.call_args_list[0][0][1][
        "filterBy"
    ]


# -- querying ---------------------------------------------------------------


def test_queries_the_single_asset_of_the_issue(vulnerabilities_processor, system):
    vulnerabilities_processor._client.paginate.return_value = iter([])

    vulnerabilities_processor.objects_for_asset("asset-1", system)

    assert _filter_of(vulnerabilities_processor)["assetIdV2"]["equals"] == ["asset-1"]


def test_filters_on_severity_and_status(vulnerabilities_processor, system):
    vulnerabilities_processor._client.paginate.return_value = iter([])

    vulnerabilities_processor.objects_for_asset("asset-1", system)

    filter_by = _filter_of(vulnerabilities_processor)
    assert filter_by["severity"] == ["CRITICAL", "HIGH"]
    assert filter_by["status"] == ["OPEN", "IN_PROGRESS"]
    assert "hasExploit" not in filter_by


def test_adds_the_exploit_filter_when_enabled(vulnerabilities_processor, system):
    # Rebuilt rather than mutated, so the test does not depend on whether the
    # settings model allows assignment.
    vulnerabilities_processor._config = WizCloudConfig(
        api_url="https://api.us17.app.wiz.io/graphql",
        client_id="id",
        client_secret="secret",
        vulnerability_has_exploit=True,
    )
    vulnerabilities_processor._client.paginate.return_value = iter([])

    vulnerabilities_processor.objects_for_asset("asset-1", system)

    assert _filter_of(vulnerabilities_processor)["hasExploit"] is True


def test_queries_an_asset_only_once_per_run(
    vulnerabilities_processor, system, vulnerability_finding_data
):
    vulnerabilities_processor._client.paginate.return_value = iter(
        [[vulnerability_finding_data]]
    )

    first = vulnerabilities_processor.objects_for_asset("asset-1", system)
    second = vulnerabilities_processor.objects_for_asset("asset-1", system)

    # The same resource backs several issues; its findings were already sent
    # with the first one and carry deterministic ids.
    assert first != []
    assert second == []
    assert vulnerabilities_processor._client.paginate.call_count == 1


# -- failure handling -------------------------------------------------------


def test_counts_a_failure_instead_of_raising(vulnerabilities_processor, system):
    vulnerabilities_processor._client.paginate.side_effect = WizGraphQLError("boom")

    objects = vulnerabilities_processor.objects_for_asset("asset-1", system)

    assert objects == []
    assert vulnerabilities_processor.failures == 1
    assert vulnerabilities_processor._logger.error.called


def test_drops_partial_results_when_a_later_page_fails(
    vulnerabilities_processor, system, vulnerability_finding_data
):
    def pages():
        yield [vulnerability_finding_data]
        raise WizGraphQLError("boom")

    vulnerabilities_processor._client.paginate.return_value = pages()

    objects = vulnerabilities_processor.objects_for_asset("asset-1", system)

    # Half an asset is worse than none: the run replays anyway.
    assert objects == []
    assert vulnerabilities_processor.failures == 1


# -- conversion -------------------------------------------------------------


@pytest.fixture
def converted(vulnerabilities_processor, system, vulnerability_finding_data) -> list:
    """The objects produced for a single kernel CVE finding."""
    vulnerabilities_processor._client.paginate.return_value = iter(
        [[vulnerability_finding_data]]
    )
    return vulnerabilities_processor.objects_for_asset("asset-1", system)


def test_maps_the_cve_fields(converted):
    vulnerability = _of_type(converted, Vulnerability)[0]
    assert vulnerability.name == "CVE-2026-46333"
    assert vulnerability.description.startswith("In the Linux kernel")
    assert vulnerability.cvss_v3_base_score == 7.1
    assert vulnerability.cvss_v3_base_severity == "HIGH"
    assert vulnerability.cvss_v3_attack_vector == "LOCAL"
    assert vulnerability.cvss_v3_scope == "UNCHANGED"
    assert vulnerability.is_cisa_kev is False
    assert vulnerability.score is None


def test_converts_epss_percentages_to_the_zero_one_range(converted):
    vulnerability = _of_type(converted, Vulnerability)[0]
    assert vulnerability.epss_percentile == 0.724
    assert vulnerability.epss_score == 0.015


def test_converts_the_user_interaction_boolean_to_a_string(
    vulnerabilities_processor, system, vulnerability_finding_data
):
    data = {
        **vulnerability_finding_data,
        "cvssv3": {
            **vulnerability_finding_data["cvssv3"],
            "userInteractionRequired": True,
        },
    }
    vulnerabilities_processor._client.paginate.return_value = iter([[data]])

    objects = vulnerabilities_processor.objects_for_asset("asset-1", system)

    assert _of_type(objects, Vulnerability)[0].cvss_v3_user_interaction == "REQUIRED"


def test_falls_back_to_the_finding_description(
    vulnerabilities_processor, system, empty_cve_description_finding_data
):
    vulnerabilities_processor._client.paginate.return_value = iter(
        [[empty_cve_description_finding_data]]
    )

    objects = vulnerabilities_processor.objects_for_asset("asset-1", system)

    vulnerability = _of_type(objects, Vulnerability)[0]
    assert vulnerability.description.startswith("The package `kernel`")


def test_links_the_given_system_to_the_vulnerability(converted, system):
    relationship = _of_type(converted, Relationship)[0]
    assert relationship.type == "has"
    # The very System the issue built, so the bundle holds one object for the
    # resource rather than two that must be merged.
    assert relationship.source is system
    assert isinstance(relationship.target, Vulnerability)
    assert relationship.start_time is not None
    # stop_time stays empty: generate_id() hashes it, so lastDetectedAt would
    # mint a new relationship on every run.
    assert relationship.stop_time is None
    assert "OPEN" in relationship.description


def test_never_emits_a_system_of_its_own(converted):
    assert _of_type(converted, System) == []


def test_skips_an_unparseable_finding(vulnerabilities_processor, system):
    vulnerabilities_processor._client.paginate.return_value = iter([[{"id": "broken"}]])

    objects = vulnerabilities_processor.objects_for_asset("asset-1", system)

    assert objects == []
    assert vulnerabilities_processor._logger.warning.called


def test_skips_a_finding_without_a_cve_id(
    vulnerabilities_processor, system, vulnerability_finding_data
):
    vulnerabilities_processor._client.paginate.return_value = iter(
        [[{**vulnerability_finding_data, "name": ""}]]
    )

    objects = vulnerabilities_processor.objects_for_asset("asset-1", system)

    assert objects == []
