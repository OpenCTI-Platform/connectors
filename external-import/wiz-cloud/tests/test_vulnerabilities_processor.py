"""Tests for the Wiz vulnerabilities processor."""

from connectors_sdk.models import Relationship, System, Vulnerability
from wiz_cloud.settings import WizCloudConfig


def _asset_ids(processor) -> list[str]:
    """Return the asset ids sent in the first paginate() call.

    Args:
        processor: The processor whose client was called.

    Returns:
        The assetIdV2 equals list of the first call.
    """
    variables = processor._client.paginate.call_args_list[0][0][1]
    return variables["filterBy"]["assetIdV2"]["equals"]


def test_collect_does_nothing_without_assets(vulnerabilities_processor):
    pages = list(vulnerabilities_processor.collect())

    assert pages == []
    assert vulnerabilities_processor._client.paginate.call_count == 0


def test_collect_filters_on_severity_and_status(vulnerabilities_processor):
    vulnerabilities_processor._run_context.add_asset("asset-1")
    vulnerabilities_processor._client.paginate.return_value = iter([])

    list(vulnerabilities_processor.collect())

    variables = vulnerabilities_processor._client.paginate.call_args_list[0][0][1]
    assert variables["filterBy"]["severity"] == ["CRITICAL", "HIGH"]
    assert variables["filterBy"]["status"] == ["OPEN", "IN_PROGRESS"]
    assert "hasExploit" not in variables["filterBy"]
    assert _asset_ids(vulnerabilities_processor) == ["asset-1"]


def test_collect_adds_the_exploit_filter_when_enabled(vulnerabilities_processor):
    # Rebuilt rather than mutated, so the test does not depend on whether the
    # settings model allows assignment.
    vulnerabilities_processor._config = WizCloudConfig(
        api_url="https://api.us17.app.wiz.io/graphql",
        client_id="id",
        client_secret="secret",
        vulnerability_has_exploit=True,
    )
    vulnerabilities_processor._run_context.add_asset("asset-1")
    vulnerabilities_processor._client.paginate.return_value = iter([])

    list(vulnerabilities_processor.collect())

    variables = vulnerabilities_processor._client.paginate.call_args_list[0][0][1]
    assert variables["filterBy"]["hasExploit"] is True


def test_collect_batches_asset_ids_at_the_size_boundary(vulnerabilities_processor):
    for index in range(51):
        vulnerabilities_processor._run_context.add_asset(f"asset-{index:03d}")
    vulnerabilities_processor._client.paginate.return_value = iter([])

    list(vulnerabilities_processor.collect())

    assert vulnerabilities_processor._client.paginate.call_count == 2
    assert len(_asset_ids(vulnerabilities_processor)) == 50


def test_collect_survives_a_failing_client(vulnerabilities_processor):
    from wiz_cloud.client_api import WizGraphQLError

    vulnerabilities_processor._run_context.add_asset("asset-1")
    vulnerabilities_processor._client.paginate.side_effect = WizGraphQLError("boom")

    pages = list(vulnerabilities_processor.collect())

    assert pages == []
    assert vulnerabilities_processor.logger.error.called


def _of_type(objects: list, kind: type) -> list:
    return [item for item in objects if isinstance(item, kind)]


def test_transform_maps_the_cve_fields(
    vulnerabilities_processor, vulnerability_finding_data
):
    bundles = list(
        vulnerabilities_processor.transform(iter([[vulnerability_finding_data]]))
    )

    vulnerability = _of_type(bundles[0], Vulnerability)[0]
    assert vulnerability.name == "CVE-2026-46333"
    assert vulnerability.description.startswith("In the Linux kernel")
    assert vulnerability.cvss_v3_base_score == 7.1
    assert vulnerability.cvss_v3_base_severity == "HIGH"
    assert vulnerability.cvss_v3_attack_vector == "LOCAL"
    assert vulnerability.cvss_v3_scope == "UNCHANGED"
    assert vulnerability.is_cisa_kev is False
    assert vulnerability.score is None


def test_transform_converts_epss_percentages_to_the_zero_one_range(
    vulnerabilities_processor, vulnerability_finding_data
):
    bundles = list(
        vulnerabilities_processor.transform(iter([[vulnerability_finding_data]]))
    )

    vulnerability = _of_type(bundles[0], Vulnerability)[0]
    assert vulnerability.epss_percentile == 0.724
    assert vulnerability.epss_score == 0.015


def test_transform_converts_the_user_interaction_boolean_to_a_string(
    vulnerabilities_processor, vulnerability_finding_data
):
    data = {
        **vulnerability_finding_data,
        "cvssv3": {
            **vulnerability_finding_data["cvssv3"],
            "userInteractionRequired": True,
        },
    }

    bundles = list(vulnerabilities_processor.transform(iter([[data]])))

    assert _of_type(bundles[0], Vulnerability)[0].cvss_v3_user_interaction == "REQUIRED"


def test_transform_falls_back_to_the_finding_description(
    vulnerabilities_processor, empty_cve_description_finding_data
):
    bundles = list(
        vulnerabilities_processor.transform(
            iter([[empty_cve_description_finding_data]])
        )
    )

    vulnerability = _of_type(bundles[0], Vulnerability)[0]
    assert vulnerability.description.startswith("The package `kernel`")


def test_transform_links_the_system_to_the_vulnerability(
    vulnerabilities_processor, vulnerability_finding_data
):
    bundles = list(
        vulnerabilities_processor.transform(iter([[vulnerability_finding_data]]))
    )

    relationship = _of_type(bundles[0], Relationship)[0]
    assert relationship.type == "has"
    assert isinstance(relationship.source, System)
    assert isinstance(relationship.target, Vulnerability)
    assert relationship.source.name == "tivan-eleonore-vm"
    assert relationship.start_time is not None
    # stop_time stays empty: generate_id() hashes it, so lastDetectedAt would
    # mint a new relationship on every run.
    assert relationship.stop_time is None
    assert "OPEN" in relationship.description


def test_transform_attributes_each_finding_to_its_own_asset(
    vulnerabilities_processor, vulnerability_finding_data, second_asset_finding_data
):
    bundles = list(
        vulnerabilities_processor.transform(
            iter([[vulnerability_finding_data, second_asset_finding_data]])
        )
    )

    pairs = {
        (item.source.name, item.target.name)
        for item in _of_type(bundles[0], Relationship)
    }
    assert pairs == {
        ("tivan-eleonore-vm", "CVE-2026-46333"),
        ("TA-733-INTEG-ING", "CVE-2026-3039"),
    }


def test_transform_emits_each_system_once(
    vulnerabilities_processor, vulnerability_finding_data
):
    second = {**vulnerability_finding_data, "id": "other", "name": "CVE-2026-0001"}

    bundles = list(
        vulnerabilities_processor.transform(
            iter([[vulnerability_finding_data, second]])
        )
    )

    assert len(_of_type(bundles[0], System)) == 1


def test_transform_skips_an_unparseable_finding(vulnerabilities_processor):
    bundles = list(vulnerabilities_processor.transform(iter([[{"id": "broken"}]])))

    assert bundles == []
    assert vulnerabilities_processor.logger.warning.called


def test_transform_skips_a_finding_without_an_asset(
    vulnerabilities_processor, vulnerability_finding_data
):
    data = {**vulnerability_finding_data, "vulnerableAsset": None}

    bundles = list(vulnerabilities_processor.transform(iter([[data]])))

    assert bundles == []
