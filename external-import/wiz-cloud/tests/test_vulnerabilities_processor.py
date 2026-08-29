"""Tests for the Wiz vulnerabilities processor."""

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
