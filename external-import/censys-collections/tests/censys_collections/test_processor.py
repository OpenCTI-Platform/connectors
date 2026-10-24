"""Tests for censys_collections.processor."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import cast
from unittest.mock import MagicMock

import pytest
from censys_collections.client import Client
from censys_collections.converter import Converter
from censys_collections.processor import CollectionsProcessor
from censys_collections.state import CensysCollectionsState
from censys_platform import Collection, CollectionStatus, Host, SearchQueryHit
from censys_platform.models import HostAssetWithMatchedServices
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import IPV4Address


def _make_collection(uid: str = "coll-1", name: str = "My Collection") -> Collection:
    return Collection(
        id=uid,
        name=name,
        query="",
        description="",
        status=CollectionStatus.ACTIVE,
        status_reason=None,
        total_assets=1,
        added_assets_24_hours=0,
        removed_assets_24_hours=0,
        create_time=datetime.now(tz=timezone.utc),
    )


def _make_processor(
    collections: list[Collection],
    hits: list[SearchQueryHit],
    configured_ids: list[str] | None = None,
    excluded_ids: list[str] | None = None,
    skip_unchanged: bool = True,
) -> CollectionsProcessor:
    client = MagicMock(spec=Client)
    client.list_collections.return_value = iter(collections)
    client.fetch_collection_hits.side_effect = lambda collection_id: iter(hits)

    converter = Converter(tlp_level="TLP:AMBER", score=50)
    processor = CollectionsProcessor(client=client, converter=converter)

    # Inject minimal mocked dependencies (normally done by ExternalImportConnector).
    mock_settings = MagicMock()
    mock_settings.censys_collections.collection_ids = configured_ids
    mock_settings.censys_collections.excluded_collection_ids = excluded_ids
    mock_settings.censys_collections.skip_unchanged_collections = skip_unchanged
    processor.settings = mock_settings
    processor.logger = MagicMock()
    processor.work_manager = MagicMock()
    processor.state = CensysCollectionsState()

    return processor


@pytest.mark.usefixtures("mock_config")
def test_collect_returns_all_collections_when_no_filter() -> None:
    colls = [_make_collection("c1"), _make_collection("c2")]
    processor = _make_processor(colls, [], configured_ids=None)
    result = processor.collect()
    assert len(result) == 2


@pytest.mark.usefixtures("mock_config")
def test_collect_filters_by_configured_ids() -> None:
    colls = [_make_collection("c1"), _make_collection("c2"), _make_collection("c3")]
    processor = _make_processor(colls, [], configured_ids=["c1", "c3"])
    result = processor.collect()
    assert [c.id for c in result] == ["c1", "c3"]


@pytest.mark.usefixtures("mock_config")
def test_collect_excludes_configured_ids_when_no_allowlist() -> None:
    colls = [_make_collection("c1"), _make_collection("c2"), _make_collection("c3")]
    processor = _make_processor(colls, [], excluded_ids=["c2"])
    result = processor.collect()
    assert [c.id for c in result] == ["c1", "c3"]


@pytest.mark.usefixtures("mock_config")
def test_collect_excludes_multiple_configured_ids() -> None:
    colls = [_make_collection("c1"), _make_collection("c2"), _make_collection("c3")]
    processor = _make_processor(colls, [], excluded_ids=["c1", "c3"])
    result = processor.collect()
    assert [c.id for c in result] == ["c2"]


@pytest.mark.usefixtures("mock_config")
def test_collect_allowlist_takes_precedence_over_denylist() -> None:
    colls = [_make_collection("c1"), _make_collection("c2"), _make_collection("c3")]
    processor = _make_processor(
        colls, [], configured_ids=["c1", "c2"], excluded_ids=["c1"]
    )
    result = processor.collect()
    # collection_ids wins entirely; excluded_collection_ids is ignored (and warned about).
    assert [c.id for c in result] == ["c1", "c2"]
    cast(MagicMock, processor.logger).warning.assert_called_once()


@pytest.mark.usefixtures("mock_config")
def test_transform_yields_objects_per_collection() -> None:
    collection = _make_collection("coll-1", "Alpha")
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(
            extensions={}, resource=Host(ip="10.0.0.1")
        )
    )
    processor = _make_processor([collection], [hit])

    bundles = list(processor.transform([collection]))

    assert len(bundles) == 1
    assert any(isinstance(o, IPV4Address) for o in bundles[0])


@pytest.mark.usefixtures("mock_config")
def test_transform_skips_collection_with_no_objects() -> None:
    collection = _make_collection("empty-coll", "Empty")
    # No hits → no objects
    processor = _make_processor([collection], [])

    bundles = list(processor.transform([collection]))
    assert bundles == []


@pytest.mark.usefixtures("mock_config")
def test_transform_updates_work_name_per_collection() -> None:
    c1 = _make_collection("c1", "First")
    c2 = _make_collection("c2", "Second")
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=Host(ip="1.1.1.1"))
    )

    client = MagicMock(spec=Client)
    client.list_collections.return_value = iter([c1, c2])
    client.fetch_collection_hits.side_effect = lambda collection_id: iter([hit])

    converter = Converter(tlp_level="TLP:AMBER", score=50)
    processor = CollectionsProcessor(client=client, converter=converter)

    mock_settings = MagicMock()
    mock_settings.censys_collections.collection_ids = None
    processor.settings = mock_settings
    processor.logger = MagicMock()
    processor.work_manager = MagicMock()
    processor.state = CensysCollectionsState()

    work_names: list[str] = []
    # Consume generator and capture work_name at each yield.
    for _ in processor.transform([c1, c2]):
        work_names.append(processor.work_name)

    assert "First" in work_names[0]
    assert "Second" in work_names[1]


@pytest.mark.usefixtures("mock_config")
def test_transform_skips_failing_collection_and_continues() -> None:
    """A collection whose asset fetch raises should be skipped, not abort the run."""
    c1 = _make_collection("c1", "Broken")
    c2 = _make_collection("c2", "Healthy")
    hit = SearchQueryHit(
        host_v1=HostAssetWithMatchedServices(extensions={}, resource=Host(ip="1.1.1.1"))
    )

    def fetch_side_effect(collection_id: str):
        if collection_id == "c1":
            raise TimeoutError("The read operation timed out")
        return iter([hit])

    client = MagicMock(spec=Client)
    client.list_collections.return_value = iter([c1, c2])
    client.fetch_collection_hits.side_effect = fetch_side_effect

    converter = Converter(tlp_level="TLP:AMBER", score=50)
    processor = CollectionsProcessor(client=client, converter=converter)

    mock_settings = MagicMock()
    mock_settings.censys_collections.collection_ids = None
    processor.settings = mock_settings
    processor.logger = MagicMock()
    processor.work_manager = MagicMock()
    processor.state = CensysCollectionsState()

    bundles = list(processor.transform([c1, c2]))

    # Only the healthy collection's objects should be yielded.
    assert len(bundles) == 1
    assert any(isinstance(o, IPV4Address) for o in bundles[0])
    processor.logger.error.assert_called_once()


@pytest.mark.usefixtures("mock_config")
def test_transform_raises_when_every_collection_fails() -> None:
    """If every collection's asset fetch fails (e.g. invalid token), the run must fail."""
    c1 = _make_collection("c1", "Broken 1")
    c2 = _make_collection("c2", "Broken 2")
    processor = _make_processor([c1, c2], [])
    client = cast(MagicMock, processor.client)
    client.fetch_collection_hits.side_effect = PermissionError("401 Unauthorized")

    with pytest.raises(DataRetrievalError):
        list(processor.transform([c1, c2]))

    assert cast(MagicMock, processor.logger).error.call_count == 2


@pytest.mark.usefixtures("mock_config")
def test_transform_does_not_raise_when_no_collections() -> None:
    processor = _make_processor([], [])
    assert list(processor.transform([])) == []


@pytest.mark.usefixtures("mock_config")
def test_process_propagates_total_failure_to_work_manager() -> None:
    """The total-failure error must reach the WorkManager context and the caller.

    ``ExternalImportConnector.callback`` only advances ``last_run`` when
    ``process()`` returns normally, so propagating the error keeps the
    connector state untouched.
    """
    c1 = _make_collection("c1", "Broken")
    processor = _make_processor([c1], [])
    client = cast(MagicMock, processor.client)
    client.fetch_collection_hits.side_effect = PermissionError("401 Unauthorized")
    work_manager = cast(MagicMock, processor.work_manager)
    # Like the real WorkManager, do not swallow exceptions on exit.
    work_manager.__exit__.return_value = False

    with pytest.raises(DataRetrievalError):
        processor.process()

    exit_args = work_manager.__exit__.call_args.args
    assert exit_args[0] is DataRetrievalError
    work_manager.send.assert_not_called()


# ---------------------------------------------------------------------------
# Incremental ingestion
# ---------------------------------------------------------------------------

_HIT = SearchQueryHit(
    host_v1=HostAssetWithMatchedServices(extensions={}, resource=Host(ip="10.0.0.1"))
)
_CHECKPOINT = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.mark.usefixtures("mock_config")
def test_transform_first_ingestion_does_not_query_events() -> None:
    collection = _make_collection("c1")
    processor = _make_processor([collection], [_HIT])
    client = cast(MagicMock, processor.client)

    bundles = list(processor.transform([collection]))

    assert len(bundles) == 1
    client.has_added_assets_since.assert_not_called()


@pytest.mark.usefixtures("mock_config")
def test_transform_skips_collection_without_added_assets() -> None:
    collection = _make_collection("c1")
    processor = _make_processor([collection], [_HIT])
    processor.state.collection_checkpoints = {"c1": _CHECKPOINT}
    client = cast(MagicMock, processor.client)
    client.has_added_assets_since.return_value = False

    bundles = list(processor.transform([collection]))

    assert bundles == []
    client.has_added_assets_since.assert_called_once_with("c1", _CHECKPOINT)
    client.fetch_collection_hits.assert_not_called()
    assert processor.state.collection_checkpoints == {"c1": _CHECKPOINT}


@pytest.mark.usefixtures("mock_config")
def test_transform_ingests_collection_with_added_assets() -> None:
    collection = _make_collection("c1")
    processor = _make_processor([collection], [_HIT])
    processor.state.collection_checkpoints = {"c1": _CHECKPOINT}
    client = cast(MagicMock, processor.client)
    client.has_added_assets_since.return_value = True

    bundles = list(processor.transform([collection]))

    assert len(bundles) == 1
    assert processor.state.collection_checkpoints["c1"] > _CHECKPOINT


@pytest.mark.usefixtures("mock_config")
def test_transform_ingests_in_full_when_events_lookup_fails() -> None:
    collection = _make_collection("c1")
    processor = _make_processor([collection], [_HIT])
    processor.state.collection_checkpoints = {"c1": _CHECKPOINT}
    client = cast(MagicMock, processor.client)
    client.has_added_assets_since.side_effect = RuntimeError("events unavailable")

    bundles = list(processor.transform([collection]))

    assert len(bundles) == 1
    cast(MagicMock, processor.logger).warning.assert_called_once()


@pytest.mark.usefixtures("mock_config")
def test_transform_ignores_checkpoints_when_skip_disabled() -> None:
    collection = _make_collection("c1")
    processor = _make_processor([collection], [_HIT], skip_unchanged=False)
    processor.state.collection_checkpoints = {"c1": _CHECKPOINT}
    client = cast(MagicMock, processor.client)

    bundles = list(processor.transform([collection]))

    assert len(bundles) == 1
    client.has_added_assets_since.assert_not_called()


@pytest.mark.usefixtures("mock_config")
def test_transform_sets_checkpoint_to_fetch_start_time() -> None:
    collection = _make_collection("c1")
    processor = _make_processor([collection], [_HIT])
    before = datetime.now(tz=timezone.utc)

    list(processor.transform([collection]))

    checkpoint = processor.state.collection_checkpoints["c1"]
    assert before <= checkpoint <= datetime.now(tz=timezone.utc)


@pytest.mark.usefixtures("mock_config")
def test_transform_sets_checkpoint_for_empty_collection() -> None:
    collection = _make_collection("c1")
    processor = _make_processor([collection], [])

    list(processor.transform([collection]))

    assert "c1" in processor.state.collection_checkpoints


@pytest.mark.usefixtures("mock_config")
def test_transform_keeps_checkpoint_when_fetch_fails() -> None:
    c1 = _make_collection("c1", "Broken")
    c2 = _make_collection("c2", "Healthy")
    processor = _make_processor([c1, c2], [_HIT])
    old = _CHECKPOINT - timedelta(days=1)
    processor.state.collection_checkpoints = {"c1": old}
    client = cast(MagicMock, processor.client)
    client.has_added_assets_since.return_value = True

    def fetch_side_effect(collection_id: str):
        if collection_id == "c1":
            raise TimeoutError("The read operation timed out")
        return iter([_HIT])

    client.fetch_collection_hits.side_effect = fetch_side_effect

    list(processor.transform([c1, c2]))

    assert processor.state.collection_checkpoints["c1"] == old
    assert "c2" in processor.state.collection_checkpoints


@pytest.mark.usefixtures("mock_config")
def test_transform_skipped_collections_do_not_mask_total_failure() -> None:
    """Skipped collections are not counted when checking for total failure."""
    unchanged = _make_collection("c1", "Unchanged")
    broken = _make_collection("c2", "Broken")
    processor = _make_processor([unchanged, broken], [])
    processor.state.collection_checkpoints = {"c1": _CHECKPOINT}
    client = cast(MagicMock, processor.client)
    client.has_added_assets_since.return_value = False
    client.fetch_collection_hits.side_effect = PermissionError("401 Unauthorized")

    with pytest.raises(DataRetrievalError):
        list(processor.transform([unchanged, broken]))


@pytest.mark.usefixtures("mock_config")
def test_transform_all_collections_skipped_does_not_raise() -> None:
    c1 = _make_collection("c1")
    processor = _make_processor([c1], [])
    processor.state.collection_checkpoints = {"c1": _CHECKPOINT}
    cast(MagicMock, processor.client).has_added_assets_since.return_value = False

    assert list(processor.transform([c1])) == []
