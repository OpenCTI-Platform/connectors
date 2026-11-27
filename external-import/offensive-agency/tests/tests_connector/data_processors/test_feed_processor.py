from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from conftest import make_settings
from connector import ConnectorState
from connector.data_processors import FeedProcessor
from connector.data_processors import feed_processor as feed_processor_module
from connectors_sdk.models import (
    Indicator,
    IPV4Address,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
    Tool,
)
from offensive_agency_client import OffensiveAgencyClient


def _processor(settings=None, state=None) -> FeedProcessor:
    processor = FeedProcessor()
    processor.inject_dependencies(
        settings=settings or make_settings(),
        helper=MagicMock(),
        state=state or ConnectorState(),
    )
    processor.post_init()
    return processor


def _feed(raw_feed):
    client = OffensiveAgencyClient(base_url="https://example.com", logger=MagicMock())
    with patch.object(client, "_get", return_value=raw_feed):
        return client.get_feed()


def _of_type(objects, model):
    return [obj for obj in objects if isinstance(obj, model)]


def _relationships(objects, relationship_type):
    return [
        obj for obj in _of_type(objects, Relationship) if obj.type == relationship_type
    ]


def test_collect_should_download_the_feed():
    processor = _processor()
    processor.client = MagicMock()

    processor.collect()

    processor.client.get_feed.assert_called_once()


def test_transform_should_send_everything_on_the_first_run(raw_feed):
    processor = _processor()

    bundles = list(processor.transform(_feed(raw_feed)))

    assert len(bundles) == 1
    objects = bundles[0]
    assert len(_of_type(objects, OrganizationAuthor)) == 1
    assert len(_of_type(objects, TLPMarking)) == 1
    assert {tool.name for tool in _of_type(objects, Tool)} == {
        "Agent Alpha",
        "Agent Beta",
    }
    assert {i.name for i in _of_type(objects, Indicator)} == {
        "198.51.100.1",
        "198.51.100.2",
    }
    assert {o.value for o in _of_type(objects, IPV4Address)} == {
        "198.51.100.1",
        "198.51.100.2",
    }
    assert len(_relationships(objects, "based-on")) == 2
    assert len(_relationships(objects, "indicates")) == 3


def test_transform_should_map_the_indicator_fields(raw_feed):
    processor = _processor()

    objects = next(processor.transform(_feed(raw_feed)))

    indicator = next(
        i for i in _of_type(objects, Indicator) if i.name == "198.51.100.2"
    )
    assert indicator.pattern == "[ipv4-addr:value = '198.51.100.2']"
    assert indicator.main_observable_type == "IPv4-Addr"
    assert indicator.indicator_types == ["anomalous-activity"]
    assert indicator.labels == ["agent:alpha", "agent:beta", "network:cloud"]
    assert indicator.valid_from == datetime(2026, 1, 8, tzinfo=timezone.utc)
    # Last seen on 2026-01-12, plus the default validity of 30 days
    assert indicator.valid_until == datetime(2026, 2, 11, tzinfo=timezone.utc)
    assert indicator.create_observables is False
    assert indicator.score is None
    assert indicator.author.name == "offensive.agency"
    assert [m.level for m in indicator.markings] == ["clear"]


def test_transform_should_produce_valid_stix_objects(raw_feed):
    processor = _processor()

    objects = next(processor.transform(_feed(raw_feed)))

    stix_objects = [obj.to_stix2_object() for obj in objects]
    indicator_ids = {o.id for o in stix_objects if o.type == "indicator"}
    tool_ids = {o.id for o in stix_objects if o.type == "tool"}
    for relationship in (o for o in stix_objects if o.type == "relationship"):
        assert relationship.source_ref in indicator_ids
    assert all(
        o.target_ref in tool_ids
        for o in stix_objects
        if o.type == "relationship" and o.relationship_type == "indicates"
    )


def test_transform_should_apply_the_configured_tlp_and_validity(raw_feed):
    settings = make_settings({"tlp_level": "amber", "indicator_validity": "P7D"})
    processor = _processor(settings=settings)

    objects = next(processor.transform(_feed(raw_feed)))

    indicator = next(
        i for i in _of_type(objects, Indicator) if i.name == "198.51.100.1"
    )
    assert indicator.valid_until == datetime(2026, 1, 17, tzinfo=timezone.utc)
    assert all(
        [m.level for m in obj.markings] == ["amber"]
        for obj in objects
        if not isinstance(obj, (OrganizationAuthor, TLPMarking))
    )


def test_transform_should_not_create_observables_when_disabled(raw_feed):
    processor = _processor(settings=make_settings({"create_observables": False}))

    objects = next(processor.transform(_feed(raw_feed)))

    assert _of_type(objects, IPV4Address) == []
    assert _relationships(objects, "based-on") == []
    assert len(_of_type(objects, Indicator)) == 2


def test_transform_should_only_send_indicators_modified_since_the_checkpoint(raw_feed):
    state = ConnectorState(last_modified=datetime(2026, 1, 12, tzinfo=timezone.utc))
    processor = _processor(state=state)

    objects = next(processor.transform(_feed(raw_feed)))

    # The indicator of the checkpoint day is sent again, the older one is not
    assert [i.name for i in _of_type(objects, Indicator)] == ["198.51.100.2"]
    # The tools are always sent, so the relationships never point to a missing object
    assert len(_of_type(objects, Tool)) == 2


def test_transform_should_send_nothing_when_nothing_changed(raw_feed):
    state = ConnectorState(last_modified=datetime(2026, 1, 13, tzinfo=timezone.utc))
    processor = _processor(state=state)

    assert list(processor.transform(_feed(raw_feed))) == []
    assert state.last_modified == datetime(2026, 1, 13, tzinfo=timezone.utc)


def test_transform_should_move_the_checkpoint_after_each_bundle(raw_feed):
    state = ConnectorState()
    processor = _processor(state=state)
    bundles = processor.transform(_feed(raw_feed))

    next(bundles)
    assert state.last_modified is None  # not sent yet

    with pytest.raises(StopIteration):
        next(bundles)
    assert state.last_modified == datetime(2026, 1, 12, tzinfo=timezone.utc)


def test_transform_should_never_move_the_checkpoint_backwards(raw_feed):
    checkpoint = datetime(2026, 1, 12, 12, tzinfo=timezone.utc)
    raw_feed["objects"][4]["modified"] = "2026-01-12T18:00:00.000Z"
    state = ConnectorState(last_modified=checkpoint)
    processor = _processor(state=state)

    list(processor.transform(_feed(raw_feed)))

    assert state.last_modified == datetime(2026, 1, 12, 18, tzinfo=timezone.utc)


def test_transform_should_split_large_feeds_into_several_bundles(raw_feed, monkeypatch):
    monkeypatch.setattr(feed_processor_module, "INDICATORS_PER_BUNDLE", 1)
    processor = _processor()

    bundles = list(processor.transform(_feed(raw_feed)))

    assert len(bundles) == 2
    for objects in bundles:
        # Every bundle carries the author, the marking and the tools it references
        assert len(_of_type(objects, OrganizationAuthor)) == 1
        assert len(_of_type(objects, TLPMarking)) == 1
        assert len(_of_type(objects, Tool)) == 2
        assert len(_of_type(objects, Indicator)) == 1


def test_transform_should_skip_an_indicator_with_an_unsupported_pattern(raw_feed):
    raw_feed["objects"][3]["pattern"] = "[domain-name:value = 'example.com']"
    processor = _processor()

    objects = next(processor.transform(_feed(raw_feed)))

    assert [i.name for i in _of_type(objects, Indicator)] == ["198.51.100.2"]


def test_transform_should_skip_an_indicator_with_an_invalid_ip(raw_feed):
    raw_feed["objects"][3]["pattern"] = "[ipv4-addr:value = 'not-an-ip']"
    processor = _processor()

    objects = next(processor.transform(_feed(raw_feed)))

    assert [i.name for i in _of_type(objects, Indicator)] == ["198.51.100.2"]


def test_transform_should_skip_a_relationship_to_an_unknown_tool(raw_feed):
    raw_feed["objects"][7]["target_ref"] = "tool--00000000-0000-5000-8000-000000000999"
    processor = _processor()

    objects = next(processor.transform(_feed(raw_feed)))

    assert len(_relationships(objects, "indicates")) == 2


def test_transform_should_drop_an_external_reference_with_only_a_source_name(raw_feed):
    # STIX refuses an external reference with only `source_name`: it must not
    # make the run fail, on a tool or on an indicator.
    raw_feed["objects"][1]["external_references"].append({"source_name": "example"})
    raw_feed["objects"][3]["external_references"] = [{"source_name": "example"}]
    processor = _processor()

    objects = next(processor.transform(_feed(raw_feed)))

    alpha = next(t for t in _of_type(objects, Tool) if t.name == "Agent Alpha")
    assert [r.url for r in alpha.external_references] == [
        "https://example.com/agent/alpha"
    ]
    indicator = next(
        i for i in _of_type(objects, Indicator) if i.name == "198.51.100.1"
    )
    assert indicator.external_references is None


def test_transform_should_skip_an_indicator_that_stix_refuses(raw_feed):
    # valid_until (modified + 1 day) before valid_from: refused by stix2
    raw_feed["objects"][3]["valid_from"] = "2026-01-20T00:00:00.000Z"
    processor = _processor(settings=make_settings({"indicator_validity": "P1D"}))

    objects = next(processor.transform(_feed(raw_feed)))

    assert [i.name for i in _of_type(objects, Indicator)] == ["198.51.100.2"]


def test_transform_should_skip_a_tool_that_fails_and_its_relationships(raw_feed):
    with patch.object(
        feed_processor_module, "Tool", side_effect=[RuntimeError("boom"), MagicMock()]
    ):
        processor = _processor()
        tools = processor._convert_tools(_feed(raw_feed).tools)

    assert list(tools) == ["tool--00000000-0000-5000-8000-000000000102"]


def test_transform_should_set_the_checkpoint_after_the_last_of_several_bundles(
    raw_feed, monkeypatch
):
    monkeypatch.setattr(feed_processor_module, "INDICATORS_PER_BUNDLE", 1)
    state = ConnectorState()
    processor = _processor(state=state)
    bundles = processor.transform(_feed(raw_feed))

    next(bundles)
    next(bundles)
    # After the first bundle (oldest indicator, 2026-01-10)
    assert state.last_modified == datetime(2026, 1, 10, tzinfo=timezone.utc)
    list(bundles)
    assert state.last_modified == datetime(2026, 1, 12, tzinfo=timezone.utc)
