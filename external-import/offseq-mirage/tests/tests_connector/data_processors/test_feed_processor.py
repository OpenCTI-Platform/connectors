from unittest.mock import MagicMock

import fixtures
from connector.data_processors import MirageFeedProcessor
from connector.state import ConnectorState
from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    AttackPattern,
    Indicator,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
    Vulnerability,
)


def _processor(connector_settings, fake_logger, bundle, state=None):
    class Dummy(MirageFeedProcessor):
        def inject_dependencies(self):
            self.settings = connector_settings
            self.state = state or ConnectorState()
            self.work_manager = MagicMock()
            self.logger = fake_logger

        def post_init(self):
            super().post_init()
            self.client = MagicMock(get_bundle=MagicMock(return_value=bundle))

    p = Dummy()
    p.inject_dependencies()
    p.post_init()
    return p


def _objects(processor):
    return [o for chunk in processor.transform(processor.collect()) for o in chunk]


def test_is_a_base_data_processor():
    assert issubclass(MirageFeedProcessor, BaseDataProcessor)


def test_converts_indicators_targets_and_relationships(connector_settings, fake_logger):
    p = _processor(connector_settings, fake_logger, fixtures.bundle())
    objects = _objects(p)

    assert isinstance(objects[0], OrganizationAuthor)
    assert isinstance(objects[1], TLPMarking)
    indicators = [o for o in objects if isinstance(o, Indicator)]
    assert {i.main_observable_type for i in indicators} == {"IPv4-Addr", "Url"}
    ip = next(i for i in indicators if i.main_observable_type == "IPv4-Addr")
    assert ip.score == 46
    assert ip.valid_until.isoformat() == "2026-11-18T23:00:00+00:00"
    assert ip.author is p.author and ip.markings == [p.tlp_marking]

    ap = next(o for o in objects if isinstance(o, AttackPattern))
    assert ap.mitre_id == "T1190"
    vuln = next(o for o in objects if isinstance(o, Vulnerability))
    assert vuln.is_cisa_kev is True
    rels = [o for o in objects if isinstance(o, Relationship)]
    assert {(r.type, type(r.target)) for r in rels} == {
        ("indicates", AttackPattern),
        ("related-to", Vulnerability),
    }

    for o in objects:
        o.to_stix2_object()
    assert p.state.last_bundle_id == fixtures.bundle()["id"]


def test_ids_are_deterministic(connector_settings, fake_logger):
    def ids():
        p = _processor(connector_settings, fake_logger, fixtures.bundle())
        return [o.id for o in _objects(p)]

    assert ids() == ids()


def test_unchanged_bundle_is_skipped(connector_settings, fake_logger):
    state = ConnectorState(last_bundle_id=fixtures.bundle()["id"])
    p = _processor(connector_settings, fake_logger, fixtures.bundle(), state)
    assert _objects(p) == []


def test_relationships_can_be_disabled(connector_settings, fake_logger):
    settings = connector_settings.model_copy(
        update={
            "offseq_mirage": connector_settings.offseq_mirage.model_copy(
                update={"import_relationships": False}
            )
        }
    )
    p = _processor(settings, fake_logger, fixtures.bundle())
    objects = _objects(p)
    assert not [o for o in objects if isinstance(o, (Relationship, AttackPattern))]


def test_bad_indicator_is_skipped_not_fatal(connector_settings, fake_logger):
    bundle = fixtures.bundle()
    bundle["objects"][1]["pattern"] = "[x-custom:value = 'a']"
    bundle["objects"][2].pop("valid_from")
    p = _processor(connector_settings, fake_logger, bundle)
    objects = _objects(p)
    assert not [o for o in objects if isinstance(o, Indicator)]
    assert not [o for o in objects if isinstance(o, Relationship)]
    assert len(fake_logger.warnings) == 2
    assert p.state.last_bundle_id == bundle["id"]


def test_batches_repeat_author_marking_and_used_targets(
    connector_settings, fake_logger
):
    bundle = fixtures.bundle()
    extra = [
        {
            **bundle["objects"][1],
            "id": f"indicator--{i:08d}-0000-5000-8000-000000000000",
            "pattern": f"[ipv4-addr:value = '203.0.113.{i}']",
        }
        for i in range(150)
    ]
    bundle["objects"][1:1] = extra
    p = _processor(connector_settings, fake_logger, bundle)
    chunks = list(p.transform(p.collect()))
    assert len(chunks) == 2
    for chunk in chunks:
        assert isinstance(chunk[0], OrganizationAuthor)
        assert isinstance(chunk[1], TLPMarking)
        refs = {r.target.id for r in chunk if isinstance(r, Relationship)}
        present = {o.id for o in chunk}
        assert refs <= present
