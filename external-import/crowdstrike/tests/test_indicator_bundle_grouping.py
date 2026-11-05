from unittest.mock import MagicMock

import pytest
from crowdstrike_feeds_connector.indicator.importer import (
    IndicatorImporter,
    IndicatorImporterConfig,
)
from pycti import Identity as PyctiIdentity
from stix2 import TLP_AMBER, Bundle, Identity, Malware


def _importer(bundle_size: int) -> IndicatorImporter:
    config = IndicatorImporterConfig(
        config=MagicMock(),
        helper=MagicMock(),
        author=MagicMock(),
        default_latest_timestamp=0,
        tlp_marking=MagicMock(),
        create_observables=True,
        create_indicators=True,
        exclude_types=[],
        report_status=0,
        report_type="threat-report",
        default_x_opencti_score=50,
        indicator_low_score=40,
        indicator_low_score_labels=set(),
        indicator_medium_score=60,
        indicator_medium_score_labels=set(),
        indicator_high_score=80,
        indicator_high_score_labels=set(),
        indicator_unwanted_labels=set(),
        indicator_max_age_by_type={},
        no_file_trigger_import=True,
        scopes={"indicator"},
        attack_lookup=None,
        bundle_size=bundle_size,
    )
    importer = IndicatorImporter(config)
    importer._send_bundle = MagicMock()
    return importer


AUTHOR = Identity(
    id=PyctiIdentity.generate_id("CrowdStrike", "organization"),
    name="CrowdStrike",
    identity_class="organization",
)
MALWARE = Malware(
    id="malware--a1b2c3d4-0000-4000-8000-000000000001",
    name="Shared",
    is_family=True,
)


def _bundle(indicator) -> Bundle:
    index = indicator["id"] if isinstance(indicator, dict) else indicator
    own = Malware(
        id=f"malware--a1b2c3d4-0000-4000-8000-{index + 100:012d}",
        name=f"Own {index}",
        is_family=True,
    )
    return Bundle(objects=[AUTHOR, TLP_AMBER, MALWARE, own], allow_custom=True)


@pytest.mark.parametrize(
    "bundle_size,expected_sizes", [(1, [4, 4, 4, 4, 4]), (2, [5, 5, 4]), (500, [8])]
)
def test_indicators_are_sent_in_bundles_of_bundle_size(bundle_size, expected_sizes):
    importer = _importer(bundle_size)
    importer._create_indicator_bundle = MagicMock(side_effect=_bundle)
    indicators = [
        {"id": i, "last_updated": 1700000000 + i, "published_date": None}
        for i in range(5)
    ]

    importer._process_indicators(indicators)

    sent = [call.args[0] for call in importer._send_bundle.call_args_list]
    assert [len(bundle.objects) for bundle in sent] == expected_sizes
    # Shared objects appear once per bundle, every indicator's own object once.
    for bundle in sent:
        ids = [obj["id"] for obj in bundle.objects]
        assert len(ids) == len(set(ids))
    own_ids = {
        obj["id"]
        for bundle in sent
        for obj in bundle.objects
        if obj["type"] == "malware" and obj["name"].startswith("Own")
    }
    assert len(own_ids) == 5


def test_discarded_indicator_is_not_sent():
    importer = _importer(500)
    importer._create_indicator_bundle = MagicMock(side_effect=[None, _bundle(1)])
    indicators = [
        {"id": i, "last_updated": 1700000000 + i, "published_date": None}
        for i in range(2)
    ]

    importer._process_indicators(indicators)

    importer._send_bundle.assert_called_once()
    assert len(importer._send_bundle.call_args.args[0].objects) == 4
