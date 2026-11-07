from unittest.mock import MagicMock

import pytest
from cybersixgill.importer import IndicatorImporter, IndicatorImporterConfig


def make_importer(feed: list[dict]) -> IndicatorImporter:
    importer = IndicatorImporter(
        IndicatorImporterConfig(
            helper=MagicMock(),
            client=MagicMock(),
            author=MagicMock(),
            create_observables=True,
            create_indicators=True,
            enable_relationships=True,
            fetch_size=1000,
        )
    )
    importer._fetch_darkfeed_data = MagicMock(return_value=feed)
    importer._process_indicator = MagicMock(return_value=True)
    return importer


def test_run_stores_a_checkpoint_mid_loop():
    # Given a feed longer than the state update interval
    feed = [{"modified": f"2026-11-03T10:00:{i:02d}.123Z"} for i in range(1, 22)]
    importer = make_importer(feed)

    # When the importer runs
    result = importer.run({"last_run": 1}, "work-id")

    # Then the checkpoint holds the 20th indicator and the run returns the last one
    importer.helper.set_state.assert_called_once_with(
        {"last_run": 1, "latest_pulse_timestamp": "2026-11-03T10:00:20.123000"}
    )
    assert result == {"latest_pulse_timestamp": "2026-11-03T10:00:21.123000"}
    assert importer._process_indicator.call_count == 21


def test_run_with_an_empty_feed_leaves_the_state_unchanged():
    importer = make_importer([])

    assert importer.run({"last_run": 1}, "work-id") == {}
    importer.helper.set_state.assert_not_called()


def test_run_fails_when_the_last_indicator_has_no_modified_timestamp():
    importer = make_importer([{"modified": "2026-11-03T10:00:01.123Z"}, {}])

    with pytest.raises(TypeError):
        importer.run({"last_run": 1}, "work-id")
