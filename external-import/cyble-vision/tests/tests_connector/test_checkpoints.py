"""A service or product without its own checkpoint must not inherit last_run."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from connector import ConnectorState
from connector.data_processors import (
    AdvisoriesProcessor,
    AlertsProcessor,
    NewsfeedProcessor,
)
from connectors_sdk import ApiClientError
from connectors_sdk.models import OrganizationAuthor, TLPMarking

# A previous run an hour ago, well after the default 7-day import_since.
LAST_RUN = datetime.now(timezone.utc) - timedelta(hours=1)
FIXTURES = Path(__file__).parents[1] / "fixtures"


class _Logger:
    def info(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None


class _Client:
    def __init__(self, pages):
        self.pages = pages
        self.since = {}

    def list_services(self):
        return list(self.pages)

    def iter_alerts(self, service, since, until, exclude_statuses):
        self.since[service] = since
        result = self.pages[service]
        if isinstance(result, Exception):
            raise result
        yield from result


def _alerts_processor(connector_settings, pages, state=None):
    processor = AlertsProcessor.__new__(AlertsProcessor)
    processor.settings = connector_settings
    processor.state = state or ConnectorState(last_run=LAST_RUN)
    processor.logger = _Logger()
    processor.client = _Client(pages)
    return processor


def test_service_without_checkpoint_starts_from_import_since(connector_settings):
    processor = _alerts_processor(connector_settings, {"github": []})
    list(processor.collect())

    since = processor.client.since["github"]
    assert since == connector_settings.cyble_vision.import_since
    assert since < LAST_RUN


def test_successful_empty_service_records_its_window(connector_settings):
    processor = _alerts_processor(connector_settings, {"github": []})
    before = datetime.now(timezone.utc)
    list(processor.collect())

    checkpoint = datetime.fromisoformat(processor.state.last_alert_created_at["github"])
    assert checkpoint >= before


def test_failed_service_keeps_no_checkpoint(connector_settings):
    processor = _alerts_processor(
        connector_settings,
        {"github": ApiClientError("boom"), "pastebin": []},
    )
    list(processor.collect())

    assert "github" not in processor.state.last_alert_created_at
    assert "pastebin" in processor.state.last_alert_created_at


def test_existing_checkpoint_is_used(connector_settings):
    checkpoint = LAST_RUN - timedelta(days=3)
    state = ConnectorState(
        last_run=LAST_RUN,
        last_alert_created_at={"github": checkpoint.isoformat()},
    )
    processor = _alerts_processor(connector_settings, {"github": []}, state)
    list(processor.collect())

    assert processor.client.since["github"] == checkpoint


def test_engine_product_without_checkpoint_starts_from_import_since(
    connector_settings,
):
    processor = AdvisoriesProcessor.__new__(AdvisoriesProcessor)
    processor.settings = connector_settings
    processor.state = ConnectorState(last_run=LAST_RUN)

    since, _ = processor.window(None)
    assert since == connector_settings.cyble_vision.import_since


def test_newsfeed_checkpoint_follows_post_date_not_created_at():
    item = json.loads((FIXTURES / "engine_newsfeed.json").read_text())
    processor = NewsfeedProcessor.__new__(NewsfeedProcessor)
    processor.state = ConnectorState()
    processor.logger = _Logger()
    processor.author = OrganizationAuthor(name="Cyble")
    processor.default_marking = TLPMarking(level="amber")

    list(processor.transform(iter([[item]])))

    # post_date is 2025-07-14; created_at (2025-08-28) must not move the cursor.
    assert processor.state.last_newsfeed_post_date.startswith("2025-07-14")
