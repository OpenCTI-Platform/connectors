"""Tests for ReportsProcessor: fetching, filtering, checkpointing."""

import datetime as dt
import logging

import pytest
import requests
from conftest import load_fixture, make_settings
from connector import ConnectorState
from connector.data_processors import ReportsProcessor, reports_processor
from connectors_sdk.client.exceptions import ApiRateLimitError, ApiServerError
from connectors_sdk.exceptions.error import DataRetrievalError
from rosti_client.models import (
    IOC,
    InvalidReportSummary,
    Report,
    ReportBundle,
    Yara,
)

UTC = dt.timezone.utc


def summary(report_id: str, last_updated: str) -> Report:
    return Report.model_validate(
        {
            "id": report_id,
            "title": f"Report {report_id}",
            "date": "2026-10-01",
            "url": f"https://example.com/{report_id}",
            "authors": [],
            "tags": [],
            "count": {"iocs": 1, "yara_rules": 0, "mitre_ids": 0},
            "checksum": "x",
            "last_updated": last_updated,
        }
    )


class FakeClient:
    """In-memory replacement for RostiClient."""

    def __init__(self, pages, fail_on=None):
        self.pages = pages
        self.fail_on = fail_on
        self.since = None
        self.detail_calls = []

    def iter_updated_reports(self, since):
        self.since = since
        yield from self.pages

    def get_report(self, report_id):
        if report_id == self.fail_on:
            raise ApiRateLimitError(
                "Rate limited (429) on GET /reports/B",
                response_body={
                    "type": "https://iana.org/assignments/http-problem-types#quota-exceeded",
                    "title": "Daily quota exceeded",
                    "detail": "Your free plan allows 1000 requests per day.",
                    "reset": "2026-10-08T00:00:00Z",
                },
            )
        self.detail_calls.append(report_id)
        for page in self.pages:
            for report in page:
                if report.id == report_id:
                    return report.model_copy()
        raise KeyError(report_id)

    def iter_report_ioc_groups(self, report_id):
        yield [
            IOC.model_validate(
                {
                    "id": f"ioc-{report_id}",
                    "type": "domain",
                    "value": f"{report_id.lower()}.evil.example",
                    "date": "2026-10-01",
                    "ids": True,
                    "report": report_id,
                }
            )
        ]

    def get_report_yara_rules(self, report_id):
        return []


def make_processor(client, state=None, fake_logger=None, **settings):
    processor = ReportsProcessor(client=client)
    processor.settings = make_settings(**settings)
    processor.state = state or ConnectorState()
    processor.logger = fake_logger
    processor.helper = None
    processor.post_init()
    return processor


def run(processor):
    """Run collect+transform the way BaseDataProcessor.send consumes them."""
    return list(processor.transform(processor.collect()))


def test_first_run_starts_from_import_since(fake_logger):
    client = FakeClient([[summary("A", "2026-10-01T10:00:00Z")]])
    processor = make_processor(client, fake_logger=fake_logger)
    run(processor)
    assert client.since == dt.datetime(2026, 9, 1, tzinfo=UTC)


def test_one_bundle_per_report_and_checkpoint(fake_logger):
    client = FakeClient(
        [[summary("A", "2026-10-01T10:00:00Z"), summary("B", "2026-10-01T11:00:00Z")]]
    )
    processor = make_processor(client, fake_logger=fake_logger)
    bundles = run(processor)

    assert len(bundles) == 2
    assert processor.state.last_report_updated == dt.datetime(
        2026, 10, 1, 11, tzinfo=UTC
    )
    assert processor.state.last_report_ids == ["B"]


def test_next_run_overlaps_and_skips_sent_reports(fake_logger):
    state = ConnectorState(
        last_report_updated=dt.datetime(2026, 10, 1, 11, tzinfo=UTC),
        last_report_ids=["B"],
    )
    client = FakeClient(
        [[summary("B", "2026-10-01T11:00:00Z"), summary("C", "2026-10-01T11:00:00Z")]]
    )
    processor = make_processor(client, state=state, fake_logger=fake_logger)
    bundles = run(processor)

    assert client.since == dt.datetime(2026, 10, 1, 10, 59, 59, tzinfo=UTC)
    assert client.detail_calls == ["C"]
    assert len(bundles) == 1
    assert processor.state.last_report_ids == ["B", "C"]


def test_quota_exceeded_keeps_checkpoint_of_last_sent_report(fake_logger):
    client = FakeClient(
        [[summary("A", "2026-10-01T10:00:00Z"), summary("B", "2026-10-01T11:00:00Z")]],
        fail_on="B",
    )
    processor = make_processor(client, fake_logger=fake_logger)
    bundles = run(processor)

    assert len(bundles) == 1
    assert processor.state.last_report_updated == dt.datetime(
        2026, 10, 1, 10, tzinfo=UTC
    )
    [quota] = fake_logger.find(
        "Rösti API quota exceeded, the import continues from the last "
        "checkpoint on the first run after the quota resets"
    )
    assert quota.level == "warning"
    assert quota.meta == {
        "detail": "Your free plan allows 1000 requests per day.",
        "reset": "2026-10-08T00:00:00Z",
        "reports_sent": 1,
    }
    assert not any(level == "error" for level, _ in fake_logger.messages)


def test_bundle_contains_report_with_all_refs(fake_logger):
    report = Report.model_validate(load_fixture("report_r1xSdqAy.json"))
    iocs = [
        IOC.model_validate(i) for i in load_fixture("report_r1xSdqAy_iocs.json")["data"]
    ]
    yara = [Yara.model_validate(y) for y in load_fixture("yara_rules.json")["data"]]

    processor = make_processor(FakeClient([]), fake_logger=fake_logger)
    objects = processor.convert_bundle(
        ReportBundle(report=report, iocs=iocs, yara_rules=yara)
    )
    stix = [
        o.to_stix2_object() if hasattr(o, "to_stix2_object") else o for o in objects
    ]
    stix_report = [o for o in stix if o["type"] == "report"][0]
    ids = {o["id"] for o in stix}

    # 16 IOCs -> 16 indicators + 16 observables + 16 relationships; 2 YARA; 2 CVEs
    assert len(stix_report["object_refs"]) == 16 * 3 + 2 + 2
    assert set(stix_report["object_refs"]) <= ids
    assert (
        sum(1 for o in stix if o["type"] == "indicator" and o["pattern_type"] == "yara")
        == 2
    )


def test_ioc_filters(fake_logger):
    processor = make_processor(
        FakeClient([]),
        fake_logger=fake_logger,
        ids_only=True,
        max_risk_level=2,
        ioc_types="domain,ip",
    )

    def ioc(**kw):
        base = {
            "id": "i",
            "type": "domain",
            "value": "x.example",
            "date": "2026-10-01",
            "ids": True,
            "report": "r",
        }
        return IOC.model_validate({**base, **kw})

    assert processor._keep_ioc(ioc())
    assert not processor._keep_ioc(ioc(ids=False))
    assert not processor._keep_ioc(ioc(type="url", value="http://x"))
    assert not processor._keep_ioc(
        ioc(risk={"level": 3, "meaning": "medium", "msg": ""})
    )
    assert processor._keep_ioc(
        ioc(risk={"level": -1, "meaning": "informational", "msg": ""})
    )


def test_hidden_yara_is_not_fetched(fake_logger):
    class YaraClient(FakeClient):
        yara_calls = 0

        def get_report_yara_rules(self, report_id):
            YaraClient.yara_calls += 1
            return []

    data = summary("A", "2026-10-01T10:00:00Z").model_dump()
    data["count"]["yara_rules"] = 2
    data["notes"] = [{"action": "hide_yara", "comment": "requested by the publisher"}]
    hidden = Report.model_validate(data)
    processor = make_processor(YaraClient([[hidden]]), fake_logger=fake_logger)
    run(processor)
    assert YaraClient.yara_calls == 0


class FakeOpenCTI:
    """Minimal stand-in for `helper.api.stix_domain_object.read(id=...)`."""

    def __init__(self, existing_ids):
        self.existing_ids = set(existing_ids)
        self.reads = []
        self.api = self
        self.stix_domain_object = self

    def read(self, id):  # pylint: disable=redefined-builtin
        self.reads.append(id)
        return {"standard_id": id} if id in self.existing_ids else None


def test_software_resolves_to_existing_tool(fake_logger):
    from pycti import Malware, Tool
    from rosti_client.models import Mitre

    tool_id = Tool.generate_id("Mimikatz")
    processor = make_processor(FakeClient([]), fake_logger=fake_logger)
    processor.helper = FakeOpenCTI([tool_id])

    entry = Mitre(id="S0002", description="Mimikatz", object_type="software")
    ref = processor._resolve_software(entry)

    assert ref.id == tool_id
    assert processor.helper.reads == [Malware.generate_id("Mimikatz"), tool_id]
    # cached: no second lookup
    processor._resolve_software(entry)
    assert len(processor.helper.reads) == 2


def test_unknown_software_is_not_linked(fake_logger):
    from rosti_client.models import Mitre

    processor = make_processor(FakeClient([]), fake_logger=fake_logger)
    processor.helper = FakeOpenCTI([])
    entry = Mitre(id="S9999", description="Nope", object_type="software")
    assert processor._resolve_software(entry) is None


def _report(report_id="oGmTvDQn"):
    return Report.model_validate(
        {
            "id": report_id,
            "title": "Grouped",
            "date": "2026-10-06",
            "url": "https://example.com/r",
        }
    )


def _stix_report(objects):
    stix = [
        o.to_stix2_object() if hasattr(o, "to_stix2_object") else o for o in objects
    ]
    return [o for o in stix if o["type"] == "report"][0], stix


def test_grouped_iocs_in_a_report(fake_logger):
    iocs = load_fixture("report_oGmTvDQn_iocs.json")["data"]
    processor = make_processor(FakeClient([]), fake_logger=fake_logger)
    objects = processor.convert_bundle(ReportBundle(report=_report(), iocs=iocs))
    stix_report, stix = _stix_report(objects)

    # standalone SHA-256: indicator + file + based-on;
    # MD5 + SHA-1 group: one indicator + one file + based-on
    assert len(stix_report["object_refs"]) == 6
    assert sum(1 for o in stix if o["type"] == "indicator") == 2
    files = [o for o in stix if o["type"] == "file"]
    assert sorted(len(f["hashes"]) for f in files) == [1, 2]
    assert set(stix_report["object_refs"]) <= {o["id"] for o in stix}


def test_filtered_member_leaves_the_rest_of_the_group(fake_logger):
    iocs = load_fixture("report_oGmTvDQn_iocs.json")["data"]
    iocs[2]["ids"] = False  # the MD5 of the group
    processor = make_processor(FakeClient([]), fake_logger=fake_logger, ids_only=True)
    objects = processor.convert_bundle(ReportBundle(report=_report(), iocs=iocs))
    _, stix = _stix_report(objects)
    patterns = sorted(o["pattern"] for o in stix if o["type"] == "indicator")
    assert len(patterns) == 2
    assert all("MD5" not in p for p in patterns)


def test_entity_ref_split_in_the_response_is_logged(fake_logger):
    def ioc(i, ref, value):
        return {
            "id": i,
            "type": "md5",
            "value": value,
            "date": "2026-10-06",
            "report": "r",
            "entity_ref": ref,
        }

    iocs = [
        ioc("a", "x", "1" * 32),
        ioc("b", None, "2" * 32),
        ioc("c", "x", "3" * 32),
    ]
    processor = make_processor(FakeClient([]), fake_logger=fake_logger)
    processor.convert_bundle(ReportBundle(report=_report(), iocs=iocs))
    assert any(
        level == "warning" and "not next to each other" in message
        for level, message in fake_logger.messages
    )


def two_reports():
    return [
        [summary("A", "2026-10-01T10:00:00Z"), summary("B", "2026-10-01T11:00:00Z")]
    ]


@pytest.mark.parametrize(
    "error",
    [
        ApiServerError("Server error (502) on GET /reports/B", status_code=502),
        requests.ConnectionError("Connection refused"),
    ],
    ids=["api_error", "network_error"],
)
def test_api_and_network_errors_fail_the_run(fake_logger, error):
    """Not skipped: the SDK marks the work as failed and keeps the old checkpoint."""

    class BrokenClient(FakeClient):
        def get_report(self, report_id):
            if report_id == "B":
                raise error
            return super().get_report(report_id)

    processor = make_processor(BrokenClient(two_reports()), fake_logger=fake_logger)
    bundles = []
    with pytest.raises(DataRetrievalError) as raised:
        for bundle in processor.transform(processor.collect()):
            bundles.append(bundle)
    assert raised.value.__cause__ is error
    assert str(error) in str(raised.value)
    assert "Reports imported before the error: 1." in str(raised.value)
    assert len(bundles) == 1
    # Logged once, by the SDK, not by the processor
    assert not any(level == "error" for level, _ in fake_logger.messages)


def test_api_error_while_loading_ioc_pages_fails_the_run(fake_logger):
    class BrokenClient(FakeClient):
        def iter_report_ioc_groups(self, report_id):
            yield from super().iter_report_ioc_groups(report_id)
            raise ApiServerError("Server error (503)", status_code=503)

    processor = make_processor(BrokenClient(two_reports()), fake_logger=fake_logger)
    with pytest.raises(DataRetrievalError) as raised:
        run(processor)
    assert "while importing report A" in str(raised.value)
    assert processor.state.last_report_updated is None
    assert not fake_logger.find("Failed to convert report, skipping it")


def test_report_that_fails_to_convert_is_skipped(fake_logger, monkeypatch):
    """One broken report must not block the import of the following ones."""
    client = FakeClient(two_reports())
    processor = make_processor(client, fake_logger=fake_logger)
    original = processor.converter.convert_report

    def broken(report, refs):
        if report.id == "A":
            raise ValueError("unexpected data")
        return original(report, refs)

    monkeypatch.setattr(processor.converter, "convert_report", broken)
    bundles = run(processor)

    assert client.detail_calls == ["A", "B"]
    assert [b[-1]["name"] for b in bundles] == ["Report B"]
    [skipped] = fake_logger.find("Failed to convert report, skipping it")
    assert skipped.level == "warning"
    assert skipped.meta == {
        "report_id": "A",
        "error": "unexpected data",
        "bundles_sent": 0,
    }
    # the checkpoint moved past both reports
    assert processor.state.last_report_updated == dt.datetime(
        2026, 10, 1, 11, tzinfo=UTC
    )
    [finished] = fake_logger.find("Rösti import finished")
    assert finished.meta == {"reports_sent": 1, "reports_skipped": 1}


def test_invalid_ioc_page_skips_the_report(fake_logger, monkeypatch):
    """A page that does not match the data model is a data error: skip, don't retry."""
    monkeypatch.setattr(reports_processor, "MAX_BUNDLE_OBJECTS", 3)

    class InvalidPageClient(FakeClient):
        def iter_report_ioc_groups(self, report_id):
            yield from super().iter_report_ioc_groups(report_id)
            if report_id == "A":
                IOC.model_validate({"id": "x", "type": "domain"})  # raises

    processor = make_processor(
        InvalidPageClient(two_reports()), fake_logger=fake_logger
    )
    bundles = run(processor)

    reports = [
        o.name for b in bundles for o in b if getattr(o, "type", None) == "report"
    ]
    assert reports == ["Report B"]
    # A: one IOC bundle was sent before the error, then the report was skipped
    assert any(getattr(o, "name", None) == "a.evil.example" for o in bundles[0])
    [skipped] = fake_logger.find("Failed to convert report, skipping it")
    assert skipped.meta["report_id"] == "A"
    assert skipped.meta["bundles_sent"] == 1
    assert processor.state.last_report_ids == ["B"]


def test_unreadable_report_details_are_skipped(fake_logger):
    class InvalidDetailClient(FakeClient):
        def get_report(self, report_id):
            if report_id == "A":
                return Report.model_validate({"id": "A"})  # raises
            return super().get_report(report_id)

    processor = make_processor(
        InvalidDetailClient(two_reports()), fake_logger=fake_logger
    )
    bundles = run(processor)

    assert [b[-1]["name"] for b in bundles] == ["Report B"]
    [skipped] = fake_logger.find("Failed to convert report, skipping it")
    assert skipped.meta["report_id"] == "A"
    assert "validation error" in skipped.meta["error"]
    assert processor.state.last_report_updated == dt.datetime(
        2026, 10, 1, 11, tzinfo=UTC
    )


def test_malformed_list_entries_are_skipped(fake_logger):
    """One broken entry in the report list must not block the reports after it."""
    bad = InvalidReportSummary(
        "A", dt.datetime(2026, 10, 1, 10, tzinfo=UTC), "title: Input should be a string"
    )
    no_id = InvalidReportSummary(None, None, "id: Field required")
    client = FakeClient([[bad, no_id, summary("B", "2026-10-01T11:00:00Z")]])
    processor = make_processor(client, fake_logger=fake_logger)
    bundles = run(processor)

    assert client.detail_calls == ["B"]
    assert [b[-1]["name"] for b in bundles] == ["Report B"]
    skipped = fake_logger.find("Failed to convert report, skipping it")
    assert [r.meta["report_id"] for r in skipped] == ["A", None]
    assert skipped[0].meta["error"] == "title: Input should be a string"
    assert processor.state.last_report_updated == dt.datetime(
        2026, 10, 1, 11, tzinfo=UTC
    )
    assert processor.state.last_report_ids == ["B"]
    [finished] = fake_logger.find("Rösti import finished")
    assert finished.meta == {"reports_sent": 1, "reports_skipped": 2}


def test_report_objects_are_only_replaced_when_enabled(fake_logger):
    report_bundle = ReportBundle(report=_report(), iocs=[])
    default = make_processor(FakeClient([]), fake_logger=fake_logger)
    replacing = make_processor(
        FakeClient([]), fake_logger=fake_logger, replace_report_objects=True
    )
    assert "opencti_upsert_operations" not in default.convert_bundle(report_bundle)[-1]
    assert replacing.convert_bundle(report_bundle)[-1]["opencti_upsert_operations"]


def test_log_context_is_passed_as_meta(fake_logger):
    """The SDK logger only keeps context given as `meta=` (connectors-sdk #8005)."""
    iocs = [
        {
            "id": "a",
            "type": "md5",
            "value": "not-a-hash",
            "date": "2026-10-06",
            "report": "r",
        }
    ]
    processor = make_processor(FakeClient([]), fake_logger=fake_logger)
    processor.convert_bundle(ReportBundle(report=_report(), iocs=iocs))
    [skipped] = fake_logger.find("IOC skipped")
    assert skipped.meta == {
        "report_id": _report().id,
        "ioc_id": "a",
        "type": "md5",
        "value": "not-a-hash",
        "reason": "Invalid MD5 hash: 'not-a-hash'",
    }
    assert all(record.meta for record in fake_logger.records)


def test_context_reaches_the_sdk_logger(caplog):
    """With the SDK's real logger, the context ends up in the record's attributes."""
    processor = ReportsProcessor(client=FakeClient([]))
    processor.settings = make_settings()
    processor.state = ConnectorState()
    processor.helper = None
    processor.post_init()
    iocs = [
        {
            "id": "a",
            "type": "md5",
            "value": "not-a-hash",
            "date": "2026-10-06",
            "report": "r",
        }
    ]
    with caplog.at_level(logging.DEBUG, logger=reports_processor.__name__):
        processor.convert_bundle(ReportBundle(report=_report(), iocs=iocs))
    [record] = [r for r in caplog.records if r.getMessage() == "IOC skipped"]
    assert record.levelname == "WARNING"
    assert record.attributes["ioc_id"] == "a"
    assert record.attributes["reason"] == "Invalid MD5 hash: 'not-a-hash'"


def test_software_lookup_cache_is_reset_every_run(fake_logger):
    processor = make_processor(FakeClient([]), fake_logger=fake_logger)
    processor._software_cache = {"S0002": None}
    run(processor)
    assert processor._software_cache == {}


def _many_iocs(report_id, count):
    return [
        IOC.model_validate(
            {
                "id": f"{report_id}-{i}",
                "type": "domain",
                "value": f"host{i}.{report_id.lower()}.example",
                "date": "2026-10-01",
                "ids": True,
                "report": report_id,
            }
        )
        for i in range(count)
    ]


def test_large_reports_are_sent_in_bounded_bundles(fake_logger, monkeypatch):
    monkeypatch.setattr(reports_processor, "MAX_BUNDLE_OBJECTS", 30)
    pulled = []

    class LargeClient(FakeClient):
        def iter_report_ioc_groups(self, report_id):
            for ioc in _many_iocs(report_id, 25):  # 25 IOCs -> 75 objects
                pulled.append(ioc.id)
                yield [ioc]

    client = LargeClient([[summary("A", "2026-10-01T10:00:00Z")]])
    processor = make_processor(client, fake_logger=fake_logger)
    chunks = processor.transform(processor.collect())

    first = next(chunks)
    # streamed: only the IOCs needed for the first bundle have been fetched
    assert len(pulled) == 10
    assert processor.state.last_report_updated is None
    rest = list(chunks)
    bundles = [first, *rest]

    assert len(bundles) == 3
    for bundle in bundles:
        assert bundle[0] is processor.converter.author
        assert bundle[1] is processor.converter.tlp_marking
        assert len(bundle) - 2 <= 30 + 1
    reports = [o for b in bundles for o in b if getattr(o, "type", None) == "report"]
    assert len(reports) == 1 and reports[0] is bundles[-1][-1]
    sent_ids = {o.id for b in bundles for o in b[2:]} - {reports[0].id}
    assert set(reports[0]["object_refs"]) == sent_ids
    assert len(reports[0]["object_refs"]) == 75
    # the checkpoint moves only after the last bundle of the report
    assert processor.state.last_report_updated == dt.datetime(
        2026, 10, 1, 10, tzinfo=UTC
    )


def test_skipped_iocs_are_logged_as_warnings(fake_logger):
    def ioc(i, ioc_type, value):
        return {
            "id": i,
            "type": ioc_type,
            "value": value,
            "date": "2026-10-06",
            "report": "r",
        }

    iocs = [ioc("a", "md5", "not-a-hash"), ioc("b", "port", "4444")]
    processor = make_processor(FakeClient([]), fake_logger=fake_logger)
    processor.convert_bundle(ReportBundle(report=_report(), iocs=iocs))
    skipped = [
        level for level, message in fake_logger.messages if message == "IOC skipped"
    ]
    # invalid value: warning; a type that is never imported: debug
    assert skipped == ["warning", "debug"]
