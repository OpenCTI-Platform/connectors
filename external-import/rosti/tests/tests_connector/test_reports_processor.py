"""Tests for ReportsProcessor: fetching, filtering, checkpointing."""

import datetime as dt

from conftest import load_fixture, make_settings
from connector import ConnectorState
from connector.data_processors import ReportsProcessor
from connectors_sdk.client.exceptions import ApiRateLimitError, ApiServerError
from rosti_client.models import IOC, Report, ReportBundle, Yara

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

    def get_report_ioc_groups(self, report_id):
        return [
            [
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
    assert (
        "warning",
        "Rösti API quota exceeded, the import continues from the last "
        "checkpoint on the first run after the quota resets",
    ) in fake_logger.messages
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


def test_other_api_errors_are_logged_as_errors(fake_logger):
    class BrokenClient(FakeClient):
        def get_report(self, report_id):
            raise ApiServerError(
                "Server error (502) on GET /reports/A", status_code=502
            )

    client = BrokenClient([[summary("A", "2026-10-01T10:00:00Z")]])
    processor = make_processor(client, fake_logger=fake_logger)
    assert run(processor) == []
    assert processor.state.last_report_updated is None
    assert (
        "error",
        "Import interrupted, will resume from the last checkpoint on the next run",
    ) in fake_logger.messages
