"""Security, budget, graph, and STIX tests for passive capture evidence."""

# pylint: disable=no-member,protected-access,wrong-import-order

import base64
import hashlib
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import stix2
from connector.evidence import EvidenceBudget, EvidenceDecoder
from pycti import OpenCTIConnectorHelper

from tests.test_connector import make_connector

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)
HTML = (
    b"<!doctype html><html><body><img src='http://never-fetch.invalid/x'></body></html>"
)


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decoder(max_item=1024, max_count=10, max_bytes=4096, max_serialized=None):
    logger = MagicMock()
    budget = EvidenceBudget(max_count, max_bytes, max_serialized)
    return EvidenceDecoder(logger, max_item, budget), logger, budget


@pytest.mark.parametrize(
    ("kind", "content", "mime"),
    [("screen", PNG, "image/png"), ("source", HTML, "text/html")],
)
def test_valid_capture_is_strictly_decoded_and_hashed(kind, content, mime):
    evidence, _, budget = decoder()

    result = evidence.decode(encoded(content), kind, "claim", "claim-1")

    assert result is not None
    assert result.content == content
    assert result.mime_type == mime
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert budget.count == 1
    assert budget.bytes == len(content)


@pytest.mark.parametrize(
    ("value", "media_type", "expected_mime"),
    [
        ("plain note", "txt", "text/plain"),
        ("<html>note</html>", "text/html", "text/html"),
        ("implicit plain", None, "text/plain"),
    ],
)
def test_note_original_is_exact_bounded_passive_evidence(
    value, media_type, expected_mime
):
    evidence, logger, budget = decoder()
    result = evidence.decode_note_original(value, media_type, "note-1")
    assert result.kind == "ransom-note"
    assert result.content == value.encode()
    assert result.mime_type == expected_mime
    assert budget.count == 1
    logger.info.assert_called_once()


@pytest.mark.parametrize(
    ("value", "media_type", "max_item", "max_count"),
    [
        (None, "txt", 1024, 10),
        ("", "txt", 1024, 10),
        ("too long", "txt", 2, 10),
        ("binary", "application/octet-stream", 1024, 10),
        ("budget", "txt", 1024, 0),
    ],
)
def test_note_original_rejections_are_content_free(
    value, media_type, max_item, max_count
):
    evidence, logger, _ = decoder(max_item=max_item, max_count=max_count)
    assert evidence.decode_note_original(value, media_type, "private-note") is None
    logged = repr(logger.warning.call_args)
    assert "private-note" not in logged
    assert "actor-profile-note" in logged


def test_torrent_metainfo_is_bounded_passive_and_content_hashed():
    evidence, _, budget = decoder()
    content = b"d3:fooe"
    result = evidence.decode_torrent_file(
        "data:application/x-bittorrent;base64," + encoded(content), "torrent-1"
    )
    assert result.kind == "torrent"
    assert result.mime_type == "application/x-bittorrent"
    assert result.content == content
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert budget.count == 1


@pytest.mark.parametrize(
    "value",
    [encoded(b"not-bencoded"), "data:text/html;base64," + encoded(b"d1:ae"), "%%%"],
)
def test_torrent_metainfo_rejections_do_not_log_identifiers_or_payload(value):
    evidence, logger, _ = decoder()
    assert evidence.decode_torrent_file(value, "sensitive-torrent") is None
    logged = repr(logger.warning.call_args)
    assert "sensitive-torrent" not in logged
    assert value not in logged


@pytest.mark.parametrize(
    ("value", "kind", "reason"),
    [
        ("%%%not-base64%%%", "screen", "base64"),
        (encoded(b"not a png"), "screen", "PNG magic"),
        ("data:text/html;base64," + encoded(PNG), "screen", "MIME"),
        (encoded(b"plain text"), "source", "recognizable HTML"),
        (encoded(b"<html>\xff</html>"), "source", "UTF-8"),
        (
            "data:text/html;charset=utf-8;base64," + encoded(HTML),
            "source",
            "parameters",
        ),
    ],
)
def test_invalid_or_spoofed_capture_is_rejected_without_payload_logging(
    value, kind, reason
):
    evidence, logger, _ = decoder()

    assert evidence.decode(value, kind, "claim", "sensitive-victim") is None

    log_text = repr(logger.warning.call_args)
    assert reason in log_text
    assert value not in log_text
    assert "sensitive-victim" not in log_text


def test_per_item_and_run_budgets_are_independent_and_fail_closed():
    too_small, logger, _ = decoder(max_item=len(PNG) - 1)
    assert too_small.decode(encoded(PNG), "screen", "claim", "one") is None
    assert "per-item limit" in repr(logger.warning.call_args)

    evidence, logger, budget = decoder(max_count=1, max_bytes=len(PNG) + len(HTML))
    assert evidence.decode(encoded(PNG), "screen", "claim", "one") is not None
    assert evidence.decode(encoded(HTML), "source", "claim", "two") is None
    assert budget.count == 1
    assert "count budget" in repr(logger.warning.call_args)

    evidence, logger, budget = decoder(max_count=2, max_bytes=len(PNG))
    assert evidence.decode(encoded(PNG), "screen", "claim", "one") is not None
    assert evidence.decode(encoded(HTML), "source", "claim", "two") is None
    assert budget.bytes == len(PNG)
    assert "byte budget" in repr(logger.warning.call_args)


def test_duplicate_content_is_charged_for_each_owner_occurrence():
    evidence, _, budget = decoder(max_count=2, max_bytes=2 * len(PNG))
    first = evidence.decode(encoded(PNG), "screen", "claim", "one")
    second = evidence.decode(encoded(PNG), "screen", "location", "two")

    assert first == second
    assert budget.count == 2
    assert budget.bytes == 2 * len(PNG)


def test_serialized_budget_charges_exact_report_representation_factors():
    screen_size = 4 * ((len(PNG) + 2) // 3)
    html_size = 4 * ((len(HTML) + 2) // 3)
    evidence, _, budget = decoder(
        max_bytes=len(PNG) + len(HTML),
        max_serialized=(3 * screen_size) + (2 * html_size),
    )

    assert evidence.decode(encoded(PNG), "screen", "claim", "one", representations=3)
    assert evidence.decode(encoded(HTML), "source", "claim", "one", representations=2)
    assert budget.serialized_bytes == (3 * screen_size) + (2 * html_size)

    rejected, _, rejected_budget = decoder(
        max_bytes=len(PNG), max_serialized=(3 * screen_size) - 1
    )
    assert (
        rejected.decode(encoded(PNG), "screen", "claim", "two", representations=3)
        is None
    )
    assert rejected.last_rejection_retryable is True
    assert rejected_budget.count == 0
    assert rejected_budget.serialized_bytes == 0


def test_retained_claim_graph_base64_matches_reserved_serialized_bytes():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    post = claim(screen=encoded(PNG), source=encoded(HTML))
    graph = connector._create_claim_graph(
        group, post, datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    )

    actual = 0
    for item in graph:
        if item.type == "artifact":
            actual += len(item.payload_bin)
        if item.type == "report":
            actual += sum(len(file["data"]) for file in item.x_opencti_files)
    assert actual == connector.evidence.budget.serialized_bytes


def test_duplicate_artifact_preserves_relationships_to_every_claim():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    observed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    first = connector._create_claim_graph(
        group, claim(screen=encoded(PNG), source=None, title="First Corp"), observed
    )
    second = connector._create_claim_graph(
        group, claim(screen=encoded(PNG), source=None, title="Second Corp"), observed
    )
    graph = connector._deduplicate([*first, *second])
    artifacts = [obj for obj in graph if obj.type == "artifact"]
    incidents = {obj.id for obj in graph if obj.type == "incident"}
    reports = [obj for obj in graph if obj.type == "report"]

    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert all(artifact.id in report.object_refs for report in reports)
    assert incidents <= {
        obj.target_ref
        for obj in graph
        if obj.type == "relationship" and obj.source_ref == artifact.id
    }


def claim(screen=encoded(PNG), source=encoded(HTML), title="Example Corp"):
    return {
        "id": f"post-{title}",
        "group_name": "akira",
        "post_title": title,
        "discovered": "2026-01-02T03:04:05Z",
        "link": "http://claim.example/victim",
        "screen": screen,
        "source": source,
    }


def test_post_evidence_is_marked_provenanced_and_scoped_to_its_claim_report():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    post = claim()

    graph = connector._create_claim_graph(
        group, post, datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    )
    artifacts = [obj for obj in graph if obj.type == "artifact"]
    report = next(obj for obj in graph if obj.type == "report")
    incident = next(obj for obj in graph if obj.type == "incident")
    url = next(obj for obj in graph if obj.type == "url")

    assert len(artifacts) == 2
    assert {item.mime_type for item in artifacts} == {"image/png", "text/html"}
    assert {item.hashes["SHA-256"] for item in artifacts} == {
        hashlib.sha256(PNG).hexdigest(),
        hashlib.sha256(HTML).hexdigest(),
    }
    payloads = {"screen": PNG, "source": HTML}
    assert all(
        base64.b64decode(item.payload_bin, validate=True)
        == payloads[item.x_ransomlook_evidence_kind]
        for item in artifacts
    )
    assert all(item.id in report.object_refs for item in artifacts)
    assert report.created_by_ref == connector.converter.author.id
    assert all(
        connector.converter.marking.id in item.object_marking_refs for item in artifacts
    )
    assert all(
        item.x_opencti_created_by_ref == connector.converter.author.id
        for item in artifacts
    )
    files = list(report.x_opencti_files)
    assert len(files) == 3
    assert {item["mime_type"] for item in files} == {"image/png", "text/html"}
    assert all(item["no_trigger_import"] is True for item in files)
    assert [item["mime_type"] for item in files] == [
        "image/png",
        "image/png",
        "text/html",
    ]
    assert [item["embedded"] for item in files] == [False, True, False]
    assert [item["name"] for item in files] == [
        "ransomnote.png",
        f"ransomlook-screen-{hashlib.sha256(PNG).hexdigest()[:16]}-inline.png",
        f"ransomlook-source-{hashlib.sha256(HTML).hexdigest()[:16]}.html",
    ]
    assert all(
        item["object_marking_refs"] == [connector.converter.marking.id]
        for item in files
    )
    assert {base64.b64decode(item["data"], validate=True) for item in files} == {
        PNG,
        HTML,
    }
    assert "x_opencti_content" not in report
    for artifact in artifacts:
        related_targets = {
            obj.target_ref
            for obj in graph
            if obj.type == "relationship" and obj.source_ref == artifact.id
        }
        assert {incident.id, url.id} <= related_targets

    parsed = stix2.parse(
        OpenCTIConnectorHelper.stix2_create_bundle(
            [*graph, group, connector.converter.author, connector.converter.marking]
        ),
        allow_custom=True,
        version="2.1",
    )
    assert len([obj for obj in parsed.objects if obj.type == "artifact"]) == 2
    parsed_report = next(obj for obj in parsed.objects if obj.type == "report")
    assert parsed_report.created_by_ref == connector.converter.author.id
    assert len(parsed_report.x_opencti_files) == 3
    assert [item["embedded"] for item in parsed_report.x_opencti_files] == [
        False,
        True,
        False,
    ]
    assert "x_opencti_content" not in parsed_report


def test_report_evidence_files_without_main_content_are_deterministic():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    post = claim()
    observed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    first_graph = connector._create_claim_graph(group, post, observed)
    second_graph = connector._create_claim_graph(group, dict(post), observed)
    first = next(obj for obj in first_graph if obj.type == "report")
    second = next(obj for obj in second_graph if obj.type == "report")

    assert first.serialize() == second.serialize()
    assert "x_opencti_content" not in first
    assert "x_opencti_content" not in second
    assert list(first.x_opencti_files) == list(second.x_opencti_files)
    assert first.modified == observed


@pytest.mark.parametrize(
    "published",
    [
        datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        datetime(2026, 7, 12, 5, tzinfo=timezone.utc),
    ],
)
def test_report_modified_tracks_published_time_without_schema_offsets(published):
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    post = claim(title="Observed Corp")
    post["discovered"] = published.isoformat()

    graph = connector._create_claim_graph(group, post, published)
    report = next(obj for obj in graph if obj.type == "report")
    assert report.modified == published


def test_deadlock_shaped_large_screen_is_a_viewable_report_file_and_artifact():
    """Regress the capture size/shape of the live deadlock/KeNHA record safely."""
    connector = make_connector()
    group = connector.converter.create_group("deadlock", {})
    screenshot = EvidenceDecoder.PNG_MAGIC + bytes(2_700_000)
    post = {
        **claim(screen=encoded(screenshot), source=None, title="KeNHA"),
        "id": "sanitized-deadlock-kenha",
        "group_name": "deadlock",
    }

    graph = connector._create_claim_graph(
        group, post, datetime(2026, 7, 11, tzinfo=timezone.utc)
    )
    report = next(obj for obj in graph if obj.type == "report")
    artifact = next(obj for obj in graph if obj.type == "artifact")
    attachments = list(report.x_opencti_files)
    downloadable = next(item for item in attachments if not item["embedded"])
    embedded = next(item for item in attachments if item["embedded"])

    assert len(post["screen"]) >= 3_600_000
    assert downloadable["name"] == "ransomnote.png"
    assert embedded["name"] == (
        f"ransomlook-screen-{hashlib.sha256(screenshot).hexdigest()[:16]}-inline.png"
    )
    assert all(item["mime_type"] == "image/png" for item in attachments)
    assert all(item["no_trigger_import"] is True for item in attachments)
    assert downloadable["embedded"] is False
    assert embedded["embedded"] is True
    assert all(
        base64.b64decode(item["data"], validate=True) == screenshot
        for item in attachments
    )
    assert base64.b64decode(artifact.payload_bin, validate=True) == screenshot
    assert artifact.hashes["SHA-256"] == hashlib.sha256(screenshot).hexdigest()
    assert "x_opencti_content" not in report


def test_rejected_post_evidence_does_not_block_core_claim_graph():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})

    graph = connector._create_claim_graph(
        group,
        claim(screen="malformed", source=encoded(b"not html")),
        datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )

    assert not any(obj.type == "artifact" for obj in graph)
    assert {"identity", "incident", "report", "url", "domain-name"} <= {
        obj.type for obj in graph
    }
    assert connector.helper.connector_logger.warning.call_count == 2
    report = next(obj for obj in graph if obj.type == "report")
    assert "x_opencti_files" not in report
    assert "x_opencti_content" not in report


def test_per_claim_count_limit_rejects_excess_evidence():
    connector = make_connector(max_artifacts_per_claim=1)
    group = connector.converter.create_group("akira", {})

    graph = connector._create_claim_graph(
        group,
        claim(),
        datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )

    assert len([obj for obj in graph if obj.type == "artifact"]) == 1
    assert "per-owner artifact count" in repr(
        connector.helper.connector_logger.warning.call_args
    )
    report = next(obj for obj in graph if obj.type == "report")
    assert len(report.x_opencti_files) == 2
    assert [item["embedded"] for item in report.x_opencti_files] == [False, True]


def test_unavailable_post_captures_create_no_report_attachment():
    connector = make_connector()
    group = connector.converter.create_group("deadlock", {})

    graph = connector._create_claim_graph(
        group,
        claim(screen=None, source=None, title="KeNHA"),
        datetime(2026, 7, 11, tzinfo=timezone.utc),
    )

    report = next(obj for obj in graph if obj.type == "report")
    assert "x_opencti_files" not in report
    assert "x_opencti_content" not in report
    assert not any(obj.type == "artifact" for obj in graph)


def test_source_only_claim_is_downloadable_but_never_embedded_or_rendered():
    connector = make_connector()
    group = connector.converter.create_group("deadlock", {})

    graph = connector._create_claim_graph(
        group,
        claim(screen=None, source=encoded(HTML), title="Source Only"),
        datetime(2026, 7, 11, tzinfo=timezone.utc),
    )

    report = next(obj for obj in graph if obj.type == "report")
    assert "x_opencti_content" not in report
    assert len(report.x_opencti_files) == 1
    attachment = report.x_opencti_files[0]
    assert attachment["mime_type"] == "text/html"
    assert attachment["embedded"] is False
    assert base64.b64decode(attachment["data"], validate=True) == HTML


def test_location_evidence_stays_with_infrastructure_and_out_of_claim_report():
    connector = make_connector(
        import_location_evidence=True, import_sensitive_infrastructure=True
    )
    group = connector.converter.create_group("akira", {})
    location = {
        "slug": "http://profile.example/",
        "private": True,
        "lastscrape": "2026-01-01T00:00:00Z",
        "screen": encoded(PNG),
        "source": encoded(HTML),
    }
    profile = connector._create_group_infrastructure(
        {"locations": [location]}, group.id, "akira"
    )
    infrastructure = next(obj for obj in profile if obj.type == "infrastructure")
    artifacts = [obj for obj in profile if obj.type == "artifact"]
    claim_graph = connector._create_claim_graph(
        group,
        claim(screen=None, source=None, title="Unrelated Victim"),
        datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    report = next(obj for obj in claim_graph if obj.type == "report")

    assert len(artifacts) == 2
    assert all(item.id not in report.object_refs for item in artifacts)
    for artifact in artifacts:
        relations = [
            obj
            for obj in profile
            if obj.type == "relationship"
            and obj.source_ref == artifact.id
            and obj.target_ref == infrastructure.id
        ]
        assert len(relations) == 1
        assert relations[0].x_ransomlook_evidence_scope == "location"
        assert any(
            obj.type == "relationship"
            and obj.source_ref == artifact.id
            and obj.target_ref == infrastructure.id
            for obj in profile
        )


def test_embedded_html_resources_are_never_fetched(monkeypatch):
    import urllib.request

    fetch = MagicMock(side_effect=AssertionError("network fetch attempted"))
    monkeypatch.setattr(urllib.request, "urlopen", fetch)
    evidence, _, _ = decoder()

    result = evidence.decode(encoded(HTML), "source", "claim", "one")

    assert result is not None
    fetch.assert_not_called()
