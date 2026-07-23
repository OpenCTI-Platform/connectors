from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from models.report import Incident, Note, Report

# --- Report ------------------------------------------------------------------


class TestReport:
    def test_minimal(self):
        r = Report(
            name="threat report",
            c_type="threat_report",
            published_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            related_objects_ids=["indicator--11111111-1111-4111-8111-111111111111"],
        )
        r.generate_stix_objects()
        sdo = r.stix_main_object
        assert sdo.type == "report"
        assert sdo.name == "threat report"
        # Report-type lookup maps "threat_report" → "Threat-Report".
        assert sdo.report_types == ["Threat-Report"]

    def test_default_published_time(self):
        # When ``published_time`` is None, the wrapper uses datetime.now(UTC).
        r = Report(
            name="x",
            c_type="threat_report",
            published_time=None,
            related_objects_ids=["indicator--11111111-1111-4111-8111-111111111111"],
        )
        # ``published_time`` is filled at __init__ — not None.
        assert r.published_time is not None
        assert r.published_time.tzinfo is not None

    def test_with_object_refs(self):
        r = Report(
            name="x",
            c_type="threat_report",
            published_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            related_objects_ids=[
                "indicator--11111111-1111-4111-8111-111111111111",
                "malware--22222222-2222-4222-8222-222222222222",
            ],
        )
        r.generate_stix_objects()
        assert len(r.stix_main_object.object_refs) == 2

    def test_labels_note_emits_when_content_set(self):
        r = Report(
            name="x",
            c_type="threat_report",
            published_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            related_objects_ids=["indicator--11111111-1111-4111-8111-111111111111"],
        )
        # ``_labels_note_content`` is set by the adapter when
        # ``STORE_REPORT_LABELS_IN_NOTE=true`` is configured.
        r._labels_note_content = ["collection:Test", "tag1", "tag2"]
        r.generate_stix_objects()
        # The note SDO is stored on the wrapper and picked up by the
        # ``BaseEntity.generate_stix_objects`` aggregation.
        assert getattr(r, "_labels_note_sdo", None) is not None
        # And ends up in the final ``stix_objects`` list.
        assert any(o.type == "note" for o in r.stix_objects)

    def test_labels_note_empty_list_skipped(self):
        r = Report(
            name="x",
            c_type="threat_report",
            published_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            related_objects_ids=["indicator--11111111-1111-4111-8111-111111111111"],
        )
        r._labels_note_content = []
        r.generate_stix_objects()
        assert getattr(r, "_labels_note_sdo", None) is None

    def test_labels_note_filters_blank_strings(self):
        r = Report(
            name="x",
            c_type="threat_report",
            published_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            related_objects_ids=["indicator--11111111-1111-4111-8111-111111111111"],
        )
        r._labels_note_content = ["  ", "", "  "]
        r.generate_stix_objects()
        # All-blank → no note attached.
        assert getattr(r, "_labels_note_sdo", None) is None

    def test_labels_note_markdown_includes_labels(self):
        out = Report._labels_note_markdown(["t1", "t2"])
        assert "## Report labels" in out
        assert "`t1`" in out
        assert "`t2`" in out


# --- Incident ---------------------------------------------------------------


class TestIncident:
    def test_requires_timestamp(self):
        inc = Incident(name="x", c_type="incident")
        with pytest.raises(ValueError, match="timestamp"):
            inc.generate_stix_objects()

    def test_first_seen_only(self):
        ts = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        inc = Incident(name="ddos-1", c_type="incident", first_seen=ts)
        inc.generate_stix_objects()
        sdo = inc.stix_main_object
        assert sdo.type == "incident"
        assert sdo.name == "ddos-1"
        # ``created`` falls back to first_seen.
        assert sdo.created == ts

    def test_last_seen_used_when_no_first(self):
        ts = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        inc = Incident(name="x", c_type="incident", last_seen=ts)
        inc.generate_stix_objects()
        assert inc.stix_main_object.created == ts

    def test_naive_datetime_stamped_utc(self):
        naive = datetime(2024, 6, 1, 12, 0, 0)  # no tzinfo
        inc = Incident(name="x", c_type="incident", first_seen=naive)
        inc.generate_stix_objects()
        # Must end up tz-aware.
        assert inc.stix_main_object.created.tzinfo is not None

    def test_full_custom_properties(self):
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        inc = Incident(
            name="leak-1",
            c_type="incident",
            first_seen=ts,
            last_seen=ts,
            severity="critical",
            incident_type="data-leak",
            objective="credential-theft",
            reliability="B",
            credibility="2",
            admiralty_code="A2",
        )
        inc.generate_stix_objects()
        sdo = inc.stix_main_object
        assert sdo["severity"] == "critical"
        assert sdo["incident_type"] == "data-leak"
        assert sdo["objective"] == "credential-theft"
        assert sdo["x_opencti_reliability"] == "B"
        assert sdo["x_opencti_credibility"] == "2"
        assert sdo["x_opencti_admiralty_code"] == "A2"

    def test_none_values_filtered_from_custom_props(self):
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        inc = Incident(name="x", c_type="incident", first_seen=ts)
        inc.generate_stix_objects()
        # ``severity`` not set → not present in serialised properties.
        assert "severity" not in inc.stix_main_object

    def test_iso_format_isostring_passthrough(self):
        # Non-datetime first_seen (already a string) passes through as-is.
        inc = Incident(
            name="x",
            c_type="incident",
            first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_seen="2024-02-01T00:00:00Z",
        )
        inc.generate_stix_objects()
        assert inc.stix_main_object["last_seen"] == "2024-02-01T00:00:00Z"


# --- Note --------------------------------------------------------------------


class TestNote:
    # stix2.Note requires non-empty ``object_refs`` — every Note test
    # must pass at least one stub ref.
    _STUB_REF = "incident--11111111-1111-4111-8111-111111111111"

    def test_minimal(self):
        n = Note(
            name="my-note",
            c_type="note",
            content="body",
            object_refs=[self._STUB_REF],
        )
        n.generate_stix_objects()
        sdo = n.stix_main_object
        assert sdo.type == "note"
        assert sdo.content == "body"

    def test_object_refs_propagate(self):
        n = Note(
            name="my-note",
            c_type="note",
            content="body",
            object_refs=["incident--11111111-1111-4111-8111-111111111111"],
        )
        n.generate_stix_objects()
        assert len(n.stix_main_object.object_refs) == 1

    def test_long_content_truncated(self):
        n = Note(
            name="x",
            c_type="note",
            content="X" * 100_000,
            object_refs=[self._STUB_REF],
        )
        n.generate_stix_objects()
        # NOTE_MAX_CONTENT = 50_000 chars.
        assert len(n.stix_main_object.content) == 50_000

    def test_none_content_becomes_empty_string(self):
        n = Note(
            name="x",
            c_type="note",
            content=None,
            object_refs=[self._STUB_REF],
        )
        n.generate_stix_objects()
        assert n.stix_main_object.content == ""

    def test_stable_id_independent_of_content(self):
        # Same name + same first object_ref → same ID, regardless of body.
        n1 = Note(
            name="t",
            c_type="note",
            content="v1",
            object_refs=["incident--11111111-1111-4111-8111-111111111111"],
        )
        n2 = Note(
            name="t",
            c_type="note",
            content="v2-different",
            object_refs=["incident--11111111-1111-4111-8111-111111111111"],
        )
        n1.generate_stix_objects()
        n2.generate_stix_objects()
        # Stable ID anchored to (name, first_object_ref), not content.
        assert n1.stix_main_object.id == n2.stix_main_object.id

    def test_deterministic_id_uses_name_and_first_ref(self):
        # The Note id is anchored to (name, first object_ref). stix2 requires
        # a non-empty object_refs, so we pass a stub ref and confirm the id
        # is a well-formed, deterministic ``note--`` UUID5.
        n = Note(
            name="t",
            c_type="note",
            content="x",
            object_refs=[self._STUB_REF],
        )
        n.generate_stix_objects()
        assert n.stix_main_object.id.startswith("note--")

    def test_created_modified_propagation(self):
        c = datetime(2024, 1, 1, tzinfo=timezone.utc)
        m = datetime(2024, 2, 1, tzinfo=timezone.utc)
        n = Note(
            name="x",
            c_type="note",
            content="b",
            object_refs=[self._STUB_REF],
            created=c,
            modified=m,
        )
        n.generate_stix_objects()
        assert n.stix_main_object.created == c
        assert n.stix_main_object.modified == m

    def test_modified_defaults_to_created(self):
        c = datetime(2024, 1, 1, tzinfo=timezone.utc)
        n = Note(
            name="x",
            c_type="note",
            content="b",
            object_refs=[self._STUB_REF],
            created=c,
        )
        n.generate_stix_objects()
        # When modified is omitted, it mirrors created.
        assert n.stix_main_object.modified == c

    def test_labels_in_custom_properties(self):
        n = Note(
            name="x",
            c_type="note",
            content="b",
            object_refs=[self._STUB_REF],
            labels=["collection:Test"],
        )
        n.generate_stix_objects()
        assert n.stix_main_object["x_opencti_labels"] == ["collection:Test"]


class TestReportLabelsNoteSkipOnException:
    def test_labels_note_skipped_when_stix_note_raises(self):
        # When ``stix2.Note`` construction inside ``_create_labels_note``
        # raises TypeError/ValueError, the wrapper swallows the error and
        # the Report still emits successfully (no labels-Note attached).
        r = Report(
            name="x",
            c_type="threat_report",
            published_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            related_objects_ids=["indicator--11111111-1111-4111-8111-111111111111"],
        )
        r._labels_note_content = ["valid-label"]
        with patch("models.report.stix2.Note", side_effect=TypeError("bad")):
            r.generate_stix_objects()
        assert r.stix_main_object is not None
        assert getattr(r, "_labels_note_sdo", None) is None
