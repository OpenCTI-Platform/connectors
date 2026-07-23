import logging
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

import pycti
import stix2
from connector.settings import NOTE_MAX_CONTENT
from models._common import _BaseSDO
from support.note_markdown import MarkdownNote


class Report(_BaseSDO):
    def __init__(
        self,
        name,
        c_type,
        published_time,
        related_objects_ids,
        tlp_color="white",
        labels=None,
        risk_score=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)
        self.published_time = published_time or datetime.now(timezone.utc)
        self.related_objects_ids = related_objects_ids or []

    @staticmethod
    def _labels_note_markdown(labels: Sequence[str]) -> str:
        nb = MarkdownNote()
        nb.h2("Report labels")
        nb.paragraph(
            "Labels from the upstream feed, stored on this Note for search and pivoting "
            "(the Report object may omit duplicate labels when configured)."
        )
        nb.h3("Values")
        for lbl in labels:
            s = str(lbl).strip()
            if s:
                nb.bullet(f"`{s}`")
        return nb.build()

    def _create_labels_note(
        self,
        labels_list: list[str] | None,
        report_id: str,
    ) -> stix2.Note | None:
        if not isinstance(labels_list, list) or len(labels_list) == 0:
            return None
        labels_norm = [str(x).strip() for x in labels_list if str(x).strip()]
        if not labels_norm:
            return None
        log = logging.getLogger(__name__)
        try:
            note_content = self._labels_note_markdown(labels_norm)
            # Stable ID: "OpenCTI report labels" + report_id — independent of content.
            anchor = datetime(2020, 1, 1, tzinfo=timezone.utc)
            note_id = pycti.Note.generate_id(anchor, f"report-labels:{report_id}")
            return stix2.Note(
                id=note_id,
                content=note_content[:NOTE_MAX_CONTENT],
                object_refs=[report_id],
                created_by_ref=self.author.id,
                object_marking_refs=self.get_markings(),
                allow_custom=True,
            )
        except (TypeError, ValueError) as e:
            log.warning("Report labels Note skipped (Report was still created): %s", e)
            return None

    def _generate_sdo(self) -> Any:
        object_refs = list(self.related_objects_ids)

        self.stix_main_object = stix2.Report(
            id=pycti.Report.generate_id(self.name, self.published_time),
            name=self.name,
            description=self.description,
            published=self.published_time,
            report_types=[self._generate_stix_report_type(self.c_type)],
            object_refs=object_refs,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            external_references=(
                self.external_references if self.external_references else None
            ),
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                **self._labels_kv(),
            },
        )

        labels_note_content = getattr(self, "_labels_note_content", None)
        note_sdo = self._create_labels_note(
            labels_note_content, self.stix_main_object.id
        )
        if note_sdo is not None:
            self._labels_note_sdo = note_sdo
        return self.stix_main_object


class Incident(_BaseSDO):
    def __init__(
        self,
        name,
        c_type,
        tlp_color="white",
        labels=None,
        risk_score=None,
        severity=None,
        incident_type=None,
        objective=None,
        reliability=None,
        credibility=None,
        admiralty_code=None,
        first_seen=None,
        last_seen=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)
        self.severity = severity
        self.incident_type = incident_type
        self.objective = objective
        self.reliability = reliability
        self.credibility = credibility
        self.admiralty_code = admiralty_code
        self.first_seen = first_seen
        self.last_seen = last_seen

    def _generate_sdo(self) -> Any:
        created = self.first_seen or self.last_seen
        if not created:
            raise ValueError("Incident requires created/first_seen/last_seen timestamp")
        if getattr(created, "tzinfo", None) is None:
            created = created.replace(tzinfo=timezone.utc)

        def _str_or_none(v: Any) -> str | None:
            return str(v) if v is not None else None

        def _iso_or_none(v: Any) -> str | None:
            if v is None:
                return None
            if isinstance(v, datetime):
                if v.tzinfo is None:
                    v = v.replace(tzinfo=timezone.utc)
                return v.isoformat().replace("+00:00", "Z")
            return str(v)

        first_seen_iso = _iso_or_none(self.first_seen)
        last_seen_iso = _iso_or_none(self.last_seen)
        custom_props = {
            "x_opencti_score": (
                self.risk_score if self.risk_score is not None else None
            ),
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
            "severity": self.severity,
            "first_seen": first_seen_iso,
            "last_seen": last_seen_iso,
            "x_opencti_first_seen": first_seen_iso,
            "x_opencti_last_seen": last_seen_iso,
            "incident_type": self.incident_type,
            "objective": self.objective,
            "x_opencti_reliability": _str_or_none(self.reliability),
            "x_opencti_credibility": _str_or_none(self.credibility),
            "x_opencti_admiralty_code": _str_or_none(self.admiralty_code),
        }
        custom_props = {k: v for k, v in custom_props.items() if v is not None}
        self.stix_main_object = stix2.Incident(
            id=pycti.Incident.generate_id(self.name, created),
            name=self.name,
            description=self.description,
            created=created,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            custom_properties=custom_props,
        )
        return self.stix_main_object


class Note(_BaseSDO):
    def __init__(
        self,
        name,
        c_type,
        tlp_color="white",
        labels=None,
        risk_score=None,
        content=None,
        object_refs=None,
        created=None,
        modified=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)
        self.content = content
        self.object_refs = object_refs or []
        self.created = created
        self.modified = modified

    def _generate_sdo(self) -> Any:
        # Stable ID: anchor + (name + first object-ref).
        # Former strategy pycti.Note.generate_id(name, content) was content-
        # derived — any body change produced a new ID → duplicate Notes in OpenCTI.
        _anchor = datetime(2020, 1, 1, tzinfo=timezone.utc)
        _first_ref = self.object_refs[0] if self.object_refs else "unknown"
        extra_kwargs: dict[str, Any] = {}
        if self.created is not None:
            extra_kwargs["created"] = self.created
        if self.modified is not None:
            extra_kwargs["modified"] = self.modified
        elif self.created is not None:
            extra_kwargs["modified"] = self.created
        custom = {
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
        }
        # ``id=`` must stay an explicit keyword argument here so the
        # ``linter_stix_id_generator`` pylint plugin can prove every
        # ``stix2.Note`` call goes through ``pycti.Note.generate_id`` —
        # hiding it inside ``**kwargs`` trips the linter at this call site.
        self.stix_main_object = stix2.Note(
            id=pycti.Note.generate_id(_anchor, f"{self.name}:{_first_ref}"),
            content=(self.content or "")[:NOTE_MAX_CONTENT],
            object_refs=self.object_refs,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            custom_properties=custom,
            **extra_kwargs,
        )
        return self.stix_main_object
