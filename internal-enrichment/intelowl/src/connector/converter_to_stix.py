"""Turn an IntelOwl job into STIX objects for OpenCTI."""

from typing import Any

from connectors_sdk.models import (
    ExternalReference,
    Malware,
    Note,
    OrganizationAuthor,
    Reference,
    Relationship,
    TLPMarking,
)
from pycti import STIX_EXT_OCTI_SCO, OpenCTIStix2

# OpenCTI TLP marking -> TLP level understood by the SDK's TLPMarking
_TLP_LEVELS = {
    "TLP:CLEAR": "clear",
    "TLP:WHITE": "white",
    "TLP:GREEN": "green",
    "TLP:AMBER": "amber",
    "TLP:AMBER+STRICT": "amber+strict",
    "TLP:RED": "red",
}

# How restrictive each OpenCTI TLP marking is, to pick the strictest of several
TLP_RANK = {
    "TLP:CLEAR": 0,
    "TLP:WHITE": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}

# OpenCTI TLP marking -> TLP sent to IntelOwl (CLEAR, GREEN, AMBER or RED). IntelOwl uses it
# to decide which analyzers may send the observable to third parties. IntelOwl has no
# AMBER+STRICT, so it is sent as RED rather than relaxed to AMBER.
_INTELOWL_TLP = {
    "TLP:CLEAR": "CLEAR",
    "TLP:WHITE": "CLEAR",
    "TLP:GREEN": "GREEN",
    "TLP:AMBER": "AMBER",
    "TLP:AMBER+STRICT": "RED",
    "TLP:RED": "RED",
}

# STIX observable type -> IntelOwl observable classification
_CLASSIFICATIONS = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "hostname": "domain",
    "url": "url",
    "file": "hash",
}


def intelowl_tlp(opencti_tlp: str | None) -> str:
    """IntelOwl TLP for an OpenCTI TLP marking. Unmarked observables are sent as CLEAR."""
    return _INTELOWL_TLP.get((opencti_tlp or "").upper(), "CLEAR")


def observable_to_intelowl(stix_entity: dict[str, Any]) -> tuple[str, str] | None:
    """Return the (classification, value) IntelOwl should analyze, or None if unsupported.

    Files are analyzed by hash, preferring SHA-256, then SHA-1, then MD5.
    """
    classification = _CLASSIFICATIONS.get(stix_entity.get("type", ""))
    if classification is None:
        return None
    if classification == "hash":
        hashes = stix_entity.get("hashes") or {}
        for algorithm in ("SHA-256", "SHA-1", "MD5"):
            if hashes.get(algorithm):
                return classification, hashes[algorithm].lower()
        return None
    value = stix_entity.get("value")
    return (classification, value) if value else None


def _data_model(report: dict[str, Any]) -> dict[str, Any]:
    data_model = report.get("data_model")
    return data_model if isinstance(data_model, dict) else {}


def verdict_score(data_model: dict[str, Any]) -> int | None:
    """OpenCTI score for IntelOwl's aggregated verdict, or None when there is no verdict.

    IntelOwl rates its confidence in a verdict with a reliability from 0 to 10.
    """
    evaluation = (data_model.get("evaluation") or "").lower()
    if evaluation == "malicious":
        reliability = data_model.get("reliability")
        reliability = reliability if isinstance(reliability, int) else 5
        return max(0, min(10, reliability)) * 10
    if evaluation == "trusted":
        return 0
    return None


class ConverterToStix:
    """Build the STIX objects and observable updates for one IntelOwl job."""

    def __init__(self, tlp_level: str = "clear") -> None:
        self.author = OrganizationAuthor(name="IntelOwl")
        self.marking = TLPMarking(level=tlp_level)

    @classmethod
    def for_entity_tlp(cls, opencti_tlp: str | None) -> "ConverterToStix":
        """Converter whose created objects carry the same TLP as the enriched entity."""
        return cls(tlp_level=_TLP_LEVELS.get((opencti_tlp or "").upper(), "clear"))

    def _note_content(
        self, value: str, playbook: str, job: dict[str, Any], data_model: dict[str, Any]
    ) -> str:
        # The content (and so the note ID) only depends on the results, not on the job ID
        # or time, so re-running an unchanged analysis updates the same note.
        lines = [f"## IntelOwl analysis of `{value}`", ""]
        evaluation = data_model.get("evaluation")
        lines.append(f"- **Verdict:** {evaluation or 'no verdict'}")
        if evaluation:
            lines.append(
                f"- **Reliability:** {data_model.get('reliability', 'n/a')}/10"
            )
        if data_model.get("malware_family"):
            lines.append(f"- **Malware family:** {data_model['malware_family']}")
        if data_model.get("tags"):
            lines.append(f"- **Tags:** {', '.join(sorted(data_model['tags']))}")
        if data_model.get("kill_chain_phase"):
            lines.append(f"- **Kill chain phase:** {data_model['kill_chain_phase']}")
        lines.append(f"- **Playbook:** {playbook}")
        lines.append(f"- **Job status:** {job.get('status')}")

        reports = sorted(
            job.get("analyzer_reports") or [], key=lambda r: r.get("name", "")
        )
        if reports:
            lines += ["", "| Analyzer | Status | Evaluation |", "| --- | --- | --- |"]
            for report in reports:
                evaluation = _data_model(report).get("evaluation") or ""
                lines.append(
                    f"| {report.get('name', '')} | {report.get('status', '')} | {evaluation} |"
                )
        return "\n".join(lines)

    def convert(
        self,
        stix_entity: dict[str, Any],
        value: str,
        playbook: str,
        job: dict[str, Any],
        job_url: str,
        update_score: bool = True,
        create_labels: bool = True,
    ) -> list[Any]:
        """Return new STIX objects for `job`, updating `stix_entity` (score, labels) in place."""
        data_model = (
            job.get("data_model") if isinstance(job.get("data_model"), dict) else {}
        )
        markings = [self.marking]
        objects: list[Any] = [
            self.author.to_stix2_object(),
            self.marking.to_stix2_object(),
        ]

        observable_ref = Reference(id=stix_entity["id"])
        note = Note(
            abstract=f"IntelOwl analysis of {value}",
            content=self._note_content(value, playbook, job, data_model),
            objects=[observable_ref],
            author=self.author,
            markings=markings,
            external_references=[
                ExternalReference(
                    source_name="IntelOwl",
                    url=job_url,
                    description=f"IntelOwl job {job.get('id')} ({playbook})",
                )
            ],
        )
        objects.append(note.to_stix2_object())

        malware_family = data_model.get("malware_family")
        if malware_family:
            malware = Malware(
                name=malware_family,
                is_family=True,
                author=self.author,
                markings=markings,
            )
            objects.append(malware.to_stix2_object())
            objects.append(
                Relationship(
                    type="related-to",
                    source=observable_ref,
                    target=malware,
                    author=self.author,
                    markings=markings,
                    description=f"IntelOwl attributes {value} to {malware_family}.",
                ).to_stix2_object()
            )

        if update_score:
            score = verdict_score(data_model)
            if score is not None:
                OpenCTIStix2.put_attribute_in_extension(
                    stix_entity, STIX_EXT_OCTI_SCO, "score", score
                )
        if create_labels:
            labels = sorted(set(data_model.get("tags") or []))
            if malware_family:
                labels.append(malware_family)
            for label in labels:
                OpenCTIStix2.put_attribute_in_extension(
                    stix_entity, STIX_EXT_OCTI_SCO, "labels", label, True
                )
        return objects
