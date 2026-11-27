"""Convert Unmask API results to STIX 2.1 objects.

No network calls happen here. Every object gets a deterministic id (pycti id
generators), so enriching the same file twice updates the same objects instead
of creating duplicates.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

import stix2
from privara_unmask_client import defang, liveness_text, outcome_label
from pycti import Identity, Indicator, Malware, Note, StixCoreRelationship

AUTHOR_NAME = "Privara Unmask"
SOURCE_NAME = "Privara Unmask"
C2_KILL_CHAIN_PHASE = stix2.KillChainPhase(
    kill_chain_name="mitre-attack", phase_name="command-and-control"
)


def format_cents(cents: int | None) -> str:
    """Format US cents as dollars (``2500`` -> ``$25.00``)."""
    return f"${(cents or 0) / 100:.2f}"


def _ts(value: Any) -> datetime:
    """Unix seconds -> aware datetime; now when missing."""
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    return datetime.now(tz=timezone.utc)


def _escape(value: str) -> str:
    """Escape a value for a STIX pattern string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _ip_type(host: str) -> str | None:
    """STIX type of an IP address host (``ipv4-addr`` / ``ipv6-addr``), None for a name."""
    try:
        version = ipaddress.ip_address(host.strip("[]")).version
    except ValueError:
        return None
    return "ipv4-addr" if version == 4 else "ipv6-addr"


C2_KINDS = frozenset({"url", "ip", "domain", "host_port"})


class C2Target:
    """What a C2 entry points to, in STIX terms.

    Built from the API's ``kind`` (``url | ip | domain | host_port``), ``host``
    and ``port`` fields: the value is never parsed. Raises ``ValueError`` for an
    entry this version does not understand (it is then left out of the bundle).
    """

    def __init__(self, entry: dict[str, Any]):
        self.value = (entry.get("value") or "").strip()
        self.kind = (entry.get("kind") or "").lower()
        if self.kind not in C2_KINDS or not self.value:
            raise ValueError(f"unsupported C2 kind {self.kind!r}")
        self.host = (entry.get("host") or "").strip().strip("[]")
        port = entry.get("port")
        self.port = port if isinstance(port, int) and 0 < port < 65536 else None
        if self.kind == "ip":
            self.host = self.host or self.value
        if self.kind == "domain":
            self.host = self.host or self.value
        if self.kind in ("ip", "host_port", "domain") and not self.host:
            raise ValueError(f"C2 entry of kind {self.kind!r} without a host")
        if self.kind == "host_port" and self.port is None:
            raise ValueError("C2 entry of kind 'host_port' without a port")
        if self.kind == "ip":
            ip_type = _ip_type(self.host)
            if ip_type is None:
                raise ValueError(
                    "C2 entry of kind 'ip' whose host is not an IP address"
                )
            self.host_type = ip_type
        else:
            self.host_type = _ip_type(self.host) or "domain-name"

    @property
    def main_observable_type(self) -> str:
        return {
            "url": "Url",
            "ipv4-addr": "IPv4-Addr",
            "ipv6-addr": "IPv6-Addr",
            "domain-name": "Domain-Name",
        }["url" if self.kind == "url" else self.host_type]

    @property
    def pattern(self) -> str:
        if self.kind == "url":
            return f"[url:value = '{_escape(self.value)}']"
        host = _escape(self.host)
        if self.kind == "host_port":
            return (
                f"[network-traffic:dst_ref.type = '{self.host_type}' AND "
                f"network-traffic:dst_ref.value = '{host}' AND "
                f"network-traffic:dst_port = {self.port}]"
            )
        return f"[{self.host_type}:value = '{host}']"

    def observable(self, **kwargs: Any) -> stix2.v21._Observable:
        """The observable the indicator is based on (URL, IP address or domain)."""
        if self.kind == "url":
            return stix2.URL(value=self.value, **kwargs)
        if self.host_type == "ipv4-addr":
            return stix2.IPv4Address(value=self.host, **kwargs)
        if self.host_type == "ipv6-addr":
            return stix2.IPv6Address(value=self.host, **kwargs)
        return stix2.DomainName(value=self.host, **kwargs)


class ConverterToStix:
    """Builds the STIX objects of one Unmask result."""

    def __init__(self, create_observables: bool = True):
        self.create_observables = create_observables
        self.author = stix2.Identity(
            id=Identity.generate_id(AUTHOR_NAME, "organization"),
            name=AUTHOR_NAME,
            identity_class="organization",
            description="Privara Unmask: the Android malware sandbox that recovers the "
            "C2. Pay only for results (https://tajapps.com/unmask/).",
            contact_information="https://tajapps.com",
        )

    # ------------------------------------------------------------ helpers

    def _relationship(
        self,
        relationship_type: str,
        source: str,
        target: str,
        markings: list[str],
        description: str | None = None,
        external_references: list | None = None,
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(relationship_type, source, target),
            relationship_type=relationship_type,
            source_ref=source,
            target_ref=target,
            description=description,
            external_references=external_references,
            created_by_ref=self.author.id,
            object_marking_refs=markings or None,
            allow_custom=True,
        )

    @staticmethod
    def _external_reference(
        job: dict[str, Any],
    ) -> list[stix2.ExternalReference] | None:
        if not job.get("job_id"):
            return None
        return [
            stix2.ExternalReference(
                source_name=SOURCE_NAME,
                external_id=job["job_id"],
                url=job.get("web_url") or None,
                description="Unmask job page on tajapps.com (opens after sign-in).",
            )
        ]

    def note(
        self,
        abstract: str,
        content: str,
        object_refs: list[str],
        markings: list[str],
        created: datetime | None = None,
        external_references: list | None = None,
    ) -> stix2.Note:
        if created is None:
            note_id = Note.generate_id(
                None, "\n".join(sorted(object_refs)) + "\n" + content
            )
            created = datetime.now(tz=timezone.utc)
        else:
            note_id = Note.generate_id(created, content)
        return stix2.Note(
            id=note_id,
            created=created,
            abstract=abstract,
            content=content,
            object_refs=object_refs,
            external_references=external_references,
            created_by_ref=self.author.id,
            object_marking_refs=markings or None,
            allow_custom=True,
        )

    def message_note(
        self, sample_ref: str, markings: list[str], abstract: str, content: str
    ) -> list[Any]:
        """A Note on the sample explaining why there is no result (refused, no balance...)."""
        return [
            self.author,
            self.note(f"Privara Unmask: {abstract}", content, [sample_ref], markings),
        ]

    # ------------------------------------------------------------- result

    def build_result(
        self,
        job: dict[str, Any],
        sample_ref: str,
        markings: list[str],
        reused: bool = False,
    ) -> list[Any]:
        """All the objects of a finished job, linked to the sample observable.

        Only ``job["c2"]`` becomes indicators. ``rejected_candidates`` are counted
        in the Note and never turned into indicators.
        """
        outcome = job.get("outcome")
        finished = _ts(job.get("finished_at"))
        ext_refs = self._external_reference(job)
        objects: list[Any] = [self.author]
        note_refs = [sample_ref]

        malware = None
        family = job.get("family") or {}
        if family.get("name"):
            malware = stix2.Malware(
                id=Malware.generate_id(family["name"]),
                name=family["name"],
                is_family=True,
                created_by_ref=self.author.id,
                object_marking_refs=markings or None,
                allow_custom=True,
            )
            family_confidence = _confidence(family.get("confidence"))
            family_text = "Malware family identified by Privara Unmask" + (
                f" (confidence {family_confidence}%)."
                if family_confidence is not None
                else "."
            )
            objects += [
                malware,
                self._relationship(
                    "related-to",
                    sample_ref,
                    malware.id,
                    markings,
                    description=family_text,
                    external_references=ext_refs,
                ),
            ]
            note_refs.append(malware.id)

        for entry in job.get("c2") or []:
            try:
                target = C2Target(entry)
            except ValueError:
                continue  # unknown kind: listed in the Note, not turned into STIX
            value = target.value
            live = bool(entry.get("live"))
            confidence = _confidence(entry.get("confidence"))
            indicator = stix2.Indicator(
                id=Indicator.generate_id(target.pattern),
                name=value,
                description=(
                    f"Command-and-control endpoint of {job.get('filename') or 'the sample'} "
                    f"(SHA-256 {job.get('sha256') or 'unknown'}), extracted by Privara Unmask "
                    f"from {entry.get('source') or 'the analysis'}"
                    + (
                        f" (confidence {confidence}%). "
                        if confidence is not None
                        else ". "
                    )
                    + f"{'Reachable' if live else 'Not reachable'} during the analysis "
                    f"(liveness check: {liveness_text(entry)})."
                    + _intel_sentence(entry)
                ),
                pattern=target.pattern,
                pattern_type="stix",
                valid_from=finished,
                indicator_types=["malicious-activity"],
                kill_chain_phases=[C2_KILL_CHAIN_PHASE],
                labels=["c2", "c2-live" if live else "c2-dead"],
                external_references=ext_refs,
                custom_properties={
                    "x_opencti_score": 90 if live else 60,
                    "x_opencti_main_observable_type": target.main_observable_type,
                },
                created_by_ref=self.author.id,
                object_marking_refs=markings or None,
                allow_custom=True,
            )
            objects.append(indicator)
            note_refs.append(indicator.id)
            objects.append(
                self._relationship(
                    "related-to",
                    sample_ref,
                    indicator.id,
                    markings,
                    description="C2 endpoint contacted or embedded by this sample.",
                )
            )
            if malware is not None:
                objects.append(
                    self._relationship(
                        "indicates",
                        indicator.id,
                        malware.id,
                        markings,
                    )
                )
            if self.create_observables:
                observable = target.observable(
                    object_marking_refs=markings or None,
                    custom_properties={
                        "x_opencti_score": 90 if live else 60,
                        "x_opencti_created_by_ref": self.author.id,
                        "x_opencti_labels": ["c2"],
                    },
                    allow_custom=True,
                )
                objects += [
                    observable,
                    self._relationship(
                        "based-on", indicator.id, observable.id, markings
                    ),
                ]

        abstract = f"Privara Unmask: {outcome_label(job)}"
        if reused:
            abstract += " (existing result, no new charge)"
        elif outcome in ("live", "dead", "none"):
            abstract += f" (charged {format_cents(job.get('charge_cents'))})"
        objects.append(
            self.note(
                abstract,
                result_markdown(job, reused),
                note_refs,
                markings,
                created=finished,
                external_references=ext_refs,
            )
        )
        return objects


def _intel(entry: dict[str, Any]) -> str:
    """abuse.ch feeds that already know this C2 (information only, never billing)."""
    intel = entry.get("intel")
    if not isinstance(intel, dict) or not intel.get("known"):
        return ""
    feeds = ", ".join(str(f) for f in intel.get("feeds") or []) or "abuse.ch"
    malware = str(intel.get("malware") or "").strip()
    return feeds + (f" ({malware})" if malware else "")


def _intel_sentence(entry: dict[str, Any]) -> str:
    known = _intel(entry)
    return f" Already listed by abuse.ch: {known}." if known else ""


def _confidence(value: Any) -> int | None:
    """0..1 float -> 0..100 int (STIX confidence)."""
    if isinstance(value, (int, float)) and 0 <= value <= 1:
        return int(round(value * 100))
    return None


def _md(value: Any) -> str:
    """Make an API string safe inside a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def result_markdown(job: dict[str, Any], reused: bool = False) -> str:
    """The Note body: outcome, charge, family, C2 table (defanged) and report link."""
    outcome = job.get("outcome") or "-"
    lines = [
        f"**Outcome:** {outcome} ({outcome_label(job)})",
        f"**Charge:** {format_cents(job.get('charge_cents'))}"
        + (
            " (charged when the job first ran; reusing it costs nothing)"
            if reused
            else ""
        ),
    ]
    family = job.get("family") or {}
    if family.get("name"):
        conf = _confidence(family.get("confidence"))
        lines.append(
            f"**Malware family:** {_md(family['name'])}"
            + (f" (confidence {conf}%)" if conf is not None else "")
        )
    lines.append(
        f"**Sample:** {_md(job.get('filename') or '-')}, package {_md(job.get('package') or '-')}, "
        f"SHA-256 `{job.get('sha256') or '-'}`"
    )
    android = job.get("android") or {}
    if android:
        tried = ", ".join(str(v) for v in android.get("tried") or []) or "-"
        lines.append(
            f"**Android:** tried {tried}; ran on {android.get('ran_on') or '-'}"
        )
    lines.append(f"**Job:** `{job.get('job_id') or '-'}`")
    if job.get("web_url"):
        lines.append(f"**Report:** {job['web_url']} (on tajapps.com, after sign-in)")

    c2 = job.get("c2") or []
    if c2:
        lines += [
            "",
            "| C2 (defanged) | Kind | Live | Liveness check | Confidence | Source | Known to abuse.ch |",
            "|---|---|---|---|---|---|---|",
        ]
        for entry in c2:
            conf = _confidence(entry.get("confidence"))
            lines.append(
                f"| {_md(entry.get('defanged') or (defang(entry['value']) if entry.get('value') else '-'))} "
                f"| {_md(entry.get('kind') or '-')} "
                f"| {'yes' if entry.get('live') else 'no'} "
                f"| {_md(liveness_text(entry))} "
                f"| {f'{conf}%' if conf is not None else '-'} "
                f"| {_md(entry.get('source') or '-')} "
                f"| {_md(_intel(entry) or 'no')} |"
            )
    rejected = job.get("rejected_candidates") or []
    if rejected:
        lines += [
            "",
            f"{len(rejected)} candidate(s) were rejected by the Privara verifier "
            "(for example embedded SDK or asset hosts) and are not indicators.",
        ]
    return "\n".join(lines)
