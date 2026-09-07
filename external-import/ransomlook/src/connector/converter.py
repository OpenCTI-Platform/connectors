import base64
import hashlib
import json
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from html import unescape
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import stix2
from connector.evidence import EvidencePayload
from pycti import (
    AttackPattern,
    CustomObservableCryptocurrencyWallet,
    Identity,
    Incident,
    Infrastructure,
    IntrusionSet,
    Malware,
    MarkingDefinition,
    Note,
    Report,
    StixCoreRelationship,
    ThreatActorGroup,
    ThreatActorIndividual,
)


class RansomLookConverter:
    """Convert normalized RansomLook records into deterministic STIX 2.1 objects."""

    SOURCE_EPOCH = datetime(2022, 1, 1, tzinfo=timezone.utc)
    REPORT_SCREEN_FILENAME = "ransomnote.png"
    MAX_DESCRIPTION_LENGTH = 100_000
    MAX_NOTE_CONTENT_LENGTH = 1_000_000
    MAX_PROFILE_REFERENCES = 25
    MAX_ACTOR_VALUES = 100
    ATTACK_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")

    @staticmethod
    def canonical_identity(value: str) -> str:
        """Return a stable, comparison-safe identity for upstream names."""
        return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()

    @classmethod
    def claim_route_identity(cls, post: dict[str, Any]) -> str:
        """Return the canonical dedicated-post route without occurrence state."""
        return json.dumps(
            [
                "ransomlook-claim",
                cls.canonical_identity(post["group_name"]),
                cls.canonical_identity(post["post_title"]),
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @classmethod
    def claim_identity(cls, post: dict[str, Any]) -> str:
        """Return one persisted occurrence of the authoritative post route.

        RansomLook's index, group history, and dedicated endpoint do not expose
        one consistently populated identifier field.  The dedicated endpoint is
        addressed by group and post title.  The connector persists the first
        accepted discovery time for a recent route so timestamp corrections keep
        one identity, then expires that mapping so a later genuine recurrence can
        become a distinct occurrence. Optional IDs remain provenance context.
        """
        identity_discovered = post.get("_ransomlook_identity_discovered") or post.get(
            "discovered"
        )
        discovered = cls.parse_timestamp(identity_discovered).isoformat()
        return json.dumps(
            [
                "ransomlook-claim-occurrence",
                cls.canonical_identity(post["group_name"]),
                cls.canonical_identity(post["post_title"]),
                discovered,
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @classmethod
    def claim_identity_timestamp(cls, post: dict[str, Any]) -> datetime:
        """Return the immutable timestamp for one persisted claim occurrence."""
        return cls.parse_timestamp(
            post.get("_ransomlook_identity_discovered") or post.get("discovered")
        )

    def __init__(
        self,
        base_url: str,
        labels: list[str],
        marking: str,
    ) -> None:
        """Initialize source attribution, labels, and the configured marking.

        Args:
            base_url: RansomLook API root used in external references.
            labels: OpenCTI labels attached to imported entities.
            marking: TLP marking name applied to imported objects.
        """
        self.base_url = base_url.rstrip("/")
        parsed_base = urlsplit(self.base_url)
        public_path = parsed_base.path.rstrip("/")
        if public_path.casefold().endswith("/api"):
            public_path = public_path[:-4]
        self.public_base_url = urlunsplit(
            (parsed_base.scheme, parsed_base.netloc, f"{public_path}/", "", "")
        )
        self.labels = labels
        self.author = stix2.Identity(
            id=Identity.generate_id("RansomLook", "organization"),
            name="RansomLook",
            identity_class="organization",
            description="Open ransomware intelligence and ransomware-group tracker.",
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            external_references=[
                stix2.ExternalReference(
                    source_name="RansomLook", url="https://www.ransomlook.io/"
                )
            ],
        )
        self.marking = self._marking(marking)

    @staticmethod
    def _marking(value: str) -> stix2.MarkingDefinition:
        """Create or select the requested TLP marking definition.

        Args:
            value: OpenCTI TLP marking name.

        Returns:
            A standard or OpenCTI-compatible custom marking definition.
        """
        standard = {
            "TLP:WHITE": stix2.TLP_WHITE,
            "TLP:GREEN": stix2.TLP_GREEN,
            "TLP:AMBER": stix2.TLP_AMBER,
            "TLP:RED": stix2.TLP_RED,
        }
        if value in standard:
            return standard[value]
        return stix2.MarkingDefinition(
            id=MarkingDefinition.generate_id("TLP", value),
            created=RansomLookConverter.SOURCE_EPOCH,
            definition_type="statement",
            definition={"statement": "custom"},
            allow_custom=True,
            custom_properties={
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": value,
            },
        )

    @staticmethod
    def parse_timestamp(value: Any) -> datetime:
        """Parse an API timestamp and normalize it to UTC.

        Args:
            value: ISO-8601 timestamp, with or without a timezone.

        Returns:
            A timezone-aware UTC datetime.

        Raises:
            ValueError: If the timestamp is empty or invalid.
        """
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and value:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            raise ValueError("RansomLook post has no discovery timestamp")
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def clean_description(value: Any) -> str | None:
        """Convert simple upstream HTML into safe plain text.

        Args:
            value: Optional HTML or plain-text description.

        Returns:
            Cleaned text, or ``None`` when no meaningful content remains.
        """
        if not isinstance(value, str) or not value:
            return None
        value = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
        value = re.sub(r"<[^>]+>", "", value)
        value = unescape(value).strip()
        if not value:
            return None
        return value[: RansomLookConverter.MAX_DESCRIPTION_LENGTH]

    def _properties(self) -> dict[str, Any]:
        """Return common OpenCTI custom properties for observables."""
        return {
            "x_opencti_labels": self.labels,
            "x_opencti_created_by_ref": self.author.id,
        }

    def create_group(self, name: str, metadata: dict[str, Any]) -> stix2.IntrusionSet:
        """Create a ransomware-group Intrusion Set.

        Args:
            name: Canonical RansomLook group name.
            metadata: Sanitized group metadata.

        Returns:
            Deterministically identified Intrusion Set.
        """
        description = self.clean_description(metadata.get("meta"))
        references = [
            stix2.ExternalReference(
                source_name="RansomLook",
                url=f"https://www.ransomlook.io/group/{quote(name, safe='')}",
            )
        ]
        profiles = metadata.get("profile")
        if isinstance(profiles, list):
            profile_urls: set[str] = set()
            for profile in profiles:
                normalized = self._normalize_http_url(profile)
                if not normalized or normalized in profile_urls:
                    continue
                profile_urls.add(normalized)
                references.append(
                    stix2.ExternalReference(
                        source_name="RansomLook group profile", url=normalized
                    )
                )
                if len(profile_urls) == self.MAX_PROFILE_REFERENCES:
                    break
        updated = self._optional_timestamp(
            metadata.get("updated")
            or metadata.get("updated_at")
            or metadata.get("lastscrape")
        )
        modified = updated or self.SOURCE_EPOCH
        return stix2.IntrusionSet(
            id=IntrusionSet.generate_id(self.canonical_identity(name)),
            name=name,
            description=description,
            created=self.SOURCE_EPOCH,
            modified=modified,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            external_references=references,
            custom_properties={"x_opencti_labels": self.labels},
        )

    @classmethod
    def _explicit_names(cls, value: Any) -> list[str]:
        """Return a bounded, stable list of non-empty explicitly supplied names."""
        if not isinstance(value, list):
            return []
        result: dict[str, str] = {}
        for item in value:
            if not isinstance(item, str):
                continue
            name = " ".join(item.split())[:512]
            if name:
                result.setdefault(cls.canonical_identity(name), name)
            if len(result) == cls.MAX_ACTOR_VALUES:
                break
        return list(result.values())

    @classmethod
    def actor_relation_names(cls, actor: dict[str, Any], relation: str) -> list[str]:
        """Return names from one explicit RansomLook actor relation collection."""
        relations = actor.get("relations")
        if not isinstance(relations, dict):
            return []
        return cls._explicit_names(relations.get(relation))

    @staticmethod
    def actor_name(actor: dict[str, Any]) -> str | None:
        """Return one bounded named-actor identity, never a group-name fallback."""
        name = actor.get("name")
        if not isinstance(name, str):
            return None
        normalized = " ".join(name.split())[:512]
        return normalized or None

    def create_named_actor(
        self, actor: dict[str, Any], *, related_stub: bool = False
    ) -> stix2.ThreatActor | None:
        """Create a distinct named Threat Actor from explicit upstream fields."""
        name = self.actor_name(actor)
        if name is None:
            return None
        aliases = [
            alias
            for alias in self._explicit_names(actor.get("aliases"))
            if self.canonical_identity(alias) != self.canonical_identity(name)
        ]
        roles = self._explicit_names(actor.get("roles"))
        references = [
            stix2.ExternalReference(
                source_name="RansomLook named actor",
                url=f"{self.base_url}/actors/{quote(name, safe='')}",
            )
        ]
        for profile in self._explicit_names(actor.get("profile")):
            normalized = self._normalize_http_url(profile)
            if normalized and not any(
                reference.get("url") == normalized for reference in references
            ):
                references.append(
                    stix2.ExternalReference(
                        source_name="RansomLook actor profile", url=normalized
                    )
                )
            if len(references) > self.MAX_PROFILE_REFERENCES:
                break

        contacts: dict[str, str] = {}
        raw_contacts = actor.get("contacts")
        if isinstance(raw_contacts, dict):
            for channel, value in raw_contacts.items():
                if not isinstance(channel, str) or not isinstance(value, str):
                    continue
                clean_channel = " ".join(channel.split())[:128]
                clean_value = " ".join(value.split())[:1024]
                if clean_channel and clean_value:
                    contacts[clean_channel] = clean_value
                if len(contacts) == self.MAX_ACTOR_VALUES:
                    break

        wanted_sources: list[str] = []
        wanted = actor.get("wanted")
        if isinstance(wanted, dict):
            for authority, detail in wanted.items():
                if (
                    not isinstance(authority, str)
                    or not authority.strip()
                    or not detail
                ):
                    continue
                wanted_sources.append(" ".join(authority.split())[:128])
                if isinstance(detail, dict):
                    normalized = self._normalize_http_url(detail.get("url"))
                    if normalized:
                        references.append(
                            stix2.ExternalReference(
                                source_name=f"RansomLook wanted: {authority[:128]}",
                                url=normalized,
                            )
                        )
                if len(wanted_sources) == self.MAX_ACTOR_VALUES:
                    break
        elif actor.get("has_wanted") is True:
            wanted_sources.append("upstream-summary")

        explicit_collective = str(
            actor.get("actor_type") or actor.get("kind") or ""
        ).casefold() in {"collective", "group", "organization"}
        actor_id = (
            ThreatActorGroup.generate_id(name)
            if explicit_collective
            else ThreatActorIndividual.generate_id(name)
        )
        custom: dict[str, Any] = {
            "x_opencti_labels": self.labels,
            "x_ransomlook_actor_profile": True,
        }
        if not explicit_collective:
            custom["resource_level"] = "individual"
        if contacts:
            custom["x_ransomlook_contacts"] = contacts
        if wanted_sources:
            custom["x_ransomlook_wanted"] = True
            custom["x_ransomlook_wanted_sources"] = wanted_sources
        if related_stub:
            custom["x_ransomlook_relation_stub"] = True
        return stix2.ThreatActor(
            id=actor_id,
            name=name,
            aliases=aliases or None,
            roles=roles or None,
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            external_references=references,
            allow_custom=True,
            custom_properties=custom,
        )

    def create_actor_forum(self, name: str) -> stix2.Infrastructure | None:
        """Represent an explicitly related forum or market as profile Infrastructure."""
        normalized = self.actor_name({"name": name})
        if normalized is None:
            return None
        identity = self.canonical_identity(normalized)
        return stix2.Infrastructure(
            id=Infrastructure.generate_id(f"ransomlook:actor-forum:{identity}"),
            name=normalized,
            description=(
                "Forum or market explicitly related to a named actor by RansomLook; "
                "the relation does not imply ownership or control."
            ),
            infrastructure_types=["unknown"],
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            custom_properties={
                "x_opencti_labels": self.labels,
                "x_ransomlook_profile_role": "forum-or-market",
            },
        )

    def create_profile_relationship(
        self, source: str, target: str, upstream_relation: str
    ) -> stix2.Relationship:
        """Create an attributed conservative edge for one explicit actor relation."""
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id("related-to", source, target),
            relationship_type="related-to",
            source_ref=source,
            target_ref=target,
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            allow_custom=True,
            custom_properties={
                "x_ransomlook_relation": upstream_relation,
                "x_ransomlook_source": "RansomLook actor profile",
            },
        )

    def create_victim(self, name: str) -> stix2.Identity:
        """Create a victim organization Identity.

        Args:
            name: Victim name published by the ransomware group.

        Returns:
            Deterministically identified organization Identity.
        """
        return stix2.Identity(
            id=Identity.generate_id(self.canonical_identity(name), "organization"),
            name=name,
            identity_class="organization",
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            custom_properties={"x_opencti_labels": self.labels},
        )

    def create_incident(self, post: dict[str, Any]) -> stix2.Incident:
        """Create an Incident for a ransomware claim.

        Args:
            post: Normalized RansomLook post.

        Returns:
            Incident identified by claim name and discovery time.
        """
        discovered = self.parse_timestamp(post.get("discovered"))
        created = self.claim_identity_timestamp(post)
        group = post["group_name"]
        victim = post["post_title"]
        name = f"{group} ransomware claim against {victim}"
        references = [
            stix2.ExternalReference(
                source_name="RansomLook",
                url=f"{self.base_url}/post/{quote(group, safe='')}/{quote(victim, safe='')}",
            )
        ]
        source_link = self.normalize_source_url(post.get("link"))
        if source_link:
            references.append(
                stix2.ExternalReference(
                    source_name="RansomLook leak post", url=source_link
                )
            )
        return stix2.Incident(
            id=Incident.generate_id(self.claim_identity(post), self.SOURCE_EPOCH),
            name=name,
            description=self.claim_description(post),
            created=created,
            modified=max(discovered, created),
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            external_references=references,
            custom_properties={
                "x_opencti_labels": self.labels,
                "first_seen": discovered,
                "last_seen": discovered,
            },
        )

    def create_report(
        self,
        post: dict[str, Any],
        refs: list[str],
        evidence: list[EvidencePayload] | None = None,
    ) -> stix2.Report:
        """Create a Report that contains one complete claim graph.

        Args:
            post: Normalized RansomLook post.
            refs: STIX IDs included in the report.

        Returns:
            Deterministically identified threat Report.
        """
        published = self.parse_timestamp(post.get("discovered"))
        created = self.claim_identity_timestamp(post)
        name = f"RansomLook: {post['group_name']} - {post['post_title']}"
        report_id = Report.generate_id(self.claim_identity(post), self.SOURCE_EPOCH)
        evidence_files = self.create_report_evidence_files(evidence or [])
        return stix2.Report(
            id=report_id,
            name=name,
            description=self.claim_description(post),
            created=created,
            modified=max(published, created),
            published=published,
            report_types=["threat-report"],
            object_refs=list(dict.fromkeys(refs)),
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            external_references=[
                stix2.ExternalReference(
                    source_name="RansomLook",
                    url=f"{self.base_url}/post/{quote(post['group_name'], safe='')}/{quote(post['post_title'], safe='')}",
                )
            ],
            custom_properties={
                "x_opencti_labels": self.labels,
                **({"x_opencti_files": evidence_files} if evidence_files else {}),
            },
        )

    def create_report_evidence_files(
        self, evidence: list[EvidencePayload]
    ) -> list[dict[str, Any]]:
        """Expose validated claim captures in OpenCTI's Report Files UI.

        The caller supplies the same payloads already accepted by the evidence
        decoder for Artifact creation. This method does not decode, inspect, or
        fetch content, so rejection and byte/count budgets remain authoritative.
        The validated PNG is exposed twice from the same accepted bytes: once as
        the normal downloadable ``ransomnote.png`` Report file and once under a
        distinct content-addressed embedded filename. OpenCTI stores normal and
        embedded files in different namespaces, so the normal file remains the
        analyst-facing attachment while the embedded copy remains separately
        available. Neither screenshot nor HTML is copied into Report main content.
        """
        extensions = {"screen": "png", "source": "html"}
        files: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for payload in sorted(
            evidence,
            key=lambda item: (
                {"screen": 0, "source": 1}.get(item.kind, 2),
                item.sha256,
            ),
        ):
            extension = extensions.get(payload.kind)
            identity = (payload.kind, payload.sha256)
            if extension is None or identity in seen:
                continue
            seen.add(identity)
            encoded = base64.b64encode(payload.content).decode("ascii")
            embedded_values = (False, True) if payload.kind == "screen" else (False,)
            for embedded in embedded_values:
                files.append(
                    {
                        "name": self.report_evidence_filename(
                            payload, embedded=embedded
                        ),
                        "data": encoded,
                        "mime_type": payload.mime_type,
                        "no_trigger_import": True,
                        "embedded": embedded,
                        "object_marking_refs": [self.marking.id],
                    }
                )
        return files

    @staticmethod
    def report_evidence_filename(
        payload: EvidencePayload, *, embedded: bool = False
    ) -> str:
        """Return a deterministic safe Report filename for accepted evidence."""
        if payload.kind == "screen":
            return (
                f"ransomlook-screen-{payload.sha256[:16]}-inline.png"
                if embedded
                else RansomLookConverter.REPORT_SCREEN_FILENAME
            )
        if payload.kind == "source":
            return f"ransomlook-source-{payload.sha256[:16]}.html"
        raise ValueError("unsupported Report evidence kind")

    def claim_description(self, post: dict[str, Any]) -> str:
        """Describe an upstream post without asserting a confirmed compromise."""
        group = str(post["group_name"])
        victim = str(post["post_title"])
        description = (
            f"RansomLook observed {group} publishing a ransomware claim naming "
            f"{victim}. This record represents the observed claim and does not "
            "independently confirm intrusion, encryption, exfiltration, payment, "
            "or publication."
        )
        upstream = self.clean_description(post.get("description"))
        if upstream:
            description = f"{description}\n\nUpstream claim text:\n{upstream}"
        return description

    def create_relationship(
        self,
        source: str,
        relationship: str,
        target: str,
        timestamp: datetime | None = None,
    ) -> stix2.Relationship:
        """Create a deterministic STIX relationship.

        Args:
            source: Source STIX ID.
            relationship: STIX relationship type.
            target: Target STIX ID.
            timestamp: Stable relationship creation/modification time.

        Returns:
            Relationship with stable source/type/target identity.
        """
        created = timestamp or self.SOURCE_EPOCH
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(relationship, source, target),
            relationship_type=relationship,
            source_ref=source,
            target_ref=target,
            created=created,
            modified=created,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
        )

    def create_evidence_artifact(
        self,
        evidence: EvidencePayload,
    ) -> stix2.Artifact:
        """Create a deterministic passive Artifact identified by type and hash."""
        if evidence.kind == "technical-analysis":
            extension = {
                "application/pdf": "pdf",
                "text/html": "html",
                "text/plain": "txt",
            }[evidence.mime_type]
        else:
            extension = {
                "screen": "png",
                "source": "html",
                "ransom-note": "html" if evidence.mime_type == "text/html" else "txt",
                "torrent": "torrent",
            }[evidence.kind]
        custom: dict[str, Any] = {
            "x_opencti_labels": self.labels,
            "x_opencti_created_by_ref": self.author.id,
            "x_opencti_description": (
                f"RansomLook {evidence.kind} capture; passive evidence, "
                "not rendered or executed."
            ),
            "x_opencti_additional_names": [
                f"ransomlook-{evidence.sha256[:16]}.{extension}"
            ],
            "x_ransomlook_evidence_kind": evidence.kind,
            "x_ransomlook_source_name": "RansomLook",
        }
        return stix2.Artifact(
            id=f"artifact--{uuid.uuid5(uuid.NAMESPACE_URL, f'ransomlook:{evidence.kind}:{evidence.sha256}')}",
            payload_bin=base64.b64encode(evidence.content).decode("ascii"),
            mime_type=evidence.mime_type,
            hashes={"SHA-256": evidence.sha256},
            object_marking_refs=[self.marking],
            custom_properties=custom,
        )

    @staticmethod
    def analysis_identity(analysis: dict[str, Any]) -> str | None:
        """Return a stable identity only when upstream supplies one explicitly."""
        for field in ("id", "uuid", "analysis_id"):
            value = analysis.get(field)
            if isinstance(value, (str, int)) and str(value).strip():
                return str(value).strip()[:512]
        return None

    def create_analysis_malware(self, value: Any) -> stix2.Malware | None:
        """Create Malware only from an explicit structured analysis mapping."""
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            return None
        name = " ".join(value["name"].split())[:512]
        if not name:
            return None
        aliases = self._explicit_names(value.get("aliases"))
        description = self.clean_description(value.get("description"))
        return stix2.Malware(
            id=Malware.generate_id(self.canonical_identity(name)),
            name=name,
            aliases=aliases or None,
            description=description,
            is_family=value.get("is_family") is True,
            malware_types=self._explicit_names(value.get("malware_types")) or None,
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            custom_properties={
                "x_opencti_labels": self.labels,
                "x_ransomlook_analysis_explicit": True,
            },
        )

    def create_analysis_attack_pattern(self, value: Any) -> stix2.AttackPattern | None:
        """Create only syntactically valid, explicitly mapped ATT&CK techniques."""
        if not isinstance(value, dict):
            return None
        external_id = value.get("external_id") or value.get("attack_id")
        name = value.get("name")
        if (
            not isinstance(external_id, str)
            or not self.ATTACK_ID.fullmatch(external_id.strip().upper())
            or not isinstance(name, str)
            or not " ".join(name.split())
        ):
            return None
        external_id = external_id.strip().upper()
        clean_name = " ".join(name.split())[:512]
        return stix2.AttackPattern(
            id=AttackPattern.generate_id(name=clean_name, x_mitre_id=external_id),
            name=clean_name,
            description=self.clean_description(value.get("description")),
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            external_references=[
                stix2.ExternalReference(
                    source_name="mitre-attack", external_id=external_id
                )
            ],
            custom_properties={
                "x_mitre_id": external_id,
                "x_opencti_labels": self.labels,
                "x_ransomlook_analysis_explicit": True,
            },
        )

    @staticmethod
    def _explicit_maliciousness(value: dict[str, Any]) -> bool:
        return (
            value.get("malicious") is True
            or str(value.get("classification") or value.get("verdict") or "").casefold()
            == "malicious"
        )

    @staticmethod
    def _detection_basis(value: dict[str, Any]) -> str | None:
        for field in ("detection_basis", "detection", "rule", "signature"):
            basis = value.get(field)
            if isinstance(basis, str) and basis.strip():
                return " ".join(basis.split())[:2048]
            if isinstance(basis, dict):
                parts = [
                    f"{key}={item}"
                    for key, item in sorted(basis.items())
                    if isinstance(key, str)
                    and isinstance(item, (str, int, float, bool))
                    and str(item).strip()
                ]
                if parts:
                    return "; ".join(parts)[:2048]
        return None

    def create_analysis_observable(self, value: Any) -> Any | None:
        """Create an observable only for an explicit malicious analysis assertion."""
        if not isinstance(value, dict) or not self._explicit_maliciousness(value):
            return None
        kind = str(value.get("type") or "").strip().casefold()
        raw = value.get("value")
        if not isinstance(raw, str) or not raw.strip():
            return None
        raw = raw.strip()
        custom = {
            **self._properties(),
            "x_opencti_description": (
                "Observable explicitly asserted malicious by RansomLook technical "
                "analysis; review the linked analysis for its evidentiary basis."
            ),
            "x_ransomlook_explicit_malicious": True,
        }
        if kind in {"domain", "domain-name"}:
            normalized = self._normalize_hostname(raw)
            if normalized is None or normalized[1]:
                return None
            try:
                ip_address(normalized[0])
                return None
            except ValueError:
                pass
            return stix2.DomainName(
                value=normalized[0],
                object_marking_refs=[self.marking],
                custom_properties=custom,
            )
        if kind == "url":
            return next(
                (
                    obj
                    for obj in self.create_website_observables(raw)
                    if obj.type == "url"
                ),
                None,
            )
        if kind in {"ipv4", "ipv4-addr", "ipv6", "ipv6-addr", "ip"}:
            try:
                address = ip_address(raw)
            except ValueError:
                return None
            expected = (
                4
                if kind.startswith("ipv4")
                else 6 if kind.startswith("ipv6") else address.version
            )
            if address.version != expected:
                return None
            cls = stix2.IPv4Address if address.version == 4 else stix2.IPv6Address
            return cls(
                value=str(address),
                object_marking_refs=[self.marking],
                custom_properties=custom,
            )
        if kind in {"file", "file-hash", "hash"}:
            algorithm = (
                str(value.get("hash_type") or value.get("algorithm") or "")
                .upper()
                .replace("_", "-")
            )
            algorithm = {"SHA256": "SHA-256", "SHA1": "SHA-1", "MD5": "MD5"}.get(
                algorithm, algorithm
            )
            lengths = {"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-512": 128}
            if algorithm not in lengths or not re.fullmatch(
                rf"[0-9A-Fa-f]{{{lengths[algorithm]}}}", raw
            ):
                return None
            return stix2.File(
                hashes={algorithm: raw.casefold()},
                object_marking_refs=[self.marking],
                custom_properties=custom,
            )
        return None

    @staticmethod
    def _indicator_pattern(observable: Any) -> str | None:
        def escaped(item: Any) -> str:
            return str(item).replace("\\", "\\\\").replace("'", "\\'")

        if observable.type in {"domain-name", "url", "ipv4-addr", "ipv6-addr"}:
            return f"[{observable.type}:value = '{escaped(observable.value)}']"
        if observable.type == "file":
            algorithm, digest = next(iter(observable.hashes.items()))
            return f"[file:hashes.'{algorithm}' = '{digest}']"
        return None

    def create_analysis_indicator(
        self, value: dict[str, Any], observable: Any
    ) -> stix2.Indicator | None:
        """Create an Indicator only with explicit maliciousness and detection basis."""
        if not self._explicit_maliciousness(value):
            return None
        basis = self._detection_basis(value)
        pattern = self._indicator_pattern(observable)
        if basis is None or pattern is None:
            return None
        observed = (
            self._optional_timestamp(value.get("observed") or value.get("created"))
            or self.SOURCE_EPOCH
        )
        return stix2.Indicator(
            id=f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'ransomlook:{pattern}:{basis}')}",
            name=(
                str(value.get("name")).strip()[:512]
                if isinstance(value.get("name"), str) and value.get("name").strip()
                else f"RansomLook detection for {observable.type}"
            ),
            pattern=pattern,
            pattern_type="stix",
            valid_from=observed,
            indicator_types=["malicious-activity"],
            created=observed,
            modified=observed,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            custom_properties={
                "x_opencti_labels": self.labels,
                "x_ransomlook_detection_basis": basis,
                "x_ransomlook_explicit_malicious": True,
            },
        )

    def create_analysis_report(
        self, analysis: dict[str, Any], object_refs: list[str]
    ) -> stix2.Report | None:
        """Create a profile-scoped technical Report from an explicit analysis ID."""
        identity = self.analysis_identity(analysis)
        if identity is None or not object_refs:
            return None
        raw_name = analysis.get("title") or analysis.get("name")
        name = (
            " ".join(raw_name.split())[:512]
            if isinstance(raw_name, str)
            else "RansomLook technical analysis"
        )
        published = (
            self._optional_timestamp(
                analysis.get("published")
                or analysis.get("created")
                or analysis.get("date")
            )
            or self.SOURCE_EPOCH
        )
        return stix2.Report(
            id=Report.generate_id(f"ransomlook:analysis:{identity}", published),
            name=name or "RansomLook technical analysis",
            description=self.clean_description(
                analysis.get("description") or analysis.get("summary")
            ),
            published=published,
            created=published,
            modified=published,
            report_types=["threat-report"],
            object_refs=list(dict.fromkeys(object_refs)),
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            external_references=[
                stix2.ExternalReference(
                    source_name="RansomLook",
                    url=f"{self.base_url}/analysis/{quote(identity, safe='')}",
                )
            ],
            custom_properties={
                "x_opencti_labels": self.labels,
                "x_ransomlook_analysis_id": identity,
                "x_ransomlook_scope": "actor-profile-unless-explicit-claim-link",
            },
        )

    @staticmethod
    def normalize_infohash(value: Any) -> str | None:
        """Return a canonical BitTorrent v1 infohash without guessing."""
        if not isinstance(value, str):
            return None
        candidate = value.strip()
        if re.fullmatch(r"[0-9A-Fa-f]{40}", candidate):
            return candidate.casefold()
        if re.fullmatch(r"[A-Z2-7a-z2-7]{32}", candidate):
            return candidate.upper()
        return None

    def create_magnet_observable(self, torrent: dict[str, Any]) -> stix2.URL | None:
        """Create a stable contextual magnet URL from an explicit infohash."""
        infohash = self.normalize_infohash(
            torrent.get("infohash") or torrent.get("info_hash")
        )
        if infohash is None:
            return None
        value = f"magnet:?xt=urn:btih:{infohash}"
        custom: dict[str, Any] = {
            **self._properties(),
            "x_opencti_description": (
                "RansomLook BitTorrent leak mechanism context; not an Indicator."
            ),
            "x_ransomlook_infohash": infohash,
            "x_ransomlook_source_name": "RansomLook",
        }
        return stix2.URL(
            id=f"url--{uuid.uuid5(uuid.NAMESPACE_URL, f'ransomlook:magnet:{infohash}')}",
            value=value,
            object_marking_refs=[self.marking],
            custom_properties=custom,
        )

    def create_torrent_peer(self, value: Any) -> Any | None:
        """Create opt-in peer telemetry as context, never as an Indicator."""
        if not isinstance(value, str):
            return None
        try:
            address = ip_address(value.strip())
        except ValueError:
            return None
        observable_type = (
            stix2.IPv4Address if address.version == 4 else stix2.IPv6Address
        )
        return observable_type(
            value=str(address),
            object_marking_refs=[self.marking],
            custom_properties={
                **self._properties(),
                "x_opencti_description": (
                    "RansomLook torrent peer telemetry; presence does not imply "
                    "maliciousness and this is not an Indicator."
                ),
                "x_ransomlook_peer_telemetry": True,
            },
        )

    def create_leak_note(
        self, leak: dict[str, Any], owner_id: str
    ) -> stix2.Note | None:
        """Represent an explicitly related leak record as contextual STIX."""
        upstream_id = leak.get("id") or leak.get("uuid") or leak.get("leak_id")
        if not isinstance(upstream_id, (str, int)) or not str(upstream_id).strip():
            return None
        raw_name = leak.get("name") or leak.get("title")
        name = raw_name.strip() if isinstance(raw_name, str) else "Data leak record"
        description = self.clean_description(leak.get("description"))
        domain = leak.get("domain")
        content = (
            "RansomLook explicitly related data-leak corpus record. This is "
            "contextual evidence and does not independently prove exfiltration "
            "or publication."
        )
        if description:
            content += f"\n\nUpstream description:\n{description}"
        custom: dict[str, Any] = {
            "x_opencti_labels": self.labels,
            "x_ransomlook_leak_id": str(upstream_id).strip(),
            "x_ransomlook_source_name": "RansomLook",
            "x_ransomlook_relation_basis": "explicit-upstream-identifier",
        }
        if isinstance(domain, str) and domain.strip():
            custom["x_ransomlook_leak_domain_context"] = domain.strip()[:1024]
        return stix2.Note(
            id=Note.generate_id(
                None, f"ransomlook:leak:{str(upstream_id).strip()}:{owner_id}"
            ),
            abstract=(name or "Data leak record")[:256],
            content=content[: self.MAX_NOTE_CONTENT_LENGTH],
            object_refs=[owner_id],
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            custom_properties=custom,
        )

    def create_direct_leak_relationship(
        self, evidence_id: str, owner_id: str, kind: str
    ) -> stix2.Relationship:
        """Create a conservative attributed edge backed by an explicit ID."""
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id("related-to", evidence_id, owner_id),
            relationship_type="related-to",
            source_ref=evidence_id,
            target_ref=owner_id,
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            allow_custom=True,
            custom_properties={
                "x_ransomlook_relation": f"direct-{kind}",
                "x_ransomlook_source": "RansomLook",
                "x_ransomlook_relation_basis": "explicit-upstream-identifier",
            },
        )

    def create_evidence_relationship(
        self,
        artifact_id: str,
        owner_id: str,
        scope: str,
        upstream_identifier: str,
        source_url: str | None,
        observed: datetime | None,
    ) -> stix2.Relationship:
        """Associate content-addressed evidence while preserving source context."""
        created = observed or self.SOURCE_EPOCH
        custom: dict[str, Any] = {
            "x_ransomlook_evidence_scope": scope,
            "x_ransomlook_upstream_identifier": upstream_identifier[:1024],
            "x_ransomlook_source_name": "RansomLook",
        }
        normalized_url = self.normalize_source_url(source_url)
        if normalized_url:
            custom["x_ransomlook_source_url"] = normalized_url
        if observed is not None:
            custom["x_ransomlook_observed"] = observed.isoformat()
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id("related-to", artifact_id, owner_id),
            relationship_type="related-to",
            source_ref=artifact_id,
            target_ref=owner_id,
            created=created,
            modified=created,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            custom_properties=custom,
        )

    def create_website_observables(
        self, value: str | None
    ) -> list[stix2.DomainName | stix2.URL]:
        """Create URL and Domain Name observables for a valid HTTP(S) site.

        Args:
            value: Website or leak-site value.

        Returns:
            Domain and URL observables, or an empty list for invalid input.
        """
        normalized = self._normalize_http_url(value)
        if not normalized:
            return []
        parsed = urlsplit(normalized)
        objects: list[stix2.DomainName | stix2.URL] = []
        custom = self._properties()
        hostname = parsed.hostname
        if hostname is None:
            return []
        try:
            ip_address(hostname)
        except ValueError:
            objects.append(
                stix2.DomainName(
                    value=hostname,
                    object_marking_refs=[self.marking],
                    custom_properties=custom,
                )
            )
        objects.append(
            stix2.URL(
                value=normalized,
                object_marking_refs=[self.marking],
                custom_properties=custom,
            )
        )
        return objects

    def normalize_source_url(self, value: Any) -> str | None:
        """Resolve a RansomLook-relative post link against the public site.

        Post detail responses commonly use root-relative links such as
        ``/post/<identifier>``.  Treating those as hostnames produces an invalid
        ``https://post/...`` observable, so resolve them before validation.
        """
        if not isinstance(value, str) or not value.strip():
            return None
        candidate = value.strip()
        parsed = urlsplit(candidate)
        if (
            not parsed.scheme
            and not parsed.netloc
            and (
                candidate.startswith("/")
                or "/" in candidate
                and "." not in candidate.split("/", 1)[0]
            )
        ):
            candidate = urljoin(self.public_base_url, candidate)
        return self._normalize_http_url(candidate)

    @staticmethod
    def _location_flag(value: Any) -> bool:
        """Interpret the boolean forms used by RansomLook location records."""
        return value is True or (
            isinstance(value, str)
            and value.strip().casefold() in {"1", "true", "yes", "on"}
        )

    @classmethod
    def location_roles(cls, location: dict[str, Any]) -> list[str]:
        """Return all explicit and derived location roles without collapsing them."""
        private = cls._location_flag(location.get("private"))
        functional = [
            role
            for role, fields in (
                ("file-server", ("fs",)),
                ("chat", ("chat",)),
                ("admin", ("admin",)),
                ("relay", ("relay", "mirror")),
            )
            if any(cls._location_flag(location.get(field)) for field in fields)
        ]
        if cls._location_flag(location.get("dls")) or not functional:
            functional.insert(0, "data-leak-site")
        return ["private" if private else "public", *functional]

    @classmethod
    def location_identity(cls, value: Any) -> str | None:
        """Return a stable logical location key independent of mutable status."""
        if not isinstance(value, str):
            return None
        raw = " ".join(value.strip().split())
        if not raw or len(raw) > 4096 or any(ord(character) < 32 for character in raw):
            return None
        return cls._normalize_http_url(raw) or cls.canonical_identity(raw)

    @classmethod
    def _optional_timestamp(cls, value: Any) -> datetime | None:
        """Parse an optional upstream lifecycle timestamp without conflating fields."""
        try:
            return cls.parse_timestamp(value)
        except (TypeError, ValueError):
            return None

    def create_location_infrastructure(
        self, group_name: str, location: dict[str, Any]
    ) -> list[Any]:
        """Create typed Infrastructure, components, and their local relationships."""
        raw_location = location.get("slug")
        identity = self.location_identity(raw_location)
        if identity is None:
            return []
        roles = self.location_roles(location)
        normalized_url = self._normalize_http_url(raw_location)
        display_location = normalized_url or str(raw_location).strip()

        first_observed = next(
            (
                parsed
                for key in ("firstseen", "first_seen", "discovered")
                if (parsed := self._optional_timestamp(location.get(key))) is not None
            ),
            None,
        )
        last_scraped = self._optional_timestamp(location.get("lastscrape"))
        upstream_updated = self._optional_timestamp(location.get("updated"))
        custom: dict[str, Any] = {
            "x_opencti_labels": self.labels,
            "x_ransomlook_location": display_location,
            "x_ransomlook_roles": roles,
            "x_ransomlook_access": roles[0],
        }
        if "available" in location:
            custom["x_ransomlook_available"] = self._location_flag(
                location.get("available")
            )
        if first_observed is not None:
            custom["x_ransomlook_first_observed"] = first_observed.isoformat()
        if last_scraped is not None:
            custom["x_ransomlook_last_scrape"] = last_scraped.isoformat()
        if upstream_updated is not None:
            custom["x_ransomlook_upstream_updated"] = upstream_updated.isoformat()

        standard_first_seen = first_observed
        standard_last_seen = last_scraped
        if (
            standard_first_seen is not None
            and standard_last_seen is not None
            and standard_last_seen < standard_first_seen
        ):
            # Retain both independently in custom source fields, but do not put an
            # inconsistent interval into the STIX lifecycle fields.
            standard_last_seen = None

        location_digest = hashlib.sha256(identity.encode()).hexdigest()[:12]
        infrastructure_name = (
            f"{self.canonical_identity(group_name)} infrastructure "
            f"[location {location_digest}]"
        )
        infrastructure = stix2.Infrastructure(
            # OpenCTI resolves Infrastructure identity by name.  Generate the
            # supplied STIX ID from that same collision-free value so separate
            # same-role locations cannot be consolidated during ingestion.
            id=Infrastructure.generate_id(infrastructure_name),
            name=infrastructure_name,
            description=(
                f"RansomLook actor-profile location: {display_location}. "
                f"Observed roles: {', '.join(roles)}. Availability is the latest "
                "observed reachability state and does not imply retirement."
            ),
            infrastructure_types=roles,
            created=self.SOURCE_EPOCH,
            modified=max(upstream_updated or self.SOURCE_EPOCH, self.SOURCE_EPOCH),
            first_seen=standard_first_seen,
            last_seen=standard_last_seen,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            custom_properties=custom,
        )
        objects: list[Any] = [infrastructure]
        for observable in self.create_website_observables(raw_location):
            objects.extend(
                [
                    observable,
                    self.create_relationship(
                        infrastructure.id, "consists-of", observable.id
                    ),
                ]
            )
        return objects

    def create_note(self, note: dict[str, Any], group_id: str) -> stix2.Note | None:
        """Create a ransom Note linked to its group.

        Args:
            note: RansomLook note record.
            group_id: Intrusion Set STIX ID referenced by the note.

        Returns:
            A deterministic Note, or ``None`` for empty content.
        """
        raw_content = note.get("content")
        if not isinstance(raw_content, str):
            return None
        content = raw_content.strip()
        if not content:
            return None
        content = content[: self.MAX_NOTE_CONTENT_LENGTH]
        upstream_id = str(note.get("id") or note.get("name") or content[:100])
        raw_name = note.get("name") or note.get("title")
        abstract = raw_name.strip() if isinstance(raw_name, str) else ""
        return stix2.Note(
            id=Note.generate_id(None, f"ransomlook:{group_id}:{upstream_id}"),
            abstract=(abstract or "Ransom note")[:256],
            content=content,
            object_refs=[group_id],
            created=self.SOURCE_EPOCH,
            modified=self.SOURCE_EPOCH,
            created_by_ref=self.author,
            object_marking_refs=[self.marking],
            custom_properties={"x_opencti_labels": self.labels},
        )

    @classmethod
    def normalize_wallet(cls, chain: Any, address: Any) -> tuple[str, str] | None:
        """Return a conservative chain and address identity for an observable."""
        if not isinstance(chain, str) or not isinstance(address, str):
            return None
        normalized_chain = cls.canonical_identity(chain).replace(" ", "-")
        normalized_chain = {
            "btc": "bitcoin",
            "xbt": "bitcoin",
            "eth": "ethereum",
            "xmr": "monero",
        }.get(normalized_chain, normalized_chain)
        normalized_address = unicodedata.normalize("NFKC", address).strip()
        if (
            not normalized_chain
            or len(normalized_chain) > 64
            or not re.fullmatch(r"[a-z0-9][a-z0-9+._-]*", normalized_chain)
            or not normalized_address
            or len(normalized_address) > 512
            or any(
                character.isspace() or ord(character) < 32
                for character in normalized_address
            )
        ):
            return None
        if normalized_chain == "ethereum" or (
            normalized_chain == "bitcoin"
            and normalized_address.casefold().startswith(("bc1", "tb1", "bcrt1"))
        ):
            normalized_address = normalized_address.casefold()
        return normalized_chain, normalized_address

    def create_wallet(
        self, wallet: dict[str, Any], chain: str
    ) -> CustomObservableCryptocurrencyWallet | None:
        """Create a chain-aware pinned OpenCTI cryptocurrency-wallet SCO."""
        normalized = self.normalize_wallet(
            wallet.get("blockchain") or chain, wallet.get("address")
        )
        if normalized is None:
            return None
        normalized_chain, address = normalized
        custom: dict[str, Any] = {
            "x_opencti_labels": self.labels,
            "x_opencti_created_by_ref": self.author.id,
            "x_opencti_description": (
                f"RansomLook actor-profile cryptocurrency wallet on {normalized_chain}; "
                "context only, not an Indicator."
            ),
            "x_ransomlook_chain": normalized_chain,
            "x_ransomlook_source_name": "RansomLook",
        }
        identity = f"ransomlook:wallet:{normalized_chain}:{address}"
        return CustomObservableCryptocurrencyWallet(
            id=f"cryptocurrency-wallet--{uuid.uuid5(uuid.NAMESPACE_URL, identity)}",
            value=address,
            object_marking_refs=[self.marking],
            custom_properties=custom,
        )

    @staticmethod
    def _normalize_http_url(  # pylint: disable=too-many-return-statements
        value: Any,
    ) -> str | None:
        """Normalize and validate an untrusted website value.

        Args:
            value: Candidate URL supplied by the upstream API.

        Returns:
            A normalized HTTP(S) URL, or ``None`` when invalid.
        """
        if not isinstance(value, str) or not value.strip():
            return None
        normalized = value.strip()
        if any(character.isspace() for character in normalized):
            return None
        scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", normalized)
        if scheme_match and scheme_match.group(1).lower() not in {"http", "https"}:
            return None
        if not scheme_match:
            normalized = f"https://{normalized}"
        parsed = urlsplit(normalized)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        normalized_hostname = RansomLookConverter._normalize_hostname(parsed.hostname)
        if normalized_hostname is None:
            return None
        hostname, is_ipv6 = normalized_hostname
        if is_ipv6:
            hostname = f"[{hostname}]"
        if (scheme, port) in {("http", 80), ("https", 443)}:
            port = None
        netloc = f"{hostname}:{port}" if port is not None else hostname
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))

    @staticmethod
    def _normalize_hostname(value: str) -> tuple[str, bool] | None:
        """Return a canonical hostname and whether it is an IPv6 address."""
        try:
            hostname = value.encode("idna").decode("ascii").lower().removesuffix(".")
        except UnicodeError:
            return None
        if not hostname or len(hostname) > 253:
            return None
        try:
            address = ip_address(hostname)
        except ValueError:
            labels = hostname.split(".")
            valid_labels = len(labels) >= 2 and all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            )
            return (hostname, False) if valid_labels else None
        return hostname, address.version == 6
