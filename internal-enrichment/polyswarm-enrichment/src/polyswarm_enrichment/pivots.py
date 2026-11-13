"""Optional pivots from an imphash or an ATT&CK technique to related files.

Both pivots are off by default because each one costs PolySwarm API lookups:

- Imphash pivot: for a file PolySwarm reports a PE imphash for, search
  PolySwarm (``search_by_ioc``) for other files with the same imphash.
- Technique pivot: for an Attack-Pattern with a MITRE ATT&CK id, search the
  PolySwarm metadata index for files whose sandbox reports list that
  technique (``cape_sandbox_v2.ttp`` or ``triage_sandbox_v0.ttp``).

Searches only: nothing is submitted, scanned or uploaded. The only values that
leave OpenCTI are the imphash or the ATT&CK id.

The pivots return plain STIX dicts. The connector decides when to call them.
"""

import json
import re
from datetime import datetime, timezone
from typing import Any

from polyswarm_enrichment.polyswarm_client import polyswarm_exceptions
from pycti import Note

IMPHASH_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# T1059 or T1059.001
MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Metadata fields that hold the techniques seen in a sandbox report
TTP_METADATA_FIELDS = ("cape_sandbox_v2.ttp", "triage_sandbox_v0.ttp")

# Hard ceiling so a typo in the setting can't turn into a large crawl
MAX_PIVOT_RESULTS = 100

# Label put on every File a pivot imports. The connector never pivots from a
# File that carries it, so auto-enrichment cannot crawl outward level by level.
PIVOT_LABEL = "polyswarm-pivot-result"


def has_pivot_label(*entities: dict | None) -> bool:
    """True when any of the entities (STIX or OpenCTI form) carries the label."""
    for entity in entities:
        for label in (entity or {}).get("x_opencti_labels") or []:
            if str(label).lower() == PIVOT_LABEL:
                return True
        for label in (entity or {}).get("objectLabel") or []:
            value = label.get("value") if isinstance(label, dict) else label
            if str(value or "").lower() == PIVOT_LABEL:
                return True
    return False


def extract_mitre_id(entity: dict | None) -> str | None:
    """Return the ATT&CK technique id of an Attack-Pattern, or None.

    Looks at ``x_mitre_id`` first, then at the external reference whose source
    is MITRE ATT&CK. Only ids shaped like T1234 or T1234.001 are returned.
    """
    if not entity:
        return None
    candidates = [entity.get("x_mitre_id")]
    for ref in entity.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        if str(ref.get("source_name", "")).lower().startswith("mitre"):
            candidates.append(ref.get("external_id"))
    for candidate in candidates:
        value = str(candidate or "").strip().upper()
        if MITRE_ID_RE.match(value):
            return value
    return None


def _sha256_of(item: Any) -> str:
    """SHA-256 of a search result (IOC string, or Metadata resource)."""
    raw = getattr(item, "json", item)
    if isinstance(raw, dict):
        raw = (raw.get("artifact") or {}).get("sha256") or raw.get("sha256")
    sha256 = (raw if isinstance(raw, str) else "").strip().lower()
    if not sha256:
        sha256 = str(getattr(item, "sha256", "") or "").strip().lower()
    return sha256 if SHA256_RE.match(sha256) else ""


class PivotService:
    """Build the STIX objects for the imphash and technique pivots."""

    def __init__(
        self,
        helper: Any,
        client: Any,
        converter: Any,
        imphash_max: int = 0,
        ttp_max: int = 0,
    ) -> None:
        self.helper = helper
        self.client = client
        self.converter = converter
        self.imphash_max = max(0, min(int(imphash_max or 0), MAX_PIVOT_RESULTS))
        self.ttp_max = max(0, min(int(ttp_max or 0), MAX_PIVOT_RESULTS))

    @property
    def imphash_enabled(self) -> bool:
        return self.imphash_max > 0

    @property
    def ttp_enabled(self) -> bool:
        return self.ttp_max > 0

    # ------------------------------------------------------------------
    # Searches
    # ------------------------------------------------------------------

    def _communities(self) -> list[tuple[Any, str]]:
        communities = [(self.client.polyswarm, self.client.polyswarm_community)]
        default = getattr(self.client, "polyswarm_default", None)
        if str(self.client.polyswarm_community).lower() == "private" and default:
            communities.append((default, "default"))
        return communities

    def _search_imphash(self, imphash: str, exclude: str, limit: int) -> list[str]:
        """SHA-256 of up to ``limit`` other files with this imphash."""
        found: list[str] = []
        for instance, community in self._communities():
            remaining = limit - len(found)
            if remaining <= 0:
                break
            # One extra so the source file itself can be dropped
            hashes, error = self.client._search_related_files(
                "imphash", imphash, instance, community, remaining + 1
            )
            if error and not error.get("is_no_results"):
                self.helper.connector_logger.warning(
                    "[PIVOT] Imphash search failed",
                    {"community": community, "error_type": error.get("error_type")},
                )
            for sha256 in hashes:
                if sha256 != exclude and sha256 not in found:
                    found.append(sha256)
        return found[:limit]

    def _search_ttp(self, mitre_id: str, limit: int) -> list[str]:
        """SHA-256 of up to ``limit`` files whose sandbox reports list the technique."""
        query = " OR ".join(f'{field}:"{mitre_id}"' for field in TTP_METADATA_FIELDS)
        found: list[str] = []
        for instance, community in self._communities():
            if len(found) >= limit:
                break
            circuit = self.client._circuit_breakers.get(community)
            if circuit and not circuit.can_execute()[0]:
                continue
            try:
                for item in instance.search_by_metadata(
                    query, include=["artifact.sha256"]
                ):
                    sha256 = _sha256_of(item)
                    if sha256 and sha256 not in found:
                        found.append(sha256)
                    if len(found) >= limit:
                        break
                if circuit:
                    circuit.record_success()
            except polyswarm_exceptions.NoResultsException:
                continue
            except (
                polyswarm_exceptions.RequestException,
                ConnectionError,
                TimeoutError,
                OSError,
            ) as err:
                if circuit:
                    circuit.record_failure()
                self.helper.connector_logger.warning(
                    "[PIVOT] Technique search failed",
                    {"community": community, "error_type": type(err).__name__},
                )
        return found[:limit]

    # ------------------------------------------------------------------
    # STIX
    # ------------------------------------------------------------------

    def _note(
        self, stable_key: str, abstract: str, content: str, refs: list[str]
    ) -> dict:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return {
            "type": "note",
            "spec_version": "2.1",
            "id": Note.generate_id(created=None, content=stable_key),
            "created": now,
            "modified": now,
            "content": content,
            "abstract": abstract,
            "created_by_ref": self.converter.author.id,
            "object_refs": refs,
        }

    def _build(
        self,
        anchor_id: str,
        anchor_is_source: bool,
        hashes: list[str],
        description: str,
        note: dict | None,
        marking_refs: list | None,
    ) -> list[dict]:
        """Related files, one related-to relationship each, and the note."""
        objects: list[Any] = []
        file_ids: list[str] = []
        for sha256 in hashes:
            related_file = self.converter.create_related_file(sha256)
            file_ids.append(related_file["id"])
            objects.append(related_file)
            source, target = (
                (anchor_id, related_file["id"])
                if anchor_is_source
                else (related_file["id"], anchor_id)
            )
            relationship = self.converter.create_relationship(
                source_id=source,
                relationship_type="related-to",
                target_id=target,
                description=description,
            )
            if relationship:
                objects.append(relationship)
        if note:
            note["object_refs"] = [anchor_id, *file_ids]
            objects.append(note)

        # stix2 objects become plain dicts so the markings can be added
        result = []
        for obj in objects:
            data = json.loads(obj.serialize()) if hasattr(obj, "serialize") else obj
            if data.get("type") == "file":
                data = {**data, "x_opencti_labels": [PIVOT_LABEL]}
            if marking_refs:
                data = {**data, "object_marking_refs": list(marking_refs)}
            result.append(data)
        return result

    def imphash_objects(
        self,
        observable_id: str,
        sha256: str,
        imphash: str | None,
        marking_refs: list | None = None,
    ) -> list[dict]:
        """Files sharing ``imphash`` with the enriched file, related-to it."""
        imphash = (imphash or "").strip().lower()
        if not self.imphash_enabled or not IMPHASH_RE.match(imphash):
            return []
        sha256 = (sha256 or "").lower()
        hashes = self._search_imphash(imphash, sha256, self.imphash_max)
        if not hashes:
            self.helper.connector_logger.info(
                "[PIVOT] No other file with this imphash", {"imphash": imphash}
            )
            return []
        listing = "\n".join(f"- `{h}`" for h in hashes)
        content = (
            "**PolySwarm Imphash Pivot**\n\n"
            f"**Shared imphash:** `{imphash}`\n\n"
            f"PolySwarm reports {len(hashes)} other file(s) with the same import "
            f"hash (limit {self.imphash_max}). Files that share an imphash often "
            "come from the same build tooling or family, but a shared imphash "
            "alone does not prove they are related.\n\n"
            f"{listing}\n"
        )
        note = self._note(
            f"polyswarm-imphash-pivot:{observable_id}:{imphash}",
            f"PolySwarm - Files sharing imphash {imphash}",
            content,
            [observable_id],
        )
        self.helper.connector_logger.info(
            "[PIVOT] Imphash pivot done", {"files": len(hashes)}
        )
        return self._build(
            observable_id,
            True,
            hashes,
            f"PolySwarm reports the same imphash ({imphash})",
            note,
            marking_refs,
        )

    def ttp_objects(
        self,
        attack_pattern_id: str,
        mitre_id: str | None,
        marking_refs: list | None = None,
    ) -> list[dict]:
        """Files PolySwarm sandbox reports associate with the technique.

        The relationship runs from the file to the Attack-Pattern with the
        generic ``related-to`` type, the only one OpenCTI documents between an
        observable and an Attack-Pattern.
        """
        mitre_id = (mitre_id or "").strip().upper()
        if not self.ttp_enabled or not MITRE_ID_RE.match(mitre_id):
            return []
        hashes = self._search_ttp(mitre_id, self.ttp_max)
        if not hashes:
            self.helper.connector_logger.info(
                "[PIVOT] No file found for technique", {"technique": mitre_id}
            )
            return []
        listing = "\n".join(f"- `{h}`" for h in hashes)
        content = (
            "**PolySwarm Technique Pivot**\n\n"
            f"**Technique:** {mitre_id}\n\n"
            f"PolySwarm sandbox reports list this technique for {len(hashes)} "
            f"file(s) (limit {self.ttp_max}). The techniques in a sandbox report "
            "are what the analysis observed for that run, and the files below "
            "are a sample of the matches, not a ranking.\n\n"
            f"{listing}\n"
        )
        note = self._note(
            f"polyswarm-ttp-pivot:{attack_pattern_id}:{mitre_id}",
            f"PolySwarm - Files with technique {mitre_id}",
            content,
            [attack_pattern_id],
        )
        self.helper.connector_logger.info(
            "[PIVOT] Technique pivot done",
            {"technique": mitre_id, "files": len(hashes)},
        )
        return self._build(
            attack_pattern_id,
            False,
            hashes,
            f"PolySwarm sandbox reports list technique {mitre_id} for this file",
            note,
            marking_refs,
        )
