"""PolySwarm live hunting source.

Pulls the account's live hunting hits (files that matched one of the
account's live YARA rules) and maps them to STIX 2.1:

- a File observable carrying the MD5, SHA-1 and SHA-256,
- an Indicator on the SHA-256, ``based-on`` the observable,
- a Note per (rule, file) with the hit details,
- a Malware object and an ``indicates`` relationship when the hit carries a
  name that looks like a real malware family (see ``family_names``). Many hits
  carry an engine label instead (for example ``Trojan.Packed2``). The name as
  reported always stays in the note and in a ``polyswarm-family:<name>``
  label, whether or not a Malware object is created.

Hits are deduplicated by hit id across runs with a bounded list in state.
This source only reads from PolySwarm; nothing is sent to PolySwarm.
"""

import json
import math
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any

import stix2
from connector.family_names import is_malware_family_name
from polyswarm_client.hunting_client import PolySwarmHuntingClient
from pycti import Indicator, Malware, Note, StixCoreRelationship

# Re-query this much before the previous run, so hits that were recorded
# late are not missed. Duplicates are dropped by hit id.
LAG_MARGIN_SECONDS = 10 * 60
# Upper bound on the window asked for in one run (the API accepted far larger
# values when measured; this keeps a run after a long outage bounded).
MAX_SINCE_SECONDS = 30 * 24 * 60 * 60
# How many recent hit ids are remembered for deduplication.
SEEN_IDS_LIMIT = 5000

MAX_RULE_NAME_LENGTH = 128
MAX_FAMILY_NAME_LENGTH = 128
MAX_MATCHED_STRINGS = 20
MAX_MATCHED_STRING_LENGTH = 200
MAX_NOTE_FIELD_LENGTH = 300

STATE_LAST_RUN = "last_run"
STATE_SEEN_IDS = "seen_hit_ids"

_HEX_LENGTHS = {"MD5": 32, "SHA-1": 40, "SHA-256": 64}
_HIT_HASH_FIELDS = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256"}
_UNSAFE_LABEL_CHARS = re.compile(r"[^A-Za-z0-9_.\-]")


def _clean_text(value: Any, max_length: int) -> str:
    """Return ``value`` as single line printable text, truncated."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, default=str)
    cleaned = "".join(
        " " if unicodedata.category(ch)[0] in ("C", "Z") and ch != " " else ch
        for ch in value
    )
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 3] + "..."
    return cleaned


def _clean_hash(value: Any, algorithm: str) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    if len(value) != _HEX_LENGTHS[algorithm]:
        return None
    if not all(ch in "0123456789abcdef" for ch in value):
        return None
    return value


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return int(value)
    return None


def _detections(hit: dict) -> tuple[int, int, int] | None:
    """Return (malicious, benign, total) when the hit carries usable counts."""
    detections = hit.get("detections")
    if not isinstance(detections, dict):
        return None
    malicious = _as_int(detections.get("malicious"))
    benign = _as_int(detections.get("benign"))
    total = _as_int(detections.get("total"))
    if malicious is None or total is None or total <= 0 or malicious < 0:
        return None
    malicious = min(malicious, total)
    return malicious, (benign if benign is not None and benign >= 0 else 0), total


def field_text(hit: dict, name: str) -> str:
    text = _clean_text(hit.get(name), MAX_NOTE_FIELD_LENGTH)
    return text or "not provided"


def _rule_label(rule_name: str) -> str:
    return "polyswarm-hunt:" + _UNSAFE_LABEL_CHARS.sub("_", rule_name)


def _family_label(family: str) -> str:
    return "polyswarm-family:" + _UNSAFE_LABEL_CHARS.sub("_", family)


def _format_matched_strings(hit: dict) -> str:
    """Describe the matched strings, truncated. The list endpoint returned
    null for this field in every hit measured, so the shape is not known;
    strings, lists of strings and lists of objects are all accepted."""
    matched = hit.get("matched_strings")
    if matched in (None, "", [], {}):
        return "not provided by the API for this hit"
    if isinstance(matched, dict):
        items = [f"{key}: {val}" for key, val in sorted(matched.items(), key=str)]
    elif isinstance(matched, (list, tuple)):
        items = list(matched)
    else:
        items = [matched]
    shown = [
        "`" + _clean_text(item, MAX_MATCHED_STRING_LENGTH).replace("`", "'") + "`"
        for item in items[:MAX_MATCHED_STRINGS]
    ]
    text = ", ".join(shown)
    hidden = len(items) - len(shown)
    if hidden > 0:
        text += f" (and {hidden} more not shown)"
    dropped = hit.get("matched_strings_dropped")
    if dropped not in (None, False, 0, ""):
        text += (
            f" (the API reports matched strings dropped: {_clean_text(dropped, 50)})"
        )
    return text


class HuntingSource:
    """Collect PolySwarm live hunting hits as STIX 2.1 objects."""

    def __init__(self, config, author, tlp_marking, logger, client=None):
        self.config = config
        self.author = author
        self.tlp_marking = tlp_marking
        self.logger = logger
        if client is None:
            client = PolySwarmHuntingClient(
                api_url=str(config.api_url),
                api_key=config.api_key.get_secret_value(),
            )
        self.client = client

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Window and state
    # ------------------------------------------------------------------

    def _since_seconds(self, last_run: datetime | None, now: datetime) -> int:
        if last_run is None:
            since = int(self.config.hunting_backfill_hours) * 3600
        else:
            elapsed = max(0.0, (now - last_run).total_seconds())
            since = math.ceil(elapsed) + LAG_MARGIN_SECONDS
        if since > MAX_SINCE_SECONDS:
            self.logger.warning(
                "Live hunting window capped; older hits are not imported.",
                meta={"requested_seconds": since, "cap_seconds": MAX_SINCE_SECONDS},
            )
            since = MAX_SINCE_SECONDS
        # since=0 means "no time filter" to the API, so never go below 1.
        return max(1, since)

    @staticmethod
    def _hit_key(hit: dict) -> str | None:
        hit_id = hit.get("id")
        if isinstance(hit_id, (str, int)) and not isinstance(hit_id, bool):
            hit_id = str(hit_id).strip()
            if hit_id:
                return hit_id
        return None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def collect(self, state: dict) -> tuple[list[dict], dict]:
        """Return (STIX 2.1 objects as plain dicts, the updated hunting sub-state)."""
        state = state if isinstance(state, dict) else {}
        now = self._now()
        last_run = _parse_time(state.get(STATE_LAST_RUN))
        previous_ids = [
            str(i) for i in (state.get(STATE_SEEN_IDS) or []) if i is not None
        ]
        seen = set(previous_ids)

        since = self._since_seconds(last_run, now)
        self.logger.info(
            "Fetching PolySwarm live hunting hits.",
            meta={"since_seconds": since, "first_run": last_run is None},
        )
        hits = self.client.list_live_hits(since)

        new_hits: list[dict] = []
        new_ids: list[str] = []
        skipped_seen = 0
        skipped_invalid = 0
        for hit in hits:
            if not isinstance(hit, dict):
                skipped_invalid += 1
                continue
            key = self._hit_key(hit)
            if key is not None and key in seen:
                skipped_seen += 1
                continue
            # A hit that is unusable now may be complete in a later copy, so
            # it is counted as skipped but not remembered as seen.
            if _clean_hash(hit.get("sha256"), "SHA-256") is None:
                skipped_invalid += 1
                continue
            if not _clean_text(hit.get("rule_name"), MAX_RULE_NAME_LENGTH):
                skipped_invalid += 1
                continue
            if key is not None:
                seen.add(key)
                new_ids.append(key)
            new_hits.append(hit)

        objects = self._map_hits(new_hits, now)
        self.logger.info(
            "PolySwarm live hunting hits processed.",
            meta={
                "hits_returned": len(hits),
                "hits_new": len(new_hits),
                "hits_already_seen": skipped_seen,
                "hits_skipped_invalid": skipped_invalid,
                "objects": len(objects),
            },
        )

        # Newest ids first, so truncation drops the oldest ones.
        new_id_set = set(new_ids)
        merged_ids = new_ids + [i for i in previous_ids if i not in new_id_set]
        new_state = {
            STATE_LAST_RUN: now.isoformat(),
            STATE_SEEN_IDS: merged_ids[:SEEN_IDS_LIMIT],
        }
        return objects, new_state

    # ------------------------------------------------------------------
    # Mapping
    # ------------------------------------------------------------------

    def _common(self) -> dict:
        return {
            "created_by_ref": self.author["id"],
            "object_marking_refs": [self.tlp_marking["id"]],
        }

    def _map_hits(self, hits: list[dict], now: datetime) -> list[dict]:
        """Map hits (newest first) to STIX objects, one object per id.

        The same file often matches the same rule many times; those hits are
        folded into one note per (rule, file), described from the newest hit.
        The Malware object comes from the newest hit of the group whose family
        passes the real-family check, and the note lists every reported family.
        """
        groups: dict[tuple[str, str], list[dict]] = {}
        for hit in hits:
            sha256 = _clean_hash(hit.get("sha256"), "SHA-256")
            rule = _clean_text(hit.get("rule_name"), MAX_RULE_NAME_LENGTH)
            groups.setdefault((sha256, rule), []).append(hit)

        rules_by_file: dict[str, list[str]] = {}
        families_by_file: dict[str, set[str]] = {}
        newest_by_file: dict[str, dict] = {}
        for (sha256, rule), group in groups.items():
            rules_by_file.setdefault(sha256, []).append(rule)
            newest_by_file.setdefault(sha256, group[0])
            for hit in group:
                family = _clean_text(hit.get("malware_family"), MAX_FAMILY_NAME_LENGTH)
                if family:
                    families_by_file.setdefault(sha256, set()).add(family)

        objects: dict[str, dict] = {}

        def add(obj) -> str:
            objects[obj["id"]] = json.loads(obj.serialize())
            return obj["id"]

        file_refs: dict[str, tuple[str, str]] = {}
        for sha256, rules in rules_by_file.items():
            newest = newest_by_file[sha256]
            labels = sorted(
                {_rule_label(rule) for rule in rules}
                | {_family_label(f) for f in families_by_file.get(sha256, ())}
            )
            observable_id = add(self._file_observable(newest, labels))
            indicator = self._indicator(newest, sha256, rules, labels, now)
            indicator_id = add(indicator)
            add(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "based-on", indicator_id, observable_id
                    ),
                    relationship_type="based-on",
                    source_ref=indicator_id,
                    target_ref=observable_id,
                    **self._common(),
                )
            )
            file_refs[sha256] = (observable_id, indicator_id)

        for (sha256, rule), group in groups.items():
            observable_id, indicator_id = file_refs[sha256]
            newest = group[0]
            refs = [observable_id, indicator_id]
            families: list[str] = []
            for hit in group:
                name = _clean_text(hit.get("malware_family"), MAX_FAMILY_NAME_LENGTH)
                if name and name not in families:
                    families.append(name)
            family = next((f for f in families if is_malware_family_name(f)), "")
            if family:
                malware = stix2.Malware(
                    id=Malware.generate_id(family),
                    name=family,
                    is_family=True,
                    **self._common(),
                )
                malware_id = add(malware)
                relationship_id = add(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "indicates", indicator_id, malware_id
                        ),
                        relationship_type="indicates",
                        source_ref=indicator_id,
                        target_ref=malware_id,
                        description=(
                            "The file matched a PolySwarm live hunting rule and "
                            "the hit was reported with this malware family name."
                        ),
                        **self._common(),
                    )
                )
                refs += [malware_id, relationship_id]
            add(
                self._note(
                    newest,
                    len(group),
                    sha256,
                    rule,
                    refs,
                    families,
                    has_malware=bool(family),
                )
            )

        return list(objects.values())

    def _file_observable(self, hit: dict, labels: list[str]) -> stix2.File:
        hashes = {}
        for algorithm, field in _HIT_HASH_FIELDS.items():
            value = _clean_hash(hit.get(field), algorithm)
            if value:
                hashes[algorithm] = value
        return stix2.File(
            hashes=hashes,
            object_marking_refs=[self.tlp_marking["id"]],
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_labels": labels,
            },
        )

    def _indicator(
        self,
        hit: dict,
        sha256: str,
        rules: list[str],
        labels: list[str],
        now: datetime,
    ) -> stix2.Indicator:
        pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
        valid_from = _parse_time(hit.get("created")) or now
        if valid_from > now:
            valid_from = now
        valid_days = max(1, int(self.config.hunting_indicator_valid_days))
        valid_until = now + timedelta(days=valid_days)
        if valid_until <= valid_from:
            valid_until = valid_from + timedelta(days=valid_days)

        description = (
            "File matched PolySwarm live hunting rule(s): "
            + ", ".join(sorted(rules))
            + "."
        )
        custom = {
            "x_opencti_main_observable_type": "StixFile",
        }
        detections = _detections(hit)
        if detections is not None:
            malicious, _, total = detections
            custom["x_opencti_score"] = round(100 * malicious / total)
            description += (
                f" Score is the share of PolySwarm engines that reported the file "
                f"as malicious when the hit was recorded ({malicious} of {total})."
            )
        return stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=sha256,
            description=description,
            pattern=pattern,
            pattern_type="stix",
            valid_from=valid_from,
            valid_until=valid_until,
            labels=labels,
            **self._common(),
            custom_properties=custom,
        )

    def _note(
        self,
        hit: dict,
        hit_count: int,
        sha256: str,
        rule: str,
        refs: list[str],
        families: list[str] | None = None,
        has_malware: bool = False,
    ) -> stix2.Note:
        families = families or []
        detections = _detections(hit)
        if detections is not None:
            malicious, benign, total = detections
            detection_text = f"{malicious} malicious, {benign} benign, {total} total"
        else:
            detection_text = "not provided by the API for this hit"

        family_note = ""
        if families and not has_malware:
            family_note = (
                " (looks like a detection label, so no malware object was created)"
            )
        family_text = (
            ", ".join(families) if families else field_text(hit, "malware_family")
        )

        def field(name: str) -> str:
            return field_text(hit, name)

        lines = [
            f"PolySwarm live hunting rule `{rule}` matched file `{sha256}`.",
            "",
            f"- Rule name: {rule}",
            f"- Malware family as reported: {family_text}{family_note}",
            f"- Engine detections at hit time: {detection_text}",
            f"- PolyScore as reported: {field('polyscore')}",
            f"- First seen on PolySwarm: {field('first_seen')}",
            f"- Hit recorded: {field('created')}",
            f"- Hits for this rule and file in this import: {hit_count}",
            f"- Community: {field('community')}",
            f"- Matched strings: {_format_matched_strings(hit)}",
        ]
        content = "\n".join(lines)
        # One note per (rule, file): the id comes from a stable key, so later
        # hits for the same rule and file update this note.
        stable_key = f"polyswarm-live-hunt|{rule}|{sha256}"
        return stix2.Note(
            id=Note.generate_id(created=None, content=stable_key),
            abstract=f"PolySwarm live hunting hit: {rule}",
            content=content,
            object_refs=refs,
            labels=[_rule_label(rule)] + [_family_label(f) for f in families],
            **self._common(),
        )
