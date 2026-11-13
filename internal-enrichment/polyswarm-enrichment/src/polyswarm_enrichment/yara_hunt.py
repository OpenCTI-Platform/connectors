"""YARA hunting driven from OpenCTI Indicators.

Starts a PolySwarm historical hunt for the YARA rule held by an Indicator,
waits for it (bounded), and turns the matched files into File observables.

This module writes to the customer's PolySwarm account (a hunt is created and
stays there) and spends hunt quota. The connector only calls it when
``POLYSWARM_YARA_HUNT_ENABLED`` is true.

SDK shapes (polyswarm-api resources.py):
- ``HistoricalHunt``: id, created, status, progress, summary, ruleset_name,
  window_days (REST field, echoed back), yara.
- ``HistoricalHuntResult``: id, sha256, md5, sha1, rule_name, malware_family,
  polyscore, matched_strings (single-result endpoint).

Hunt statuses measured read-only on 2026-11-10: PENDING, COMPLETED, LIMITED
(LIMITED = the hunt hit its result cap and finished). Failure and cancel
statuses are not documented, so unknown statuses are treated as still running
until the timeout.
"""

import hashlib
import importlib
import json
import re
import time
from datetime import datetime, timezone
from itertools import islice

import stix2
from polyswarm_enrichment.pivots import PIVOT_LABEL
from polyswarm_enrichment.polyswarm_client import polyswarm_exceptions
from pycti import Note

try:  # optional: only used when already present in the image, so not a requirement
    _yara = importlib.import_module("yara")
except Exception:  # pragma: no cover - depends on the image
    _yara = None

# polyswarm_api.resources is imported lazily so tests can run without it
VALID_WINDOW_DAYS = (30, 60, 90, 180)

SUCCESS_STATUSES = {"COMPLETED", "LIMITED"}
FAILURE_STATUSES = {
    "FAILED",
    "FAILURE",
    "ERROR",
    "CANCELLED",
    "CANCELED",
    "STOPPED",
    "DELETED",
    "EXPIRED",
}

POLL_INTERVAL_SECONDS = 20
# Matched strings are fetched one result at a time, so only a few results
STRING_RESULTS = 3
STRINGS_PER_RESULT = 5
STRING_DATA_MAX = 60
STATE_KEY = "yara_hunts"
# historical_list(since=...) takes seconds (measured: 120 days back returned
# only the hunts of the last 120 days); an empty list raises NoResultsException.
# A finished hunt stays reusable for its whole window plus part of a day (see
# _is_stale), so look back the longest valid window plus one day.
ACCOUNT_LOOKBACK_SECONDS = (max(VALID_WINDOW_DAYS) + 1) * 86400

_RULE_NAME_RE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_]\w*)", re.M)


def is_yara_indicator(stix_entity: dict) -> bool:
    """True for an Indicator whose pattern type is yara."""
    return str(
        stix_entity.get("pattern_type") or ""
    ).strip().lower() == "yara" and bool((stix_entity.get("pattern") or "").strip())


def rule_names(rule: str) -> list[str]:
    """Names of the rules declared in a YARA source text."""
    return _RULE_NAME_RE.findall(rule)


def rule_digest(rule: str) -> str:
    """Stable digest of the rule text (whitespace at the ends ignored)."""
    return hashlib.sha256(rule.strip().encode("utf-8")).hexdigest()


def validate_rule(rule: str) -> str | None:
    """Compile the rule locally when a YARA library is available.

    Returns an error message, or None when the rule compiles or no library is
    installed (PolySwarm validates the rule when the hunt is created).
    """
    if _yara is None:
        return None
    try:
        _yara.compile(source=rule)
    except Exception as err:  # yara.SyntaxError / yara.Error
        return str(err)
    return None


def _ascii(text: object, limit: int) -> str:
    """Printable ASCII only, so notes never carry binary or odd characters."""
    cleaned = "".join(
        ch if 32 <= ord(ch) < 127 else "."
        for ch in str(text if text is not None else "")
    )
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def short_error(err: Exception) -> str:
    """Exception type plus a short ASCII message, safe to show in a note."""
    message = _ascii(" ".join(str(err).split()), 120)
    return f"{type(err).__name__}: {message}" if message else type(err).__name__


def format_matched_strings(matched: list | None) -> list[str]:
    """One short line per matched string: identifier, offset, data."""
    lines = []
    for item in (matched or [])[:STRINGS_PER_RESULT]:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"{_ascii(item.get('identifier'), 40)} at offset "
            f"{_ascii(item.get('offset'), 20)}: "
            f"{_ascii(item.get('data'), STRING_DATA_MAX)}"
        )
    return lines


class HuntOutcome:
    """What happened to one hunt, for the note and the bundle."""

    def __init__(self):
        self.hunt_id: str | None = None
        self.status: str = ""
        self.window_days: int | None = None
        self.reused: bool = False
        self.replaced_hunt_id: str | None = None
        self.replaced_window_days: int | None = None
        self.timed_out: bool = False
        self.failed: bool = False
        self.error: str | None = None
        self.total_matches: int | None = None
        self.results: list = []
        self.strings: dict[str, list[str]] = {}


class YaraHunter:
    """Creates, follows and reads PolySwarm historical hunts."""

    def __init__(
        self,
        api,
        helper,
        window_days: int,
        timeout: int,
        max_results: int,
        sleep=time.sleep,
        clock=time.monotonic,
    ):
        self.api = api
        self.helper = helper
        self.window_days = window_days
        self.timeout = timeout
        self.max_results = max_results
        self._sleep = sleep
        self._clock = clock

    # ------------------------------------------------------------------ state
    def _load_state(self) -> dict:
        try:
            state = self.helper.get_state() or {}
        except Exception:
            state = {}
        return state.get(STATE_KEY) or {}

    def _save_state(self, hunts: dict) -> None:
        try:
            state = self.helper.get_state() or {}
            state[STATE_KEY] = hunts
            self.helper.set_state(state)
        except Exception as err:
            self.helper.connector_logger.warning(
                f"[YARA] Could not save hunt state: {err}"
            )

    def _remember(self, digest: str, hunt_id: str) -> None:
        hunts = self._load_state()
        hunts[digest] = {
            "hunt_id": str(hunt_id),
            "started": datetime.now(timezone.utc).isoformat(),
        }
        # Keep the state small: the newest 50 rules
        if len(hunts) > 50:
            for key in sorted(hunts, key=lambda k: hunts[k].get("started", ""))[:-50]:
                hunts.pop(key, None)
        self._save_state(hunts)

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def hunt_name(rule: str) -> str:
        """Ruleset name for the hunt: readable, and unique per rule text."""
        names = rule_names(rule)
        label = names[0] if names else "rule"
        return f"OpenCTI {label[:40]} {rule_digest(rule)[:12]}"

    @staticmethod
    def is_finished(status: str) -> bool:
        return status in SUCCESS_STATUSES or status in FAILURE_STATUSES

    def _get_hunt(self, hunt_id):
        return self.api.historical_get(str(hunt_id))

    def _is_stale(self, hunt, outcome: HuntOutcome) -> bool:
        """A finished hunt older than its own window no longer covers today."""
        if str(hunt.status).upper() not in SUCCESS_STATUSES:
            return False
        meta = getattr(hunt, "json", None)
        meta = meta if isinstance(meta, dict) else {}
        days = meta.get("window_days") or self.window_days
        created = getattr(hunt, "created", None) or meta.get("created")
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created.replace("Z", "+00:00"))
            except ValueError:
                return False
        if not isinstance(created, datetime):
            return False
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - created).days > int(days):
            outcome.replaced_hunt_id = str(hunt.id)
            outcome.replaced_window_days = int(days)
            return True
        return False

    def _find_existing_hunt(self, rule: str, outcome: HuntOutcome):
        """A hunt already made for this rule: running, or finished and usable.

        Looked up in the saved state first, then in the account's hunts. A hunt
        that failed or was cancelled is not reused.
        """
        digest = rule_digest(rule)
        remembered = self._load_state().get(digest)
        if remembered:
            try:
                hunt = self._get_hunt(remembered["hunt_id"])
                if str(
                    hunt.status
                ).upper() not in FAILURE_STATUSES and not self._is_stale(hunt, outcome):
                    return hunt
            except Exception as err:
                self.helper.connector_logger.warning(
                    f"[YARA] Could not look up remembered hunt: {short_error(err)}"
                )
        name = self.hunt_name(rule)
        try:
            for hunt in self.api.historical_list(since=ACCOUNT_LOOKBACK_SECONDS):
                if getattr(hunt, "ruleset_name", None) == name and (
                    str(hunt.status).upper() not in FAILURE_STATUSES
                    and not self._is_stale(hunt, outcome)
                ):
                    return hunt
        except polyswarm_exceptions.NoResultsException:
            pass
        except Exception as err:
            self.helper.connector_logger.warning(
                f"[YARA] Could not list existing hunts: {short_error(err)}"
            )
        return None

    def _create_hunt(self, rule: str):
        """Start the hunt. This is the call that writes to the account."""
        from polyswarm_api import resources

        return resources.HistoricalHunt.create(
            self.api,
            yara=rule,
            ruleset_name=self.hunt_name(rule),
            window_days=self.window_days,
            community=self.api.community,
        ).result()

    # --------------------------------------------------------------------- run
    def run(self, rule: str) -> HuntOutcome:
        """Validate, start (or resume) the hunt, wait, and read the results."""
        outcome = HuntOutcome()
        outcome.window_days = self.window_days

        error = validate_rule(rule)
        if error:
            outcome.failed = True
            outcome.error = f"The YARA rule does not compile ({_ascii(error, 160)})"
            return outcome

        hunt = self._find_existing_hunt(rule, outcome)
        if hunt is not None:
            # A stale hunt skipped on the way here no longer matters
            outcome.replaced_hunt_id = None
            outcome.replaced_window_days = None
            outcome.reused = True
            self.helper.connector_logger.info(
                "[YARA] A hunt for this rule already exists, reusing it",
                {"hunt_id": str(hunt.id)},
            )
        else:
            try:
                hunt = self._create_hunt(rule)
            except polyswarm_exceptions.InvalidYaraRulesException as err:
                outcome.failed = True
                outcome.error = f"PolySwarm rejected the YARA rule ({short_error(err)})"
                return outcome
            except Exception as err:
                outcome.failed = True
                outcome.error = f"Could not start the hunt ({short_error(err)})"
                return outcome
            self._remember(rule_digest(rule), hunt.id)

        outcome.hunt_id = str(hunt.id)
        window = getattr(hunt, "json", {}) or {}
        if isinstance(window, dict) and window.get("window_days"):
            outcome.window_days = window["window_days"]

        hunt = self._wait(hunt, outcome)
        if outcome.failed or outcome.timed_out:
            return outcome

        summary = getattr(hunt, "summary", None) or {}
        if isinstance(summary, dict):
            outcome.total_matches = summary.get("count")
        self._read_results(outcome)
        return outcome

    def _wait(self, hunt, outcome: HuntOutcome):
        deadline = self._clock() + self.timeout
        while True:
            outcome.status = str(hunt.status).upper()
            if outcome.status in SUCCESS_STATUSES:
                return hunt
            if outcome.status in FAILURE_STATUSES:
                outcome.failed = True
                outcome.error = f"The hunt ended with status {outcome.status}"
                return hunt
            if self._clock() >= deadline:
                outcome.timed_out = True
                return hunt
            self._sleep(POLL_INTERVAL_SECONDS)
            try:
                hunt = self._get_hunt(hunt.id)
            except Exception as err:
                self.helper.connector_logger.warning(
                    f"[YARA] Hunt status check failed, retrying: {short_error(err)}"
                )

    def _read_results(self, outcome: HuntOutcome) -> None:
        seen = set()
        try:
            for result in self.api.historical_results(hunt=outcome.hunt_id):
                sha256 = str(getattr(result, "sha256", "") or "").lower()
                if len(sha256) != 64 or sha256 in seen:
                    continue
                seen.add(sha256)
                outcome.results.append(result)
                if len(outcome.results) >= self.max_results:
                    break
        except polyswarm_exceptions.NoResultsException:
            pass
        except Exception as err:
            outcome.error = f"Could not read the hunt results ({short_error(err)})"

        for result in list(islice(outcome.results, STRING_RESULTS)):
            lines = format_matched_strings(self._matched_strings(result))
            if lines:
                outcome.strings[str(result.sha256).lower()] = lines

    def _matched_strings(self, result) -> list | None:
        listed = getattr(result, "matched_strings", None)
        if listed is None and isinstance(getattr(result, "json", None), dict):
            listed = result.json.get("matched_strings")
        if listed:
            return listed
        try:
            single = self.api.historical_result(result.id)
        except Exception:
            return None
        found = getattr(single, "matched_strings", None)
        if found is None and isinstance(getattr(single, "json", None), dict):
            found = single.json.get("matched_strings")
        return found


# ---------------------------------------------------------------- STIX output
def build_note(
    indicator: dict, rule: str, outcome: HuntOutcome, author_id: str
) -> dict:
    """The single note on the Indicator that reports the hunt."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    names = rule_names(rule)
    rule_label = ", ".join(names[:5]) if names else "unknown"
    window = (
        f"{outcome.window_days} days" if outcome.window_days else "platform maximum"
    )

    lines = ["**PolySwarm YARA historical hunt**", ""]
    if outcome.hunt_id:
        lines.append(f"- Hunt id: {outcome.hunt_id}")
    lines.append(f"- Rule: {rule_label}")
    lines.append(f"- Window: {window}")
    if outcome.reused:
        lines.append(
            "- An earlier hunt for this rule was reused, no new hunt was started"
        )

    if outcome.replaced_hunt_id:
        lines.append(
            f"- The earlier hunt for this rule ({outcome.replaced_hunt_id}) is "
            f"older than its {outcome.replaced_window_days} day window, so a new "
            "hunt was started"
        )

    if outcome.failed:
        abstract = "PolySwarm YARA hunt failed"
        lines.append(f"- Result: {outcome.error}")
    elif outcome.timed_out:
        abstract = "PolySwarm YARA hunt still running"
        lines.append(f"- Status: {outcome.status or 'running'}")
        lines.append(
            "- Result: the hunt was still running when the connector stopped "
            "waiting. It keeps running in the PolySwarm account. Enrich this "
            "Indicator again later to import the matches."
        )
    else:
        abstract = f"PolySwarm YARA hunt: {len(outcome.results)} file(s) imported"
        lines.append(f"- Status: {outcome.status}")
        total = (
            outcome.total_matches
            if outcome.total_matches is not None
            else len(outcome.results)
        )
        lines.append(f"- Matches reported by PolySwarm: {total}")
        lines.append(f"- Files imported: {len(outcome.results)}")
        if outcome.status == "LIMITED":
            lines.append(
                "- PolySwarm stopped the hunt at its result limit, so the "
                "match count is a lower bound"
            )
        if outcome.error:
            lines.append(f"- Warning: {outcome.error}")
        for sha256, strings in outcome.strings.items():
            lines.append("")
            lines.append(f"Matched strings for {sha256}:")
            lines.extend(f"- {s}" for s in strings)

    stable = f"polyswarm-yara-hunt:{indicator['id']}:{outcome.hunt_id or 'none'}"
    if not outcome.hunt_id:
        stable += f":{rule_digest(rule)[:12]}"
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": Note.generate_id(created=None, content=stable),
        "created": now,
        "modified": now,
        "abstract": abstract,
        "content": "\n".join(lines) + "\n",
        "created_by_ref": author_id,
        "object_refs": [indicator["id"]],
    }


def _file_observable(converter, result) -> dict:
    """File observable built with all its hashes, so the id covers them all."""
    hashes = {"SHA-256": str(result.sha256).lower()}
    for algo, attr, length in (("MD5", "md5", 32), ("SHA-1", "sha1", 40)):
        value = str(getattr(result, attr, "") or "").lower()
        if len(value) == length and all(c in "0123456789abcdef" for c in value):
            hashes[algo] = value
    file_obj = json.loads(stix2.File(hashes=hashes, allow_custom=True).serialize())
    file_obj["x_opencti_created_by_ref"] = converter.author.id
    # Same label the pivots use, so these files are never rescanned, downloaded
    # or pivoted again when auto-enrichment picks them up.
    file_obj["x_opencti_labels"] = [PIVOT_LABEL]
    return file_obj


def build_file_objects(converter, indicator: dict, outcome: HuntOutcome) -> list:
    """File observables with hashes, each related-to the Indicator."""
    objects = []
    for result in outcome.results:
        file_obj = _file_observable(converter, result)
        objects.append(file_obj)
        relationship = converter.create_relationship(
            source_id=indicator["id"],
            relationship_type="related-to",
            target_id=file_obj["id"],
            description=(
                "This file matched the YARA rule in a PolySwarm historical hunt "
                f"(hunt {outcome.hunt_id})"
            ),
        )
        if relationship:
            objects.append(relationship)
    return objects


def with_markings(objects: list, marking_refs: list | None) -> list:
    """Derived objects keep the Indicator's markings."""
    if not marking_refs:
        return objects
    return [
        {
            **(json.loads(obj.serialize()) if hasattr(obj, "serialize") else obj),
            "object_marking_refs": list(marking_refs),
        }
        for obj in objects
    ]
