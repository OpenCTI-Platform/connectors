import calendar
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

EPOCH_ZERO = "1970-01-01T00:00:00.000Z"
FAR_FUTURE = "5138-11-16T09:46:40.000Z"

# Custom-attribute GraphQL projections kept lean so the API queries
# only fetch the fields the connector actually reads. The platform
# returns one node per match; widening the projection would just add
# wire-payload and serialisation cost for fields we never look at.
_TA_ATTRIBUTES = """
    id
    standard_id
    name
    last_seen
"""

_USES_REL_ATTRIBUTES = """
    id
    to {
        ... on BasicObject {
            id
            standard_id
            entity_type
        }
    }
"""

_INDICATOR_LATEST_ATTRIBUTES = """
    id
    valid_from
    created_at
"""

_REPORT_LATEST_ATTRIBUTES = """
    id
    published
"""


class ThreatActorEnrichment:
    """Enrich ``threat-actor-group`` entities with a forward-only ``last_seen``.

    The connector walks every ``Threat-Actor-Group`` in the platform,
    aggregates the most recent activity date from the indicators and
    reports linked to the malware the actor ``uses``, and writes the
    result back as ``last_seen`` via the OpenCTI GraphQL API. All
    reads and writes go through ``helper.api`` (pycti) — no direct
    Elasticsearch access — so the connector inherits the platform's
    access-control model, GraphQL filter semantics, query schedulers
    and TLS / proxy settings.
    """

    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        if os.path.isfile(config_file_path):
            with open(config_file_path) as config_file:
                # ``yaml.load`` returns ``None`` for an empty / whitespace-
                # only document. Both ``OpenCTIConnectorHelper`` and the
                # downstream ``get_config_variable(..., config, ...)``
                # calls index into the mapping, so a ``None`` here would
                # crash startup. ``or {}`` upholds the same contract as
                # the missing-file branch below.
                config = yaml.safe_load(config_file) or {}
        else:
            config = {}

        self.helper = OpenCTIConnectorHelper(config)

        self.interval = get_config_variable(
            "THREAT_ACTOR_ENRICHMENT_INTERVAL",
            ["threat_actor_enrichment", "interval"],
            config,
            True,
            24,
        )

    # ------------------------------------------------------------------ #
    # Date helpers                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        """Parse an ISO-8601 timestamp into a UTC-aware ``datetime``.

        Always returns a timezone-aware value (UTC) on success so the
        downstream ``max(candidate_dates, ...)`` and
        ``best_dt > current_dt`` comparisons never raise ``TypeError``
        on mixed aware / naive operands. ``datetime.fromisoformat``
        returns a naive ``datetime`` for inputs that carry no offset
        (legacy STIX dates, malformed-but-parseable values), so we
        normalise explicitly here rather than at every call site.
        """
        if not date_str:
            return None
        try:
            parsed = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _format_last_seen(dt: datetime) -> str:
        """Serialise a ``datetime`` to OpenCTI's canonical ``last_seen`` shape.

        OpenCTI stores ``last_seen`` as a UTC ISO-8601 timestamp with
        millisecond precision and a ``Z`` suffix
        (``YYYY-MM-DDTHH:MM:SS.sssZ``). Normalise to UTC first so an
        offset-bearing ``datetime`` cannot silently move the value
        backward, then compose the canonical millisecond shape
        explicitly so the output is timezone-correct and preserves
        the source precision.
        """
        if dt.tzinfo is None:
            dt_utc = dt.replace(tzinfo=timezone.utc)
        else:
            dt_utc = dt.astimezone(timezone.utc)
        millis = dt_utc.microsecond // 1000
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}Z"

    @classmethod
    def _is_stale(cls, current_last_seen: str | None) -> bool:
        """Check if ``last_seen`` is missing, sentinel, or unparseable.

        Unparseable values are treated as stale so the connector can
        self-heal historical bad data (e.g. an upstream import that
        wrote a garbage string into ``last_seen``). Flagging only
        missing / epoch-zero / far-future would have short-circuited
        the ``best_dt > current_dt`` branch on a ``current_dt is None``
        guard and the bad value would be locked in forever.
        """
        if not current_last_seen:
            return True
        if current_last_seen in (EPOCH_ZERO, FAR_FUTURE):
            return True
        return cls._parse_date(current_last_seen) is None

    # ------------------------------------------------------------------ #
    # OpenCTI API queries (read-side)                                    #
    # ------------------------------------------------------------------ #

    def _iter_threat_actor_groups(self) -> list[dict]:
        """Return every ``Threat-Actor-Group`` from the platform.

        ``helper.api.threat_actor_group.list(getAll=True)`` paginates
        under the hood (the default page size is server-controlled)
        and materialises the full collection into a list before
        returning, so a single call is enough to walk every entity
        without the per-cycle scroll bookkeeping a direct ES query
        would need. Return type is the concrete ``list`` (rather
        than ``Iterable``) so the caller can use ``len(...)`` for
        the run-summary log without copying.
        """
        return (
            self.helper.api.threat_actor_group.list(
                getAll=True,
                customAttributes=_TA_ATTRIBUTES,
            )
            or []
        )

    def _get_malware_ids(self, ta_internal_id: str) -> list[str]:
        """Return the OpenCTI ids of every malware the threat actor uses."""
        relationships = (
            self.helper.api.stix_core_relationship.list(
                fromId=ta_internal_id,
                relationship_type="uses",
                toTypes=["Malware"],
                getAll=True,
                customAttributes=_USES_REL_ATTRIBUTES,
            )
            or []
        )
        # Dedupe via a ``set`` for O(1) membership while still
        # returning a ``list`` with insertion order preserved — a
        # threat actor can carry many ``uses`` relationships
        # pointing at the same malware (different ``confidence``,
        # different reports) and the previous ``target_id not in
        # malware_ids`` shape was O(n) per iteration → O(n²)
        # overall.
        malware_ids: list[str] = []
        seen_ids: set[str] = set()
        for rel in relationships:
            if not isinstance(rel, dict):
                continue
            target = rel.get("to")
            if not isinstance(target, dict):
                continue
            target_id = target.get("id")
            if target_id and target_id not in seen_ids:
                seen_ids.add(target_id)
                malware_ids.append(target_id)
        return malware_ids

    @staticmethod
    def _regarding_filter(malware_ids: list[str], relationship_type: str) -> dict:
        """Build a ``regardingOf`` filter for entities related to malware.

        OpenCTI's ``regardingOf`` filter selects entities that are on
        either end of a relationship of the given type pointing at any
        of the supplied ids. Used to fetch indicators that ``indicates``
        the threat actor's malware in a single round-trip.
        """
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "regardingOf",
                    "values": [
                        {"key": "id", "values": malware_ids},
                        {"key": "relationship_type", "values": [relationship_type]},
                    ],
                }
            ],
            "filterGroups": [],
        }

    @staticmethod
    def _objects_filter(malware_ids: list[str]) -> dict:
        """Build a filter for containers (e.g. reports) holding the malware."""
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "objects",
                    "values": malware_ids,
                }
            ],
            "filterGroups": [],
        }

    # Pull a small window rather than ``first=1`` on the ranked
    # queries below. With ``orderBy=<date> desc + first=1`` a single
    # indicator or report carrying a sentinel ``valid_from`` /
    # ``published`` (``FAR_FUTURE`` or ``EPOCH_ZERO`` — both legal
    # placeholder values produced by some upstream pipelines) would
    # dominate the result and either short-circuit the fallback
    # (indicators) or cause the function to return ``None``
    # (reports), silently locking the connector out of seeing the
    # real latest activity. ``10`` is large enough to absorb a
    # cluster of sentinel-bearing nodes while keeping the wire
    # payload small (each node is at most a handful of fields).
    _LATEST_WINDOW = 10

    def _get_latest_indicator_date(self, malware_ids: list[str]) -> str | None:
        """Return the most recent ``valid_from`` of any indicator that
        ``indicates`` one of the malware ids (falls back to ``created_at``).

        Walks a small window of indicators sorted descending by
        ``valid_from``. The first non-sentinel ``valid_from`` is the
        latest real one (the server-side sort guarantees that). When
        every ``valid_from`` in the window is a sentinel, the
        function falls back to the largest non-sentinel
        ``created_at`` carried by the same window — computed
        client-side because the iteration order is by
        ``valid_from``, not ``created_at``.
        """
        if not malware_ids:
            return None
        indicators = (
            self.helper.api.indicator.list(
                filters=self._regarding_filter(malware_ids, "indicates"),
                orderBy="valid_from",
                orderMode="desc",
                first=self._LATEST_WINDOW,
                customAttributes=_INDICATOR_LATEST_ATTRIBUTES,
            )
            or []
        )
        for node in indicators:
            vf = node.get("valid_from")
            if vf and vf not in (EPOCH_ZERO, FAR_FUTURE):
                return vf
        best: tuple[datetime, str] | None = None
        for node in indicators:
            ca = node.get("created_at")
            if not ca or ca in (EPOCH_ZERO, FAR_FUTURE):
                continue
            parsed = self._parse_date(ca)
            if parsed is None:
                continue
            if best is None or parsed > best[0]:
                best = (parsed, ca)
        return best[1] if best else None

    def _get_latest_report_date(self, malware_ids: list[str]) -> str | None:
        """Return the most recent ``published`` date of any report that
        contains one of the malware ids.

        Walks a small window of reports sorted descending by
        ``published`` and returns the first non-sentinel value.
        With ``first=1`` a stray sentinel at the top of the order
        would cause the function to return ``None`` even when other
        reports in the same window carry valid ``published`` dates.
        """
        if not malware_ids:
            return None
        reports = (
            self.helper.api.report.list(
                filters=self._objects_filter(malware_ids),
                orderBy="published",
                orderMode="desc",
                first=self._LATEST_WINDOW,
                customAttributes=_REPORT_LATEST_ATTRIBUTES,
            )
            or []
        )
        for node in reports:
            published = node.get("published")
            if published and published not in (EPOCH_ZERO, FAR_FUTURE):
                return published
        return None

    # ------------------------------------------------------------------ #
    # Enrichment orchestration                                           #
    # ------------------------------------------------------------------ #

    def _process_enrichment(self) -> None:
        """Main enrichment logic: scan every threat actor and update stale last_seen."""
        self.helper.log_info("Starting threat actor last_seen enrichment run")

        threat_actors = self._iter_threat_actor_groups()
        self.helper.log_info(f"Found {len(threat_actors)} threat-actor-group entities")

        updated = 0
        skipped = 0
        errors = 0

        for ta in threat_actors:
            ta_name: str = ta.get("name") or "unknown"
            ta_internal_id: str | None = ta.get("id")
            current_last_seen: str | None = ta.get("last_seen")

            if not ta_internal_id:
                # Defensive: a payload missing the canonical id would
                # crash the ``update_field`` write below with an opaque
                # error from the API layer. Surface it here with a
                # contextual log line so the operator can correlate
                # the upstream data-quality issue with the source TA.
                self.helper.log_warning(
                    f"Skipping threat actor {ta_name} with no resolvable id"
                )
                skipped += 1
                continue

            try:
                malware_ids = self._get_malware_ids(ta_internal_id)
                # ``(parsed, raw)`` tuples so ``max`` keys on the
                # comparable ``datetime`` form (lex-string compare
                # across mixed ISO offsets / precisions can pick the
                # wrong value) while the raw source string remains
                # available for logging.
                candidate_dates: list[tuple[datetime, str]] = []
                for raw in (
                    self._get_latest_indicator_date(malware_ids),
                    self._get_latest_report_date(malware_ids),
                ):
                    parsed = self._parse_date(raw)
                    if parsed is not None:
                        candidate_dates.append((parsed, raw))

                if not candidate_dates:
                    skipped += 1
                    continue

                best_dt, _best_raw = max(candidate_dates, key=lambda pair: pair[0])
                current_dt = self._parse_date(current_last_seen)

                should_update = self._is_stale(current_last_seen) or (
                    current_dt is not None and best_dt > current_dt
                )

                if not should_update:
                    skipped += 1
                    continue

                new_last_seen = self._format_last_seen(best_dt)

                self.helper.api.stix_domain_object.update_field(
                    id=ta_internal_id,
                    input={"key": "last_seen", "value": new_last_seen},
                )

                self.helper.log_info(
                    f"Updated {ta_name:<35} last_seen: "
                    f"{(current_last_seen or 'N/A')[:10]} -> {new_last_seen[:10]}"
                )
                updated += 1

            except Exception as err:
                # Surface the exception type AND message so an
                # operator can diagnose the failure (API timeout vs.
                # GraphQL validation error vs. permission denied)
                # without enabling debug logging.
                self.helper.log_error(
                    f"Error processing threat actor {ta_name} "
                    f"({type(err).__name__}): {err}"
                )
                errors += 1

        self.helper.log_info(
            f"Run complete: {updated} updated, {skipped} skipped, "
            f"{errors} errors (of {len(threat_actors)} total)"
        )

    # ------------------------------------------------------------------ #
    # Scheduler loop                                                     #
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        self.helper.log_info("Threat Actor Enrichment connector starting")
        while True:
            try:
                timestamp = int(time.time())

                current_state: dict[str, Any] | None = self.helper.get_state()
                if current_state and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.fromtimestamp(last_run, tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")

                interval_seconds = int(self.interval) * 60 * 60
                # Only initiate a work when we're actually going to
                # process — creating a work on every 60-second loop
                # tick regardless of the interval check would leave a
                # dangling "in progress" work per minute (≈ 1440 per
                # day) when the connector was idle waiting for the
                # next cycle. ``initiate_work`` has no counterpart
                # cleanup on the idle path, so any work we open here
                # must be closed by ``to_processed`` on the same
                # iteration.
                if last_run is None or (timestamp - last_run) > interval_seconds:
                    now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    friendly_name = "Threat Actor Enrichment run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    # Pre-assign so the ``finally`` below can always
                    # reference ``message`` even if a
                    # ``KeyboardInterrupt`` / ``SystemExit`` (which the
                    # inner ``except Exception`` deliberately does not
                    # catch) interrupts the body before either branch
                    # assigns it — otherwise the cleanup would mask
                    # the real exception with ``UnboundLocalError``.
                    message = "Connector run interrupted"
                    try:
                        self._process_enrichment()
                        message = (
                            f"Connector ran successfully, next run in "
                            f"{self.interval} hours"
                        )
                        self.helper.log_info(message)
                    except Exception as run_err:
                        # Surface the failure on the work itself so
                        # OpenCTI doesn't show a permanently
                        # "in progress" entry and the operator sees
                        # the underlying error in the work log; the
                        # outer broad ``except`` below still keeps the
                        # connector alive for the next interval.
                        message = (
                            f"Connector run failed ({type(run_err).__name__}): "
                            f"{run_err}"
                        )
                        self.helper.log_error(message)
                    finally:
                        # Persist ``last_run`` regardless of success
                        # or failure so the scheduler backs off to
                        # the configured interval instead of re-
                        # running on the next 60-second tick. The
                        # previous shape only set the state on the
                        # success path, so a persistent failure
                        # (bad token, platform unreachable, GraphQL
                        # validation error) produced ≈1440 retry
                        # works per day until the operator
                        # intervened — clear failure indication once
                        # per interval is more useful than per-
                        # minute spam in the work log.
                        utc_time = calendar.timegm(
                            datetime.now(timezone.utc).utctimetuple()
                        )
                        self.helper.set_state({"last_run": utc_time})
                        self.helper.api.work.to_processed(work_id, message)
                else:
                    next_in = interval_seconds - (timestamp - last_run)
                    self.helper.log_info(
                        f"Connector will run in {next_in // 3600}h "
                        f"{(next_in % 3600) // 60}m"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception as e:
                # Mirror the inner ``_process_enrichment`` handler:
                # include the exception type so operators can tell a
                # state-store error apart from a force-ping failure
                # without enabling debug logging.
                self.helper.log_error(f"{type(e).__name__}: {e}")

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)

    def run(self) -> None:
        self.start()


if __name__ == "__main__":
    try:
        connector = ThreatActorEnrichment()
        connector.run()
    except Exception:
        import traceback

        traceback.print_exc()
        sys.exit(1)
