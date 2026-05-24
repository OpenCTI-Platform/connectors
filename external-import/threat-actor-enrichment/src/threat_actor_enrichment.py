import calendar
import os
import sys
import time
from datetime import datetime, timezone

import urllib3
import yaml
from elasticsearch import Elasticsearch
from pycti import OpenCTIConnectorHelper, get_config_variable

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EPOCH_ZERO = "1970-01-01T00:00:00.000Z"
FAR_FUTURE = "5138-11-16T09:46:40.000Z"
SCROLL_SIZE = 200


class ThreatActorEnrichment:
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
                config = yaml.load(config_file, Loader=yaml.FullLoader) or {}
        else:
            config = {}

        self.helper = OpenCTIConnectorHelper(config)

        self.es_host = get_config_variable(
            "THREAT_ACTOR_ENRICHMENT_ES_HOST",
            ["threat_actor_enrichment", "es_host"],
            config,
        )
        self.es_user = get_config_variable(
            "THREAT_ACTOR_ENRICHMENT_ES_USER",
            ["threat_actor_enrichment", "es_user"],
            config,
            False,
            "",
        )
        self.es_password = get_config_variable(
            "THREAT_ACTOR_ENRICHMENT_ES_PASSWORD",
            ["threat_actor_enrichment", "es_password"],
            config,
            False,
            "",
        )
        self.es_verify_ssl = get_config_variable(
            "THREAT_ACTOR_ENRICHMENT_ES_VERIFY_SSL",
            ["threat_actor_enrichment", "es_verify_ssl"],
            config,
            False,
            False,
        )
        self.sdo_index = get_config_variable(
            "THREAT_ACTOR_ENRICHMENT_SDO_INDEX",
            ["threat_actor_enrichment", "sdo_index"],
            config,
            False,
            "opencti_stix_domain_objects-*",
        )
        self.interval = get_config_variable(
            "THREAT_ACTOR_ENRICHMENT_INTERVAL",
            ["threat_actor_enrichment", "interval"],
            config,
            True,
            24,
        )

    def _get_es_client(self) -> Elasticsearch:
        kwargs = {
            "verify_certs": self.es_verify_ssl,
            "request_timeout": 120,
        }
        if self.es_user and self.es_password:
            kwargs["basic_auth"] = (self.es_user, self.es_password)
        return Elasticsearch(self.es_host, **kwargs)

    def _fetch_all_threat_actors(self, es: Elasticsearch) -> list[dict]:
        """Fetch every threat-actor-group with its rel_uses links via scroll.

        OpenCTI stores denormalised relationships as **literal flat
        top-level keys with a dot in the name** (e.g.
        ``rel_uses.internal_id``) rather than as nested objects — see
        ``opencti-graphql/src/database/engine.ts`` where the indexer
        manipulates ``ctx._source['rel_uses.internal_id']`` directly,
        and ``schema/general.js::buildRefRelationKey`` which composes
        the field name as ``${REL_INDEX_PREFIX}${type}.${field}``. ES
        ``_source`` filtering, on the other hand, interprets dotted
        paths as nested traversal, so requesting
        ``_source=["rel_uses.internal_id"]`` silently strips the field
        from the returned hit and the connector ends up with an empty
        malware list for every threat actor — silently a no-op.

        Use the ``fields`` API for the dotted-key field so ES returns
        it as a flat list at ``hit["fields"]["rel_uses.internal_id"]``
        via the mapping, and keep ``_source`` for the plain attributes
        we actually need to read by their canonical names. Sort by
        ``_doc`` for the recommended efficient full-index scroll
        pattern (no scoring, no sort overhead), and always release the
        scroll context (the ES default is 5 min retention; releasing
        early frees server resources even if the caller crashes
        mid-iteration).
        """
        results = []
        resp = es.search(
            index=self.sdo_index,
            scroll="2m",
            size=SCROLL_SIZE,
            query={"term": {"entity_type.keyword": "threat-actor-group"}},
            sort=["_doc"],
            _source=["name", "internal_id", "last_seen", "first_seen"],
            fields=["rel_uses.internal_id"],
        )
        scroll_id = resp["_scroll_id"]
        try:
            results.extend(resp["hits"]["hits"])
            while len(resp["hits"]["hits"]) > 0:
                resp = es.scroll(scroll_id=scroll_id, scroll="2m")
                scroll_id = resp["_scroll_id"]
                results.extend(resp["hits"]["hits"])
        finally:
            es.clear_scroll(scroll_id=scroll_id)
        return results

    def _get_latest_indicator_date(
        self, es: Elasticsearch, malware_ids: list[str]
    ) -> str | None:
        """Find the latest valid_from from indicators linked to the given malware.

        Prefers valid_from (the authoritative STIX activity date) over created_at,
        falling back to created_at only when valid_from is missing or sentinel.
        """
        if not malware_ids:
            return None

        resp = es.search(
            index=self.sdo_index,
            size=0,
            query={
                "bool": {
                    "must": [{"term": {"entity_type.keyword": "indicator"}}],
                    "filter": {
                        "terms": {"rel_indicates.internal_id.keyword": malware_ids}
                    },
                }
            },
            aggs={
                "latest_valid_from": {"max": {"field": "valid_from"}},
                "latest_created": {"max": {"field": "created_at"}},
            },
        )
        aggs = resp["aggregations"]
        vf = aggs["latest_valid_from"].get("value_as_string")
        if vf and vf not in (EPOCH_ZERO, FAR_FUTURE):
            return vf
        ca = aggs["latest_created"].get("value_as_string")
        if ca and ca not in (EPOCH_ZERO, FAR_FUTURE):
            return ca
        return None

    def _get_latest_report_date(
        self, es: Elasticsearch, malware_ids: list[str]
    ) -> str | None:
        """Find the latest published date from reports referencing the given malware."""
        if not malware_ids:
            return None

        resp = es.search(
            index=self.sdo_index,
            size=0,
            query={
                "bool": {
                    "must": [{"term": {"entity_type.keyword": "report"}}],
                    "filter": {
                        "terms": {"rel_object.internal_id.keyword": malware_ids}
                    },
                }
            },
            aggs={"latest_published": {"max": {"field": "published"}}},
        )
        val = resp["aggregations"]["latest_published"].get("value_as_string")
        if val and val not in (EPOCH_ZERO, FAR_FUTURE):
            return val
        return None

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        """Parse an ISO-8601 timestamp into a UTC-aware ``datetime``.

        Always returns a timezone-aware value (UTC) on success so the
        downstream ``max(candidate_dates, ...)`` and ``best_dt >
        current_dt`` comparisons never raise ``TypeError`` on mixed
        aware / naive operands. ``datetime.fromisoformat`` returns a
        naive ``datetime`` for inputs that carry no offset (legacy
        STIX dates, malformed-but-parseable values), so we normalise
        explicitly here rather than at every call site.
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
        (``YYYY-MM-DDTHH:MM:SS.sssZ``). The previous shape used
        ``strftime("%Y-%m-%dT%H:%M:%S.000Z")`` which (a) truncated the
        millisecond field to ``.000``, dropping any sub-second
        precision the source carried, and (b) tacked a ``Z`` on without
        converting to UTC — so a ``best_dt`` with a ``+02:00`` offset
        would have been written as if it were UTC, silently moving
        ``last_seen`` two hours backward. Normalise to UTC, then
        compose the canonical millisecond shape explicitly so the
        output is timezone-correct and preserves the source precision.
        """
        if dt.tzinfo is None:
            dt_utc = dt.replace(tzinfo=timezone.utc)
        else:
            dt_utc = dt.astimezone(timezone.utc)
        millis = dt_utc.microsecond // 1000
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}Z"

    @classmethod
    def _is_stale(cls, current_last_seen: str | None) -> bool:
        """Check if last_seen is missing, sentinel, or unparseable.

        Unparseable values are treated as stale so the connector can
        self-heal historical bad data (e.g. an upstream import that
        wrote a garbage string into ``last_seen``). The previous
        shape only flagged missing / epoch-zero / far-future, so a
        non-empty but unparseable value would short-circuit the
        ``best_dt > current_dt`` branch on a ``current_dt is None``
        guard and the bad value would be locked in forever.
        """
        if not current_last_seen:
            return True
        if current_last_seen in (EPOCH_ZERO, FAR_FUTURE):
            return True
        return cls._parse_date(current_last_seen) is None

    def _process_enrichment(self):
        """Main enrichment logic: scan all threat actors and update stale last_seen."""
        self.helper.log_info("Starting threat actor last_seen enrichment run")
        es = self._get_es_client()

        threat_actors = self._fetch_all_threat_actors(es)
        self.helper.log_info(f"Found {len(threat_actors)} threat-actor-group entities")

        updated = 0
        skipped = 0
        errors = 0

        for ta_hit in threat_actors:
            src = ta_hit["_source"]
            ta_name = src.get("name", "unknown")
            ta_internal_id = src.get("internal_id")
            current_last_seen = src.get("last_seen")

            # ``rel_uses.internal_id`` is a literal flat top-level
            # dotted-key in OpenCTI's ES mapping (see
            # ``_fetch_all_threat_actors``); the ``fields`` API
            # returns it as a flat list at ``hit["fields"][...]``.
            fields = ta_hit.get("fields") or {}
            malware_ids = fields.get("rel_uses.internal_id") or []

            try:
                # Collect candidate dates as ``(parsed, raw)`` tuples
                # so we can ``max`` on the parsed ``datetime`` (a
                # lex-string compare across mixed ISO offsets or
                # precisions can pick the wrong value) but still keep
                # the raw source string for logging.
                candidate_dates: list[tuple[datetime, str]] = []

                for raw in (
                    self._get_latest_indicator_date(es, malware_ids),
                    self._get_latest_report_date(es, malware_ids),
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
                # Surface the exception type AND message so an operator
                # can diagnose the failure (ES query error vs. GraphQL
                # update vs. mapping mismatch) without enabling debug
                # logging. The previous shape dropped both, leaving
                # only "Error processing threat actor <name>" with no
                # actionable signal.
                self.helper.log_error(
                    f"Error processing threat actor {ta_name} "
                    f"({type(err).__name__}): {err}"
                )
                errors += 1

        self.helper.log_info(
            f"Run complete: {updated} updated, {skipped} skipped, "
            f"{errors} errors (of {len(threat_actors)} total)"
        )

    def start(self):
        self.helper.log_info("Threat Actor Enrichment connector starting")
        while True:
            try:
                timestamp = int(time.time())

                current_state = self.helper.get_state()
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
                # process — the previous shape created a fresh work
                # on every 60-second loop tick regardless of the
                # interval check, leaving one dangling "in progress"
                # work per minute (≈ 1440 per day) when the connector
                # was idle waiting for the next cycle. ``initiate_work``
                # has no counterpart cleanup on the idle path, so any
                # work we open here must be closed by ``to_processed``
                # on the same iteration.
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
                        utc_time = calendar.timegm(
                            datetime.now(timezone.utc).utctimetuple()
                        )
                        self.helper.set_state({"last_run": utc_time})
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
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)

    def run(self):
        self.start()


if __name__ == "__main__":
    try:
        connector = ThreatActorEnrichment()
        connector.run()
    except Exception:
        import traceback

        traceback.print_exc()
        sys.exit(1)
