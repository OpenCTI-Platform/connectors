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
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

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
        """Fetch every threat-actor-group with its rel_uses links via scroll."""
        results = []
        resp = es.search(
            index=self.sdo_index,
            scroll="2m",
            size=SCROLL_SIZE,
            query={"term": {"entity_type.keyword": "threat-actor-group"}},
            _source=[
                "name",
                "internal_id",
                "last_seen",
                "first_seen",
                "rel_uses.internal_id",
            ],
        )
        scroll_id = resp["_scroll_id"]
        results.extend(resp["hits"]["hits"])
        while len(resp["hits"]["hits"]) > 0:
            resp = es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = resp["_scroll_id"]
            results.extend(resp["hits"]["hits"])
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
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def _is_stale(current_last_seen: str | None) -> bool:
        """Check if last_seen is missing, epoch-zero, or far-future."""
        if not current_last_seen:
            return True
        return current_last_seen in (EPOCH_ZERO, FAR_FUTURE)

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

            # rel_uses.internal_id is a flat dot-notation field in ES
            malware_ids = src.get("rel_uses.internal_id", [])

            try:
                candidate_dates: list[str] = []

                ind_date = self._get_latest_indicator_date(es, malware_ids)
                if ind_date:
                    candidate_dates.append(ind_date)

                rpt_date = self._get_latest_report_date(es, malware_ids)
                if rpt_date:
                    candidate_dates.append(rpt_date)

                if not candidate_dates:
                    skipped += 1
                    continue

                best_date_str = max(candidate_dates)
                best_dt = self._parse_date(best_date_str)
                current_dt = self._parse_date(current_last_seen)

                if best_dt is None:
                    skipped += 1
                    continue

                should_update = self._is_stale(current_last_seen) or (
                    current_dt is not None and best_dt > current_dt
                )

                if not should_update:
                    skipped += 1
                    continue

                new_last_seen = best_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

                self.helper.api.stix_domain_object.update_field(
                    id=ta_internal_id,
                    input={"key": "last_seen", "value": new_last_seen},
                )

                self.helper.log_info(
                    f"Updated {ta_name:<35} last_seen: "
                    f"{(current_last_seen or 'N/A')[:10]} -> {new_last_seen[:10]}"
                )
                updated += 1

            except Exception:
                self.helper.log_error(f"Error processing threat actor {ta_name}")
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
                now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                friendly_name = "Threat Actor Enrichment run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

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
                if last_run is None or (timestamp - last_run) > interval_seconds:
                    self._process_enrichment()

                    utc_time = calendar.timegm(
                        datetime.now(timezone.utc).utctimetuple()
                    )
                    self.helper.set_state({"last_run": utc_time})
                    message = (
                        f"Connector ran successfully, next run in "
                        f"{self.interval} hours"
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(message)
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
