"""OpenCTI CrowdStrike indicator importer module."""

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, NamedTuple, Optional, Set

from crowdstrike_feeds_connector.related_actors.importer import RelatedActorImporter
from crowdstrike_feeds_services.client.indicators import IndicatorsAPI
from crowdstrike_feeds_services.utils import (
    datetime_to_timestamp,
    timestamp_to_datetime,
)
from crowdstrike_feeds_services.utils.attack_lookup import AttackTechniqueLookup
from crowdstrike_feeds_services.utils.labels import parse_crowdstrike_labels
from crowdstrike_feeds_services.utils.report_fetcher import FetchedReport, ReportFetcher
from stix2 import Bundle, Identity, MarkingDefinition

from ..importer import BaseImporter
from .builder import IndicatorBundleBuilder, IndicatorBundleBuilderConfig

if TYPE_CHECKING:
    from crowdstrike_feeds_connector import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class IndicatorImporterConfig(NamedTuple):
    """CrowdStrike indicator importer configuration."""

    config: "ConnectorSettings"
    helper: "OpenCTIConnectorHelper"
    author: Identity
    default_latest_timestamp: int
    tlp_marking: MarkingDefinition
    create_observables: bool
    create_indicators: bool
    exclude_types: List[str]
    report_status: int
    report_type: str
    default_x_opencti_score: int
    indicator_low_score: int
    indicator_low_score_labels: Set[str]
    indicator_medium_score: int
    indicator_medium_score_labels: Set[str]
    indicator_high_score: int
    indicator_high_score_labels: Set[str]
    indicator_unwanted_labels: Set[str]
    indicator_max_age_by_type: Dict[str, Optional[timedelta]]
    no_file_trigger_import: bool
    scopes: set[str]
    attack_lookup: Optional[AttackTechniqueLookup]
    max_records_per_run: Optional[int] = None


class IndicatorImporter(BaseImporter):
    """CrowdStrike indicator importer."""

    _NAME = "Indicator"

    _LATEST_INDICATOR_TIMESTAMP = "latest_indicator_timestamp"
    # Persisted last ``_marker`` value seen across runs. ``_marker`` is
    # ``<unix_timestamp_10chars><unique_suffix>``, so resuming from the
    # bare ``last_updated`` timestamp (the legacy state key, seconds
    # granularity) makes the FQL ``_marker:>='1700000005'`` match every
    # marker whose timestamp prefix is ``1700000005`` — including the
    # indicators we already processed in the previous run. Persisting
    # the exact last marker shrinks the boundary overlap to (at most)
    # the single indicator whose marker we stored, which the downstream
    # STIX-ID dedup already absorbs. Missing key is a normal state for
    # deployments upgrading from a prior version of the connector — the
    # importer falls back to the timestamp resume in that case.
    _LATEST_INDICATOR_MARKER = "latest_indicator_marker"

    def __init__(self, config: IndicatorImporterConfig) -> None:
        """Initialize CrowdStrike indicator importer."""
        super().__init__(
            config.config,
            config.helper,
            config.author,
            config.tlp_marking,
        )

        self.indicators_api_cs = IndicatorsAPI(config.config, config.helper)
        self.related_actor_importer = RelatedActorImporter(
            config.config,
            config.helper,
        )
        # Simple per-run cache to avoid repeated actor resolution calls.
        self.create_observables = config.create_observables
        self.create_indicators = config.create_indicators
        self.default_latest_timestamp = config.default_latest_timestamp
        self.exclude_types = config.exclude_types
        self.report_status = config.report_status
        self.report_type = config.report_type
        self.default_x_opencti_score = config.default_x_opencti_score
        self.indicator_low_score = config.indicator_low_score
        self.indicator_low_score_labels = config.indicator_low_score_labels
        self.indicator_medium_score = config.indicator_medium_score
        self.indicator_medium_score_labels = config.indicator_medium_score_labels
        self.indicator_high_score = config.indicator_high_score
        self.indicator_high_score_labels = config.indicator_high_score_labels
        self.indicator_unwanted_labels = config.indicator_unwanted_labels
        self.indicator_max_age_by_type = config.indicator_max_age_by_type
        self.no_file_trigger_import = config.no_file_trigger_import
        self.scopes = config.scopes
        # Preloaded at connector startup; used to resolve MITRE technique IDs for ATT&CK labels.
        self.attack_lookup = config.attack_lookup
        self.max_records_per_run = (
            config.max_records_per_run
            if config.max_records_per_run and config.max_records_per_run > 0
            else None
        )
        if not (self.create_observables or self.create_indicators):
            msg = "'create_observables' and 'create_indicators' false at the same time"
            raise ValueError(msg)

        self.report_fetcher = ReportFetcher(
            config.config, config.helper, self.no_file_trigger_import
        )

    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Run importer."""
        self._info("Running indicator importer with state: {0}...", state)

        self._clear_report_fetcher_cache()

        fetch_timestamp = state.get(
            self._LATEST_INDICATOR_TIMESTAMP, self.default_latest_timestamp
        )
        # Optional - older state shapes (pre-marker-resume) won't carry
        # this key and the fetch falls back to the timestamp-based
        # marker, which is correct for the very first run after upgrade.
        fetch_marker = state.get(self._LATEST_INDICATOR_MARKER)

        latest_indicator_updated_datetime: datetime | None = None

        indicator_batch = self._fetch_indicators(fetch_timestamp, fetch_marker)
        if indicator_batch:
            latest_batch_updated_datetime = self._process_indicators(indicator_batch)

            if latest_batch_updated_datetime is not None and (
                latest_indicator_updated_datetime is None
                or latest_batch_updated_datetime > latest_indicator_updated_datetime
            ):
                latest_indicator_updated_datetime = latest_batch_updated_datetime

        latest_indicator_updated_timestamp = fetch_timestamp

        if latest_indicator_updated_datetime is not None:
            latest_indicator_updated_timestamp = datetime_to_timestamp(
                latest_indicator_updated_datetime
            )

        # Persist the highest ``_marker`` actually observed during this
        # run for exact cross-run continuation. We take the last item's
        # ``_marker`` because ``_paginated_query_indicators`` sorts by
        # ``_marker.asc`` and only extends ``resources`` with the
        # (cap-sliced) accepted page, so the last item carries the
        # highest accepted marker. When the field is missing on the
        # last item, fall back to the previously-persisted marker
        # rather than dropping the key — losing the marker would
        # silently re-trigger the seconds-granularity overlap on the
        # next run.
        next_marker = (
            indicator_batch[-1].get("_marker") if indicator_batch else None
        ) or fetch_marker

        new_state: Dict[str, Any] = {
            self._LATEST_INDICATOR_TIMESTAMP: latest_indicator_updated_timestamp,
        }
        if next_marker:
            new_state[self._LATEST_INDICATOR_MARKER] = next_marker

        self._info(
            "Indicator importer completed, latest fetch {0}.",
            timestamp_to_datetime(latest_indicator_updated_timestamp),
        )

        return new_state

    def _clear_report_fetcher_cache(self) -> None:
        self.report_fetcher.clear_cache()

    # FalconPy / CrowdStrike caps a single ``QueryIntelIndicatorEntities``
    # call at 5000 records. We pick 1000 by default to keep batches small
    # enough to be processed-and-sent before the next page is fetched,
    # which spreads memory & ingestion-queue pressure more evenly.
    _PAGE_LIMIT = 1000

    def _fetch_indicators(
        self, fetch_timestamp: int, fetch_marker: Optional[str] = None
    ) -> List[dict]:
        """Fetch all indicators updated since ``fetch_timestamp``.

        Walks the CrowdStrike indicator API using marker-based deep
        pagination (the ``_marker`` FQL field, sorted ``_marker.asc``)
        up to the configured ``max_records_per_run`` cap when set.
        Returns the full list of resources in a single batch so the
        downstream ``_process_indicators`` step can compute the latest
        ``last_updated`` timestamp across the whole run.

        ``fetch_marker`` is the previously-persisted last ``_marker``
        from the importer state and, when supplied, is preferred over
        ``fetch_timestamp`` for the initial cursor (the persisted
        marker carries the unique suffix and pins resume to the exact
        boundary indicator). It is ``None`` on the first run after
        upgrade.
        """
        return self._paginated_query_indicators(
            limit=self._PAGE_LIMIT,
            fetch_timestamp=fetch_timestamp,
            fetch_marker=fetch_marker,
        )

    def _build_fql_filter(self, marker: str) -> str:
        """Build the FQL filter used for a single indicator API call.

        The base clause is ``_marker:>='<marker>'`` — CrowdStrike's
        documented deep-pagination contract for ``QueryIntelIndicatorEntities``
        (see https://www.falconpy.io/Usage/Response-Handling.html).

        On the first run / after a state migration, ``marker`` is the
        importer state's ``last_updated`` timestamp (Unix seconds);
        this matches the 10-character timestamp prefix of every
        ``_marker`` so we pick up from that second onward. On every
        subsequent run, ``marker`` is the exact ``_marker`` of the
        last indicator we accepted in the previous run, persisted in
        state under ``latest_indicator_marker`` — using the full
        marker (with its unique suffix) pins the resume cursor to the
        exact boundary indicator instead of all indicators that share
        the same second.
        """
        fql_filter = f"_marker:>='{marker}'"
        if self.exclude_types:
            fql_filter = f"{fql_filter}+type:!{self.exclude_types}"
        return fql_filter

    def _paginated_query_indicators(
        self,
        limit: int,
        fetch_timestamp: int,
        fetch_marker: Optional[str] = None,
    ) -> List[dict]:
        """Walk every page of the indicator API and return the aggregated list.

        Pagination relies on CrowdStrike's documented marker-based deep
        pagination: each indicator carries a monotonically-increasing
        ``_marker`` field whose first 10 characters are a Unix timestamp
        (in seconds). The first call filters with the importer state
        timestamp; subsequent calls advance the marker using the last
        indicator returned by the previous page. Pagination ends when:

        * the API returns an empty page (the primary, authoritative
          termination signal - when no indicators match the current
          ``_marker:>='<cursor>'`` filter, the API returns an empty
          ``resources`` list and we are done), OR
        * the last accepted indicator on a page is missing its
          ``_marker`` field (defensive - prevents an infinite loop on
          a malformed response), OR
        * the marker does not advance between two consecutive pages
          (defensive - same anti-spin guard for an API that wedges on
          one cursor), OR
        * the configured ``max_records_per_run`` cap is reached.

        The cap is enforced at the resource level — the *last* page is
        sliced down to the remaining quota — so the aggregated batch
        contains at most ``max_records_per_run`` records and we never
        yield a record beyond the cap.

        NOTE: The previous implementation tried to paginate via a
        ``Next-Page`` HTTP header / ``next_page`` continuation token,
        but ``GET /intel/combined/indicators/v1`` does *not* expose
        those (they are reserved for other CrowdStrike Service
        Collections such as Hosts), so the loop only ever ran once and
        every run capped at a single ``limit``-sized batch.
        """
        # Sort ascending by ``_marker`` so the last indicator on a page
        # always carries the largest ``_marker`` we have seen so far —
        # the cursor that drives the next call.
        sort = "_marker.asc"
        resources: List[dict] = []
        # Resume from the persisted ``_marker`` when available so the
        # boundary doesn't re-fetch every indicator that shares the
        # same second prefix; otherwise fall back to the seconds-
        # granularity timestamp for the initial run.
        current_marker: str = fetch_marker or str(fetch_timestamp)
        last_seen_marker: Optional[str] = None

        while True:
            fql_filter = self._build_fql_filter(current_marker)

            response = self.indicators_api_cs.get_combined_indicator_entities(
                limit=limit, sort=sort, fql_filter=fql_filter
            )

            page_resources = response.get("resources") or []
            if not page_resources:
                break

            # ``meta.pagination`` can legitimately be missing or null —
            # guard against both so we don't AttributeError on the
            # ``.get()`` below.
            meta = response.get("meta") or {}
            pagination = meta.get("pagination") or {}
            meta_total = pagination.get("total")

            remaining_cap = self._remaining_cap(len(resources))
            if remaining_cap is not None and remaining_cap <= 0:
                self._log_run_cap_reached(len(resources))
                break

            if remaining_cap is not None and len(page_resources) > remaining_cap:
                page_resources = page_resources[:remaining_cap]

            resources.extend(page_resources)

            # Marker for the next page = ``_marker`` of the last indicator
            # we accepted on this page. Fall back gracefully when the
            # field is missing so a single malformed response cannot
            # spin the loop forever on the same marker.
            next_marker = page_resources[-1].get("_marker")

            self.helper.connector_logger.info(
                "Fetched indicator batch",
                {
                    "batch_size": len(page_resources),
                    "total_fetched": len(resources),
                    # ``meta.pagination.total`` is the count of records
                    # matching the *current request's* FQL filter
                    # (``_marker:>='<cursor>'`` + any ``type:!<exclude>``
                    # clause). It decreases as the marker advances
                    # because the FQL changes per call, not because the
                    # field has a special "remaining" semantics - so
                    # surface it under a neutral name that does not
                    # claim either contract. ``utils.paginate`` in this
                    # repo uses the same field as the absolute total
                    # for offset-based queries elsewhere.
                    "matching_filter_total": meta_total,
                    "max_records_per_run": self.max_records_per_run,
                    "current_marker": current_marker,
                    "next_marker": next_marker,
                },
            )

            if (
                self.max_records_per_run is not None
                and len(resources) >= self.max_records_per_run
            ):
                self._log_run_cap_reached(len(resources))
                break

            if not next_marker:
                self.helper.connector_logger.warning(
                    "Last indicator on page is missing '_marker' field; "
                    "stopping pagination to avoid an infinite loop",
                    {"indicator_id": page_resources[-1].get("id")},
                )
                break

            # Defensive: if the marker doesn't advance (e.g. the API
            # returns the same page again), break instead of looping
            # forever. ``_marker`` is monotonically increasing per the
            # API contract, so equality means we're stuck.
            if last_seen_marker is not None and next_marker == last_seen_marker:
                self.helper.connector_logger.warning(
                    "Indicator pagination marker did not advance; "
                    "stopping to avoid an infinite loop",
                    {"marker": next_marker},
                )
                break

            # NOTE: no ``meta_total <= 0`` early-stop. CrowdStrike's
            # contract is that ``total`` reflects records matching the
            # current request; when no records match, the API returns
            # an empty ``resources`` list and the empty-page check at
            # the top of the loop already breaks. A ``total == 0``
            # response alongside non-empty ``resources`` would be an
            # API inconsistency and is not a normal-flow termination.

            last_seen_marker = next_marker
            current_marker = next_marker

        return resources

    def _remaining_cap(self, already_fetched: int) -> Optional[int]:
        """Return how many more records can still be fetched in this run."""
        if self.max_records_per_run is None:
            return None
        return self.max_records_per_run - already_fetched

    def _log_run_cap_reached(self, total_fetched: int) -> None:
        self.helper.connector_logger.info(
            "Reached per-run indicator cap, stopping pagination for this run",
            {
                "total_fetched": total_fetched,
                "max_records_per_run": self.max_records_per_run,
            },
        )

    def _process_indicators(self, indicators: List[dict]) -> datetime | None:
        indicator_count = len(indicators)
        self._info("Processing {0} indicators...", indicator_count)

        latest_updated_datetime = None

        failed = 0
        for indicator in indicators:
            result = self._process_indicator(indicator)
            if not result:
                failed += 1

            updated_date = timestamp_to_datetime(indicator["last_updated"])
            if (
                latest_updated_datetime is None
                or updated_date > latest_updated_datetime
            ):
                latest_updated_datetime = updated_date

        imported = indicator_count - failed
        total = imported + failed

        self._info(
            "Processing indicators completed (imported: {0}, failed: {1}, total: {2}, latest: {3})",  # noqa: E501
            imported,
            failed,
            total,
            latest_updated_datetime,
        )

        return latest_updated_datetime

    def _process_indicator(self, indicator: dict) -> bool:
        self._info("Processing indicator {0}...", indicator["id"])

        if self._is_indicator_too_old(indicator):
            return True

        indicator_bundle = self._create_indicator_bundle(indicator)
        if indicator_bundle is None:
            self._warning("Discarding indicator {0} bundle", indicator["id"])
            return False

        # with open(f"indicator_bundle_{indicator_bundle['id']}.json", "w") as f:
        #     f.write(indicator_bundle.serialize(pretty=True))

        self._send_bundle(indicator_bundle)

        return True

    def _is_indicator_too_old(self, indicator: dict) -> bool:
        indicator_type = indicator.get("type", "")
        published_date_timestamp = indicator.get("published_date")

        if published_date_timestamp is None:
            return False

        published_date = timestamp_to_datetime(published_date_timestamp)
        now = datetime.now(timezone.utc)

        threshold_key = "default"
        if indicator_type in ["ip_address", "ip_address_block"]:
            threshold_key = "ip"
        elif indicator_type == "domain":
            threshold_key = "domain"
        elif indicator_type == "url":
            threshold_key = "url"
        elif indicator_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
            threshold_key = "hash"

        threshold = self.indicator_max_age_by_type.get(threshold_key)

        # Fallback to default if type-specific threshold is not defined
        if threshold is None and threshold_key != "default":
            threshold = self.indicator_max_age_by_type.get("default")

        if threshold is not None:
            if published_date < (now - threshold):
                self._info(
                    "Indicator {0} (type: {1}, published: {2}) is older than the threshold ({3}), skipping...",
                    indicator["id"],
                    indicator_type,
                    published_date,
                    threshold,
                )
                return True

        return False

    def _get_reports_by_code(self, codes: List[str]) -> List[FetchedReport]:
        return self.report_fetcher.get_by_codes(codes)

    def _create_indicator_bundle(self, indicator: dict) -> Optional[Bundle]:
        try:
            parsed_labels = parse_crowdstrike_labels(indicator.get("labels") or [])
            indicator["label_names"] = parsed_labels.raw
            indicator["attack_patterns"] = parsed_labels.attack_patterns
            indicator["malware_families"] = parsed_labels.malware_families

            # Resolve ATT&CK technique IDs for label-derived attack patterns so we can build canonical
            # Attack Pattern objects that match the MITRE connector (source of truth).
            resolved_attack_patterns: List[Dict[str, str]] = []
            if self.attack_lookup:
                for ap_name in parsed_labels.attack_patterns:
                    mitre_id = self.attack_lookup.lookup_mitre_id(ap_name)
                    if mitre_id:
                        resolved_attack_patterns.append(
                            {"name": ap_name, "mitre_id": mitre_id}
                        )
            indicator["attack_patterns_resolved"] = resolved_attack_patterns

            # Do NOT merge these into `indicator["actors"]` (that field is reserved for resolved
            # related actors from the API). Keep label-derived actors separate.
            indicator["actor_names_from_labels"] = parsed_labels.actor_names

            # Indicator types: merge CrowdStrike API arrays (preferred) and label-derived threat types (fallback)
            api_threat_types = (
                indicator.get("threat_types") or parsed_labels.threat_types
            )
            api_domain_types = indicator.get("domain_types") or []
            api_ip_address_types = indicator.get("ip_address_types") or []

            # Preserve order, de-dupe case-insensitively
            merged_indicator_types: List[str] = []
            seen: set[str] = set()
            for v in (
                list(api_threat_types)
                + list(api_domain_types)
                + list(api_ip_address_types)
            ):
                s = str(v).strip()
                if not s or s.lower() in seen:
                    continue
                seen.add(s.lower())
                merged_indicator_types.append(s)

            # Keep the effective threat types separately for debugging/visibility
            indicator["threat_types"] = list(api_threat_types)
            indicator["indicator_types"] = merged_indicator_types

            self.helper.connector_logger.debug(
                "Parsed indicator labels",
                {
                    "indicator_id": indicator.get("id"),
                    "raw_label_count": len(indicator.get("labels") or []),
                    "label_name_count": len(indicator.get("label_names") or []),
                    "attack_pattern_count": len(indicator.get("attack_patterns") or []),
                    "attack_pattern_resolved_count": len(
                        indicator.get("attack_patterns_resolved") or []
                    ),
                    "malware_family_count": len(
                        indicator.get("malware_families") or []
                    ),
                    "actor_name_count": len(
                        indicator.get("actor_names_from_labels") or []
                    ),
                    "threat_type_count": len(indicator.get("threat_types") or []),
                    "indicator_type_count": len(indicator.get("indicator_types") or []),
                },
            )
            # Map CrowdStrike malicious confidence (low/medium/high) -> STIX/OpenCTI confidence (0-100)
            cs_mc = (indicator.get("malicious_confidence") or "").strip().lower()
            cs_conf_map = {"high": 90, "medium": 50, "low": 10}
            mapped_confidence = cs_conf_map.get(cs_mc)

            if mapped_confidence is not None:
                indicator["confidence"] = mapped_confidence

            if "actor" in self.scopes:
                # Process related actors
                related_actors = indicator.get("actors") or []
                indicator["actors"] = (
                    self.related_actor_importer._process_related_actors(
                        indicator.get("id"), related_actors
                    )
                )
                self.helper.connector_logger.debug(
                    "Resolved indicator actors",
                    {
                        "indicator_id": indicator.get("id"),
                        "actor_count": len(indicator.get("actors") or []),
                        "actor_entry_type": (
                            type(indicator["actors"][0]).__name__
                            if indicator.get("actors")
                            else None
                        ),
                    },
                )

            bundle_builder_config = IndicatorBundleBuilderConfig(
                indicator=indicator,
                author=self.author,
                source_name=self._source_name(),
                object_markings=[self.tlp_marking],
                confidence_level=self._confidence_level(),
                create_observables=self.create_observables,
                create_indicators=self.create_indicators,
                default_x_opencti_score=self.default_x_opencti_score,
                indicator_low_score=self.indicator_low_score,
                indicator_low_score_labels=self.indicator_low_score_labels,
                indicator_medium_score=self.indicator_medium_score,
                indicator_medium_score_labels=self.indicator_medium_score_labels,
                indicator_high_score=self.indicator_high_score,
                indicator_high_score_labels=self.indicator_high_score_labels,
                indicator_unwanted_labels=self.indicator_unwanted_labels,
                scopes=self.scopes,
            )

            bundle_builder = IndicatorBundleBuilder(self.helper, bundle_builder_config)
            indicator_bundle_built = bundle_builder.build()
            if indicator_bundle_built:
                return indicator_bundle_built.get("indicator_bundle")
            else:
                self.helper.connector_logger.warning(
                    "[WARNING] The construction of the indicator and all related entities has been skipped.",
                    {
                        "indicator_id": indicator.get("id"),
                        "indicator_type": indicator.get("type"),
                    },
                )
                return None
        except TypeError as err:
            self.helper.connector_logger.warning(
                "Skipping unsupported indicator type.",
                {
                    "indicator_id": indicator.get("id"),
                    "indicator_type": indicator.get("type"),
                    "indicator_value": indicator.get("indicator"),
                    "error": str(err),
                },
            )
            return None
        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error occurred when creating a bundle indicator.",
                {
                    "error": err,
                    "indicator_id": indicator.get("id"),
                    "indicator_type": indicator.get("type"),
                },
            )
            raise
