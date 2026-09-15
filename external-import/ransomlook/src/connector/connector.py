# pylint: disable=wrong-import-order

import hashlib
import json
import time
from collections.abc import Iterator
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import stix2
from connector.api_client import (
    DeferredPostWindow,
    RansomLookAPIClient,
    RansomLookAPIError,
    RansomLookCapabilityUnavailable,
    RansomLookCycleBudgetExhausted,
)
from connector.converter import RansomLookConverter
from connector.evidence import EvidenceBudget, EvidenceDecoder, EvidencePayload
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


@dataclass(frozen=True)
class GroupEnrichment:
    """One independently deliverable actor-profile enrichment unit."""

    key: str
    name: str
    objects: list[Any]
    complete: bool


@dataclass(frozen=True)
class CollectionCycle:
    """Claim intelligence and optional enrichment collected for one window."""

    claims: list[Any]
    enrichments: list[GroupEnrichment]
    encountered_groups: dict[str, str]
    incomplete_claims: dict[str, dict[str, Any]] = field(default_factory=dict)
    processed_claim_keys: set[str] = field(default_factory=set)
    deferred_windows: list[DeferredPostWindow] = field(default_factory=list)
    resolved_deferred_keys: set[str] = field(default_factory=set)
    route_registry_updates: dict[str, dict[str, Any]] = field(default_factory=dict)
    deferred_window_metadata: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class RunMetrics:
    """Content-free counters emitted once for operational review of a run."""

    fetched_posts: int = 0
    accepted_posts: int = 0
    skipped_posts: int = 0
    imported_objects: int = 0
    delivered_bundles: int = 0
    optional_skips: int = 0
    retry_state_evictions: int = 0
    revision_ledger_evictions: int = 0


class RansomLookConnector:
    """Coordinate scheduled RansomLook collection and OpenCTI bundle delivery."""

    MAX_COLLECTION_WINDOW = timedelta(days=7)
    STATE_VERSION = 4
    REVISION_LEDGER_MAX_ENTRIES = 100_000
    ROUTE_REGISTRY_MAX_ENTRIES = 20_000

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """Initialize the API client and STIX converter.

        Args:
            config: Validated connector configuration.
            helper: OpenCTI connector helper.
        """
        self.config = config
        self.helper = helper
        self.client = RansomLookAPIClient(
            helper,
            str(config.ransomlook.api_base_url),
            (
                config.ransomlook.api_key.get_secret_value()
                if config.ransomlook.api_key is not None
                else None
            ),
            config.ransomlook.max_response_size_mb,
            config.ransomlook.max_records_per_endpoint,
            config.ransomlook.max_pages_per_endpoint,
            config.ransomlook.max_requests_per_run,
            config.ransomlook.max_run_duration_seconds,
        )
        self.converter = RansomLookConverter(
            str(config.ransomlook.api_base_url),
            list(config.ransomlook.labels),
            config.ransomlook.marking_definition,
        )
        self._reset_evidence_budget()
        self.metrics = RunMetrics()
        self._unsafe_claim_cursor = False

    def _reset_evidence_budget(self) -> None:
        """Start a fresh, independently bounded evidence budget for one run."""
        source = self.config.ransomlook
        self.evidence = EvidenceDecoder(
            self.helper.connector_logger,
            source.max_artifact_size_mb * 1024 * 1024,
            EvidenceBudget(
                source.max_artifacts_per_run,
                source.max_artifact_bytes_per_run_mb * 1024 * 1024,
                source.max_evidence_serialized_bytes_per_run_mb * 1024 * 1024,
            ),
        )
        self._leak_cache: tuple[list[dict[str, Any]], bool] | None = None

    @staticmethod
    def _deduplicate(objects: list[Any]) -> list[Any]:
        """Deduplicate STIX objects by ID while retaining the latest value.

        Args:
            objects: STIX objects with an ``id`` attribute.

        Returns:
            Objects in stable first-ID order, with duplicate values updated.
        """
        result: dict[str, Any] = {}
        for obj in objects:
            previous = result.get(obj.id)
            if previous is not None and all(
                hasattr(value, "serialize") for value in (previous, obj)
            ):
                previous_modified = getattr(previous, "modified", None)
                current_modified = getattr(obj, "modified", None)
                if (
                    previous_modified is not None
                    and previous_modified == current_modified
                    and previous.serialize() != obj.serialize()
                ):
                    raise ValueError(
                        "RansomLook produced divergent content at one STIX version"
                    )
            result[obj.id] = obj
        return list(result.values())

    def _window(self, now: datetime) -> tuple[datetime, datetime]:
        """Calculate a replay-safe import window.

        Args:
            now: Current UTC time.

        Returns:
            Inclusive start and end times. Subsequent runs replay one day so late
            upstream publications are not lost.
        """
        state = self._load_state()
        cursor = state["claims"].get("last_successful_run")
        if cursor:
            try:
                cursor_time = self.converter.parse_timestamp(cursor)
                start = cursor_time - timedelta(
                    days=self.config.ransomlook.replay_window_days
                )
            except (TypeError, ValueError):
                self.helper.connector_logger.warning(
                    "Ignoring invalid RansomLook state cursor",
                    {"cursor_type": type(cursor).__name__},
                )
                cursor_time = None
                start = now - timedelta(
                    days=self.config.ransomlook.initial_history_days
                )
        else:
            cursor_time = None
            start = now - timedelta(days=self.config.ransomlook.initial_history_days)
        if start > now:
            self.helper.connector_logger.warning(
                "RansomLook state cursor is in the future; using replay window"
            )
            start = now - timedelta(days=self.config.ransomlook.replay_window_days)
            cursor_time = None
        if cursor_time is None:
            return start, min(now, start + self.MAX_COLLECTION_WINDOW)
        forward_capacity = self.MAX_COLLECTION_WINDOW - timedelta(
            days=self.config.ransomlook.replay_window_days
        )
        return start, min(now, cursor_time + forward_capacity)

    def _collect(self, start: datetime, end: datetime) -> list[Any]:
        """Collect a date window and build deterministic STIX claim graphs.

        Args:
            start: Inclusive collection window start.
            end: Inclusive collection window end.

        Returns:
            Deduplicated STIX objects ready for bundling.
        """
        cycle = self._collect_cycle(start, end, {})
        objects = list(cycle.claims)
        for enrichment in cycle.enrichments:
            objects.extend(enrichment.objects)
        return self._deduplicate(objects)

    def _collect_cycle(
        self,
        start: datetime,
        end: datetime,
        pending_groups: dict[str, str],
        pending_claims: dict[str, dict[str, Any]] | None = None,
        deferred_windows: dict[str, dict[str, Any]] | None = None,
        route_registry: dict[str, dict[str, Any]] | None = None,
    ) -> CollectionCycle:
        """Build separately deliverable claim and actor-profile work."""
        self._reset_evidence_budget()
        self.metrics = RunMetrics()
        self.client.begin_run()
        pending_claims = pending_claims or {}
        deferred_windows = deferred_windows or {}
        route_registry = route_registry or {}
        active_pending = sorted(
            (
                (key, value)
                for key, value in pending_claims.items()
                if value.get("status") == "pending"
            ),
            key=lambda item: (str(item[1].get("first_failed_at", "")), item[0]),
        )
        record_limit = self.config.ransomlook.max_records_per_endpoint
        pending_quota = min(len(active_pending), max(1, record_limit // 5))
        selected_pending = dict(active_pending[:pending_quota])
        blocked_claim_keys = {
            self._claim_state_key_from_post(retry_post)
            for record in pending_claims.values()
            if record.get("status") == "blocked"
            if (retry_post := self._pending_claim_post(record)) is not None
        }
        active_deferred = sorted(
            (
                (key, value)
                for key, value in deferred_windows.items()
                if value.get("status") == "pending"
            ),
            key=lambda item: (str(item[1].get("first_failed_at", "")), item[0]),
        )
        posts: list[dict[str, Any]] = []
        newly_deferred: list[DeferredPostWindow] = []
        deferred_metadata: dict[str, dict[str, Any]] = {}
        resolved_deferred: set[str] = set()
        successful_ranges: set[tuple[str, str]] = set()
        deferred_attempts_remaining = self.config.ransomlook.max_pages_per_endpoint
        remaining_collection_budget = max(0, record_limit - pending_quota)
        for key, record in active_deferred:
            if remaining_collection_budget <= 0 or deferred_attempts_remaining <= 0:
                break
            deferred_attempts_remaining -= 1
            try:
                retry_start_date = self._canonical_deferred_date(record.get("start"))
                retry_end_date = self._canonical_deferred_date(record.get("end"))
                retry_start = self.converter.parse_timestamp(retry_start_date)
                retry_end = self.converter.parse_timestamp(retry_end_date)
            except (TypeError, ValueError):
                resolved_deferred.add(key)
                continue
            retry_batch = self.client.get_posts(
                retry_start,
                retry_end,
                record_budget=remaining_collection_budget,
            )
            if hasattr(retry_batch, "posts") and hasattr(
                retry_batch, "deferred_windows"
            ):
                posts.extend(retry_batch.posts)
                retry_deferred = list(retry_batch.deferred_windows)
            else:
                posts.extend(retry_batch)
                retry_deferred = []
            remaining_collection_budget = max(
                0, record_limit - pending_quota - len(posts)
            )
            resolved_deferred.add(key)
            if retry_deferred:
                for window in retry_deferred:
                    newly_deferred.append(window)
                    deferred_metadata[
                        self._deferred_window_key(window.start, window.end)
                    ] = dict(record)
            else:
                successful_ranges.add((retry_start_date, retry_end_date))

        normal_budget = max(0, record_limit - pending_quota - len(posts))
        batch = self.client.get_posts(start, end, record_budget=normal_budget)
        if hasattr(batch, "posts") and hasattr(batch, "deferred_windows"):
            posts.extend(batch.posts)
            newly_deferred.extend(batch.deferred_windows)
        else:  # compatibility for isolated adapters and test doubles
            posts.extend(batch)
        unique_deferred = {
            (
                self._canonical_deferred_date(window.start),
                self._canonical_deferred_date(window.end),
            ): window
            for window in newly_deferred
        }
        newly_deferred = [
            DeferredPostWindow(key[0], key[1], window.reason)
            for key, window in unique_deferred.items()
            if key not in successful_ranges
        ]
        deferred_metadata = {
            self._deferred_window_key(start_date, end_date): deferred_metadata.get(
                self._deferred_window_key(start_date, end_date), {}
            )
            for start_date, end_date in unique_deferred
            if (start_date, end_date) not in successful_ranges
        }

        for record in selected_pending.values():
            retry_post = self._pending_claim_post(record)
            if retry_post is None:
                continue
            retry_post["_ransomlook_retry"] = True
            posts.append(retry_post)

        self.metrics.fetched_posts = len(posts)
        grouped_posts: dict[
            str, tuple[str, list[tuple[dict[str, Any], str, datetime]]]
        ] = {}
        route_records: dict[
            str, dict[str, tuple[dict[str, Any], str, str, datetime]]
        ] = {}
        route_counts: dict[str, int] = {}

        for indexed_post in posts:
            identity = self._parse_indexed_post(indexed_post)
            if identity is None:
                self.metrics.skipped_posts += 1
                continue
            group_name, post_title, discovered = identity
            if not indexed_post.get(
                "_ransomlook_retry"
            ) and discovered > end + timedelta(minutes=5):
                self.helper.connector_logger.warning(
                    "Skipping RansomLook post with a future timestamp",
                    {"identity_sha256": self._identity_hash(group_name, post_title)},
                )
                self.metrics.skipped_posts += 1
                continue
            route_key = self.converter.claim_route_identity(
                {"group_name": group_name, "post_title": post_title}
            )
            discovered_key = discovered.isoformat()
            route_counts[route_key] = route_counts.get(route_key, 0) + 1
            route_bucket = route_records.setdefault(route_key, {})
            existing = route_bucket.get(discovered_key)
            if existing is not None:
                self.metrics.skipped_posts += 1
                existing_post, _, _, existing_discovered = existing
                if discovered >= existing_discovered:
                    indexed_post = self._merge_post_records(existing_post, indexed_post)
                    route_bucket[discovered_key] = (
                        indexed_post,
                        group_name,
                        post_title,
                        discovered,
                    )
                continue
            route_bucket[discovered_key] = (
                indexed_post,
                group_name,
                post_title,
                discovered,
            )

        route_updates: dict[str, dict[str, Any]] = {}
        claim_records: dict[str, tuple[dict[str, Any], str, str, datetime]] = {}
        ordered_records = sorted(
            (
                (route_key, discovered_key, record)
                for route_key, records in route_records.items()
                for discovered_key, record in records.items()
            ),
            key=lambda item: (
                not bool(item[2][0].get("_ransomlook_retry")),
                item[2][3],
                item[0],
                item[1],
            ),
        )
        now_iso = datetime.now(timezone.utc).isoformat()
        for (
            route_key,
            _discovered_key,
            (
                indexed_post,
                group_name,
                post_title,
                discovered,
            ),
        ) in ordered_records:
            route_state_key = self._claim_state_key(route_key)
            occurrences = self._route_registry_occurrences(
                route_registry.get(route_state_key)
            )
            source_ids = self._post_source_ids(indexed_post)
            if isinstance(indexed_post.get("_ransomlook_identity_discovered"), str):
                identity_discovered = self.converter.parse_timestamp(
                    indexed_post["_ransomlook_identity_discovered"]
                ).isoformat()
            else:
                identity_discovered = self._select_occurrence_identity(
                    occurrences,
                    discovered,
                    source_ids,
                    route_counts.get(route_key, 1),
                )
            indexed_post["_ransomlook_identity_discovered"] = identity_discovered
            occurrence_state_key = self._claim_state_key(identity_discovered)
            previous = occurrences.get(occurrence_state_key, {})
            aliases = sorted(
                set(
                    [
                        identity_discovered,
                        discovered.isoformat(),
                        *previous.get("aliases", []),
                    ]
                )
            )
            occurrences[occurrence_state_key] = {
                "identity_discovered": identity_discovered,
                "last_seen": now_iso,
                "aliases": aliases,
                "source_ids": sorted(
                    set([*previous.get("source_ids", []), *source_ids])
                )[:20],
            }
            route_updates[route_state_key] = {
                "last_seen": now_iso,
                "occurrences": occurrences,
            }
            state_key = self._claim_state_key_from_post(indexed_post)
            if state_key in blocked_claim_keys:
                self.metrics.skipped_posts += 1
                continue
            claim_key = self.converter.claim_identity(indexed_post)
            existing = claim_records.get(claim_key)
            if existing is not None:
                self.metrics.skipped_posts += 1
                existing_post, _, _, existing_discovered = existing
                if discovered >= existing_discovered:
                    claim_records[claim_key] = (
                        self._merge_post_records(existing_post, indexed_post),
                        group_name,
                        post_title,
                        discovered,
                    )
                continue
            claim_records[claim_key] = (
                indexed_post,
                group_name,
                post_title,
                discovered,
            )

        for claim_key, (
            indexed_post,
            group_name,
            post_title,
            discovered,
        ) in sorted(
            claim_records.items(),
            key=lambda item: (
                not bool(item[1][0].get("_ransomlook_retry")),
                item[1][3],
                item[0],
            ),
        ):
            del claim_key
            self.metrics.accepted_posts += 1
            key = self.converter.canonical_identity(group_name)
            display_name, group_posts = grouped_posts.setdefault(key, (group_name, []))
            group_posts.append((indexed_post, post_title, discovered))
            grouped_posts[key] = (display_name, group_posts)

        encountered = {key: value[0] for key, value in grouped_posts.items()}
        if self.config.ransomlook.enrich_actor_profiles:
            for key, name in pending_groups.items():
                grouped_posts.setdefault(key, (name, []))

        claims: list[Any] = []
        enrichments: list[GroupEnrichment] = []
        incomplete: dict[str, dict[str, Any]] = {}
        processed_keys: set[str] = set()
        actor_objects: dict[str, list[Any]] = {}
        actors_complete = True
        if self.config.ransomlook.enrich_actor_profiles:
            claim_request_reserve = sum(
                1 + len(group_posts)
                for _group_name, group_posts in grouped_posts.values()
                if group_posts
            )
            actor_objects, actors_complete = self._try_create_named_actor_profiles(
                {key for key in grouped_posts},
                request_reserve=claim_request_reserve,
            )
        group_order = sorted(
            grouped_posts,
            key=lambda key: (
                not any(
                    post.get("_ransomlook_retry")
                    for post, _, _ in grouped_posts[key][1]
                ),
                key,
            ),
        )
        for group_key in group_order:
            group_name, group_posts = grouped_posts[group_key]
            group_posts.sort(
                key=lambda item: (not bool(item[0].get("_ransomlook_retry")), item[2])
            )
            if self.client.remaining_requests <= 0:
                self._retain_request_budget_claims(
                    group_posts, incomplete, pending_claims
                )
                continue
            try:
                metadata, full_posts, group_complete = self._try_get_group_data(
                    group_name
                )
            except RansomLookCycleBudgetExhausted:
                self._retain_request_budget_claims(
                    group_posts, incomplete, pending_claims
                )
                continue
            full_post_index = self._index_full_posts(full_posts)
            claim_group = self.converter.create_group(
                group_name, metadata if group_complete else {}
            )

            prepared_posts: list[tuple[dict[str, Any], datetime]] = []
            retry_reasons: dict[str, list[str]] = {}
            for post_index, (indexed_post, post_title, discovered) in enumerate(
                group_posts
            ):
                state_key = self._claim_state_key_from_post(indexed_post)
                if self.client.remaining_requests <= 0:
                    self._retain_request_budget_claims(
                        group_posts[post_index:],
                        incomplete,
                        pending_claims,
                    )
                    break
                group_post = full_post_index.get((post_title, discovered), {})
                # The group history and date index are discovery mechanisms.  The
                # dedicated post endpoint is the authoritative claim-evidence
                # carrier and may be the only response containing description,
                # screen, and source (as in the lockbit5/magna.com.do record).
                try:
                    dedicated_post, detail_complete = self._get_post_data(
                        group_name, post_title
                    )
                except RansomLookCycleBudgetExhausted:
                    self._retain_request_budget_claims(
                        group_posts[post_index:],
                        incomplete,
                        pending_claims,
                    )
                    break
                post = {
                    **self._merge_post_records(
                        indexed_post, group_post, dedicated_post
                    ),
                    "group_name": group_name,
                    "post_title": post_title,
                    "discovered": discovered.isoformat(),
                    "_ransomlook_detail_complete": detail_complete,
                }
                prepared_posts.append((post, discovered))
                retry_reasons[self.converter.claim_identity(post)] = (
                    [] if detail_complete else ["detail"]
                )

            if group_posts and not prepared_posts:
                continue

            profile_leaks, claim_leaks, leak_complete = (
                self._try_create_group_leak_intelligence(
                    group_name, claim_group.id, [post for post, _ in prepared_posts]
                )
            )
            profile_analyses, claim_analyses, analyses_complete = (
                self._try_create_group_analysis_intelligence(
                    group_name, claim_group.id, [post for post, _ in prepared_posts]
                )
            )
            if not leak_complete or not analyses_complete:
                for reasons in retry_reasons.values():
                    reasons.append("claim-context")
            if group_posts:
                # Deliver the group before claim relationships and Reports that
                # reference it. This keeps bounded cross-bundle delivery ordered
                # even when several OpenCTI workers consume the work item.
                if len(claims) + 1 <= self.config.ransomlook.max_objects_per_run:
                    claims.append(claim_group)
                else:
                    for post, _discovered in prepared_posts:
                        state_key = self._claim_state_key_from_post(post)
                        incomplete[state_key] = self._claim_retry_record(
                            post,
                            ["object-budget"],
                            pending_claims.get(state_key),
                        )
                    continue

            for post, discovered in prepared_posts:
                claim_key = self.converter.claim_identity(post)
                claim_objects = self._create_claim_graph(
                    claim_group,
                    post,
                    discovered,
                    claim_leaks.get(claim_key, []),
                    claim_analyses.get(claim_key, []),
                    retry_reasons=retry_reasons[claim_key],
                )
                state_key = self._claim_state_key(claim_key)
                if (
                    len(claims) + len(claim_objects)
                    > self.config.ransomlook.max_objects_per_run
                ):
                    retry_reasons[claim_key].append("object-budget")
                    incomplete[state_key] = self._claim_retry_record(
                        post,
                        retry_reasons[claim_key],
                        pending_claims.get(state_key),
                    )
                    continue
                claims.extend(claim_objects)
                processed_keys.add(state_key)
                if retry_reasons[claim_key]:
                    incomplete[state_key] = self._claim_retry_record(
                        post,
                        retry_reasons[claim_key],
                        pending_claims.get(state_key),
                    )

            if self.config.ransomlook.enrich_actor_profiles:
                # Optional profile objects can still be produced when the group
                # detail endpoint fails. Include the deterministic baseline
                # Intrusion Set so every enrichment delivery remains a complete
                # logical graph instead of depending on an earlier claim run.
                enrichment_objects: list[Any] = [claim_group]
                complete = (
                    group_complete
                    and actors_complete
                    and leak_complete
                    and analyses_complete
                )
                enrichment_objects.extend(actor_objects.get(group_key, []))
                enrichment_objects.extend(profile_leaks)
                enrichment_objects.extend(profile_analyses)
                if group_complete:
                    try:
                        enriched_group = claim_group
                        infrastructure_budget_exhaustions = (
                            self.evidence.budget.exhausted
                        )
                        enrichment_objects.extend(
                            [
                                enriched_group,
                                *self._create_group_infrastructure(
                                    metadata, enriched_group.id, group_name
                                ),
                            ]
                        )
                        complete = complete and (
                            self.evidence.budget.exhausted
                            == infrastructure_budget_exhaustions
                        )
                        if self.config.ransomlook.import_notes:
                            notes, notes_complete = self._try_create_group_notes(
                                group_name, enriched_group.id
                            )
                            enrichment_objects.extend(notes)
                            complete = complete and notes_complete
                        if self.config.ransomlook.import_wallets:
                            wallets, wallets_complete = self._try_create_group_wallets(
                                group_name, enriched_group.id
                            )
                            enrichment_objects.extend(wallets)
                            complete = complete and wallets_complete
                    except Exception as exc:
                        self.helper.connector_logger.warning(
                            "Unable to convert optional RansomLook enrichment",
                            {
                                "group_sha256": self._identity_hash(group_name),
                                "error_type": self._error_kind(exc),
                            },
                        )
                        enrichment_objects = [
                            claim_group,
                            *actor_objects.get(group_key, []),
                        ]
                        complete = False
                enrichments.append(
                    GroupEnrichment(
                        group_key,
                        group_name,
                        self._with_attribution(enrichment_objects),
                        complete,
                    )
                )

        self.metrics.optional_skips += sum(
            1 for enrichment in enrichments if not enrichment.complete
        )

        return CollectionCycle(
            self._with_attribution(claims),
            enrichments,
            encountered,
            incomplete,
            processed_keys,
            newly_deferred,
            resolved_deferred,
            route_updates,
            deferred_metadata,
        )

    @staticmethod
    def _identity_hash(*values: str) -> str:
        """Return a bounded identifier suitable for logs, never source text."""
        return hashlib.sha256("\x00".join(values).encode()).hexdigest()[:16]

    @staticmethod
    def _claim_state_key(route_key: str) -> str:
        """Return a content-free stable key for persisted claim retry work."""
        return hashlib.sha256(route_key.encode()).hexdigest()

    def _claim_state_key_from_post(self, post: dict[str, Any]) -> str:
        """Return the persisted retry key for one claim occurrence."""
        return self._claim_state_key(self.converter.claim_identity(post))

    def _canonical_deferred_date(self, value: Any) -> str:
        """Normalize a deferred post-window boundary to its API date key."""
        return self.converter.parse_timestamp(str(value)).date().isoformat()

    @staticmethod
    def _post_source_ids(post: dict[str, Any]) -> set[str]:
        """Return explicit upstream IDs that can bind timestamp corrections."""
        return {
            f"{field}:{str(post[field]).strip()}"
            for field in ("id", "post_id", "uuid")
            if isinstance(post.get(field), (str, int)) and str(post[field]).strip()
        }

    def _route_registry_occurrences(
        self, record: dict[str, Any] | None
    ) -> dict[str, dict[str, Any]]:
        """Return normalized occurrence entries from persisted route state."""
        if not isinstance(record, dict):
            return {}
        raw_occurrences = record.get("occurrences")
        occurrences: dict[str, dict[str, Any]] = {}
        if isinstance(raw_occurrences, dict):
            for key, value in raw_occurrences.items():
                if not isinstance(key, str) or not isinstance(value, dict):
                    continue
                try:
                    identity_discovered = self.converter.parse_timestamp(
                        value.get("identity_discovered")
                    ).isoformat()
                    last_seen = self.converter.parse_timestamp(
                        value.get("last_seen")
                    ).isoformat()
                except (TypeError, ValueError):
                    continue
                aliases: list[str] = []
                for alias in value.get("aliases", []):
                    if not isinstance(alias, str):
                        continue
                    try:
                        aliases.append(
                            self.converter.parse_timestamp(alias).isoformat()
                        )
                    except (TypeError, ValueError):
                        continue
                source_ids = [
                    str(source_id)[:512]
                    for source_id in value.get("source_ids", [])
                    if isinstance(source_id, str) and source_id
                ][:20]
                occurrences[key] = {
                    "identity_discovered": identity_discovered,
                    "last_seen": last_seen,
                    "aliases": sorted(set([identity_discovered, *aliases])),
                    "source_ids": sorted(set(source_ids)),
                }
            return occurrences
        return {}

    def _select_occurrence_identity(
        self,
        occurrences: dict[str, dict[str, Any]],
        discovered: datetime,
        source_ids: set[str],
        incoming_route_count: int,
    ) -> str:
        """Choose the persisted occurrence timestamp for one observed row."""
        discovered_iso = discovered.isoformat()
        for occurrence in occurrences.values():
            aliases = set(occurrence.get("aliases", []))
            if discovered_iso == occurrence.get("identity_discovered") or (
                discovered_iso in aliases
            ):
                return str(occurrence["identity_discovered"])
        if source_ids:
            for occurrence in occurrences.values():
                if source_ids & set(occurrence.get("source_ids", [])):
                    return str(occurrence["identity_discovered"])
        if incoming_route_count == 1 and len(occurrences) == 1:
            occurrence = next(iter(occurrences.values()))
            try:
                existing = self.converter.parse_timestamp(
                    occurrence.get("identity_discovered")
                )
            except (TypeError, ValueError):
                return discovered_iso
            correction_window = timedelta(days=1)
            if abs(discovered - existing) <= correction_window:
                return str(occurrence["identity_discovered"])
        return discovered_iso

    @staticmethod
    def _pending_claim_post(record: dict[str, Any]) -> dict[str, Any] | None:
        """Rebuild one bounded index-shaped record from persisted retry state."""
        group_name = record.get("group_name")
        post_title = record.get("post_title")
        discovered = record.get("discovered")
        if not all(
            isinstance(value, str) and value
            for value in (group_name, post_title, discovered)
        ):
            return None
        result = {
            "group_name": group_name,
            "post_title": post_title,
            "discovered": discovered,
        }
        identity_discovered = record.get("identity_discovered")
        if isinstance(identity_discovered, str):
            result["_ransomlook_identity_discovered"] = identity_discovered
        context = record.get("context")
        if isinstance(context, dict):
            for key in ("id", "post_id", "uuid", "link", "website"):
                value = context.get(key)
                if isinstance(value, (str, int)) and str(value).strip():
                    result[key] = str(value).strip()[:4096]
        return result

    def _claim_retry_record(
        self,
        post: dict[str, Any],
        reasons: list[str],
        previous: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Build one bounded retry record, blocking terminal hot loops."""
        now = datetime.now(timezone.utc)
        previous = previous if isinstance(previous, dict) else {}
        attempts = min(
            self.config.ransomlook.max_claim_retries,
            int(previous.get("attempts", 0)) + 1,
        )
        first_failed_at = previous.get("first_failed_at")
        if not isinstance(first_failed_at, str):
            first_failed_at = now.isoformat()
        try:
            age = now - self.converter.parse_timestamp(first_failed_at)
        except (TypeError, ValueError):
            first_failed_at = now.isoformat()
            age = timedelta(0)
        status = "pending"
        if attempts >= self.config.ransomlook.max_claim_retries or age >= timedelta(
            days=self.config.ransomlook.retry_max_age_days
        ):
            status = "blocked"
        context: dict[str, str] = {}
        for key in ("id", "post_id", "uuid", "link", "website"):
            value = post.get(key)
            if isinstance(value, (str, int)) and str(value).strip():
                context[key] = str(value).strip()[:4096]
        return {
            "group_name": str(post["group_name"])[:512],
            "post_title": str(post["post_title"])[:1024],
            "discovered": self.converter.parse_timestamp(
                post.get("discovered")
            ).isoformat(),
            "identity_discovered": self.converter.parse_timestamp(
                post.get("_ransomlook_identity_discovered") or post.get("discovered")
            ).isoformat(),
            "context": context,
            "reasons": sorted(set(reasons)),
            "attempts": attempts,
            "first_failed_at": first_failed_at,
            "status": status,
        }

    def _deferred_window_key(self, start: str, end: str) -> str:
        start_date = self._canonical_deferred_date(start)
        end_date = self._canonical_deferred_date(end)
        return hashlib.sha256(f"{start_date}\x00{end_date}".encode()).hexdigest()

    @staticmethod
    def _clamped_attempts(value: Any, maximum: int) -> int | None:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return None
        return min(value, maximum)

    @staticmethod
    def _error_kind(exc: BaseException) -> str:
        """Classify failures without logging exception text or embedded URLs."""
        return type(exc).__name__

    def _log_run_metrics(self, outcome: str) -> None:
        """Emit one payload-free operational summary."""
        budget = self.evidence.budget
        self.helper.connector_logger.info(
            "RansomLook run metrics",
            {
                "outcome": outcome,
                "posts_fetched": self.metrics.fetched_posts,
                "posts_accepted": self.metrics.accepted_posts,
                "posts_skipped": self.metrics.skipped_posts,
                "objects_imported": self.metrics.imported_objects,
                "bundles_delivered": self.metrics.delivered_bundles,
                "optional_skips": self.metrics.optional_skips,
                "retry_state_evictions": self.metrics.retry_state_evictions,
                "revision_ledger_evictions": self.metrics.revision_ledger_evictions,
                "artifacts_accepted": budget.count,
                "artifacts_rejected": budget.rejected,
                "artifact_bytes_accepted": budget.bytes,
                "artifact_serialized_bytes_reserved": budget.serialized_bytes,
                "artifact_count_budget": budget.max_count,
                "artifact_byte_budget": budget.max_bytes,
                "artifact_serialized_byte_budget": budget.max_serialized_bytes,
                "request_attempts": self.client.request_attempts,
                "request_attempt_budget": self.client.max_requests_per_run,
                "run_duration_seconds": round(
                    max(0.0, time.monotonic() - self.client.run_started), 3
                ),
            },
        )

    def _try_create_named_actor_profiles(
        self, group_keys: set[str], request_reserve: int = 0
    ) -> tuple[dict[str, list[Any]], bool]:
        """Fetch named actors once and retain only explicit encountered-group links."""
        if not group_keys:
            return {}, True
        by_group: dict[str, list[Any]] = {key: [] for key in group_keys}
        request_reserve = max(0, request_reserve)
        if self.client.remaining_requests <= request_reserve:
            return by_group, False
        try:
            summaries = self.client.get_actors()
        except RansomLookCycleBudgetExhausted:
            return by_group, False
        except RansomLookCapabilityUnavailable as exc:
            self.helper.connector_logger.info(
                "Skipping unavailable RansomLook named-actor capability",
                {"capability": exc.capability, "status_code": exc.status_code},
            )
            return by_group, True
        except RansomLookAPIError as exc:
            self.helper.connector_logger.warning(
                "Unable to enumerate optional RansomLook named actors",
                {"error_type": self._error_kind(exc)},
            )
            return by_group, False

        complete = True
        seen: set[str] = set()
        for summary in summaries:
            actor_name = self.converter.actor_name(summary)
            if actor_name is None:
                self.metrics.optional_skips += 1
                continue
            actor_key = self.converter.canonical_identity(actor_name)
            if actor_key in seen:
                continue
            seen.add(actor_key)
            try:
                if self.client.remaining_requests <= request_reserve:
                    complete = False
                    break
                actor = {**summary, **self.client.get_actor(actor_name)}
                related_groups = {
                    self.converter.canonical_identity(name): name
                    for name in self.converter.actor_relation_names(actor, "groups")
                }
                matched = group_keys & related_groups.keys()
                if not matched:
                    continue
                objects = self._create_named_actor_graph(actor, related_groups, matched)
                for group_key in matched:
                    by_group[group_key].extend(objects[group_key])
            except RansomLookCycleBudgetExhausted:
                complete = False
                break
            except RansomLookCapabilityUnavailable as exc:
                self.helper.connector_logger.info(
                    "Skipping unavailable RansomLook named-actor detail",
                    {
                        "actor_sha256": self._identity_hash(actor_name),
                        "capability": exc.capability,
                        "status_code": exc.status_code,
                    },
                )
                # A known unavailable capability is not transient incomplete
                # work. Retrying every group cannot make it available.
                continue
            except RansomLookAPIError as exc:
                self.helper.connector_logger.warning(
                    "Unable to import optional RansomLook named actor",
                    {
                        "actor_sha256": self._identity_hash(actor_name),
                        "error_type": self._error_kind(exc),
                    },
                )
                complete = False
            except (ValueError, TypeError) as exc:
                self.metrics.optional_skips += 1
                self.helper.connector_logger.warning(
                    "Skipping malformed optional RansomLook named actor",
                    {
                        "actor_sha256": self._identity_hash(actor_name),
                        "error_type": self._error_kind(exc),
                    },
                )
        return by_group, complete

    def _create_named_actor_graph(
        self,
        actor: dict[str, Any],
        related_groups: dict[str, str],
        matched_groups: set[str],
    ) -> dict[str, list[Any]]:
        """Convert one actor and its explicit peer/forum/group relations."""
        named_actor = self.converter.create_named_actor(actor)
        if named_actor is None:
            raise ValueError("RansomLook named actor has no usable name")
        shared: list[Any] = [named_actor]
        for peer_name in self.converter.actor_relation_names(actor, "peers"):
            peer = self.converter.create_named_actor(
                {"name": peer_name}, related_stub=True
            )
            if peer is not None:
                shared.extend(
                    [
                        peer,
                        self.converter.create_profile_relationship(
                            named_actor.id, peer.id, "peer"
                        ),
                    ]
                )
        for forum_name in self.converter.actor_relation_names(actor, "forums"):
            forum = self.converter.create_actor_forum(forum_name)
            if forum is not None:
                shared.extend(
                    [
                        forum,
                        self.converter.create_profile_relationship(
                            named_actor.id, forum.id, "forum-or-market"
                        ),
                    ]
                )

        result: dict[str, list[Any]] = {}
        for group_key in matched_groups:
            group = self.converter.create_group(related_groups[group_key], {})
            result[group_key] = self._deduplicate(
                [
                    *shared,
                    self.converter.create_profile_relationship(
                        named_actor.id, group.id, "group"
                    ),
                ]
            )
        return result

    def _with_attribution(self, objects: list[Any]) -> list[Any]:
        if not objects:
            return []
        # Source Identity and marking must precede the objects that reference
        # them when a logical delivery is divided into bounded bundles.
        return self._deduplicate(
            [self.converter.author, self.converter.marking, *objects]
        )

    def _try_get_group_data(
        self, group_name: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
        """Fetch group data and retain whether optional enrichment completed."""
        try:
            metadata, posts = self.client.get_group(group_name)
            return metadata, posts, True
        except RansomLookAPIError as exc:
            self.helper.connector_logger.warning(
                "Unable to enrich RansomLook group; importing claims without "
                "group metadata",
                {
                    "group_sha256": self._identity_hash(group_name),
                    "error_type": self._error_kind(exc),
                },
            )
            return {}, [], False

    def _get_post_data(
        self, group_name: str, post_title: str
    ) -> tuple[dict[str, Any], bool]:
        """Fetch dedicated claim details with a fail-open summary fallback."""
        try:
            detail = self.client.get_post(group_name, post_title)
            return detail, bool(detail)
        except RansomLookAPIError as exc:
            self.helper.connector_logger.warning(
                "Unable to enrich RansomLook claim; importing index data",
                {
                    "identity_sha256": self._identity_hash(group_name, post_title),
                    "error_type": self._error_kind(exc),
                },
            )
            return {}, False

    @staticmethod
    def _merge_post_records(*records: dict[str, Any]) -> dict[str, Any]:
        """Merge progressively richer post records without empty-value erasure.

        RansomLook can repeat a post across the date index, group history, and
        dedicated post endpoint with different field coverage.  Later records
        take precedence only when they carry a meaningful value, so an empty
        summary field cannot erase dedicated description or evidence.
        """
        merged: dict[str, Any] = {}
        for record in records:
            for key, value in record.items():
                if value is None:
                    continue
                if isinstance(value, str) and not value.strip():
                    continue
                if isinstance(value, (list, dict)) and not value:
                    continue
                merged[key] = value
        return merged

    def _retain_request_budget_claims(
        self,
        posts: list[tuple[dict[str, Any], str, datetime]],
        incomplete: dict[str, dict[str, Any]],
        pending_claims: dict[str, dict[str, Any]],
    ) -> None:
        """Retain unprocessed indexed posts when the aggregate request budget ends."""
        for indexed_post, _post_title, _discovered in posts:
            state_key = self._claim_state_key_from_post(indexed_post)
            incomplete[state_key] = self._claim_retry_record(
                indexed_post,
                ["request-budget"],
                pending_claims.get(state_key),
            )

    def _try_create_group_notes(
        self, group_name: str, group_id: str
    ) -> tuple[list[Any], bool]:
        """Return notes and a completion flag for retry orchestration."""
        budget_exhaustions = self.evidence.budget.exhausted
        try:
            notes = self.client.get_group_notes(group_name)
        except RansomLookCycleBudgetExhausted:
            return [], False
        except RansomLookCapabilityUnavailable as exc:
            self.helper.connector_logger.info(
                "Skipping unavailable RansomLook notes capability",
                {"capability": exc.capability, "status_code": exc.status_code},
            )
            return [], True
        except RansomLookAPIError as exc:
            self.helper.connector_logger.warning(
                "Unable to import optional RansomLook notes",
                {
                    "group_sha256": self._identity_hash(group_name),
                    "error_type": self._error_kind(exc),
                },
            )
            return [], False
        objects: list[Any] = []
        complete = True
        seen: set[str] = set()
        for summary in notes:
            upstream_id = summary.get("id")
            detail = summary
            if isinstance(upstream_id, (str, int)) and str(upstream_id).strip():
                key = str(upstream_id).strip()
                if key in seen:
                    continue
                seen.add(key)
                try:
                    detail = {**summary, **self.client.get_note(key)}
                except RansomLookCycleBudgetExhausted:
                    complete = False
                    break
                except RansomLookCapabilityUnavailable as exc:
                    self.helper.connector_logger.info(
                        "Skipping unavailable RansomLook note detail",
                        {
                            "identifier_sha256": self._identity_hash(group_name, key),
                            "capability": exc.capability,
                            "status_code": exc.status_code,
                        },
                    )
                except RansomLookAPIError as exc:
                    self.helper.connector_logger.warning(
                        "Unable to import optional RansomLook note detail",
                        {
                            "identifier_sha256": self._identity_hash(group_name, key),
                            "error_type": self._error_kind(exc),
                        },
                    )
                    complete = False
            note = self.converter.create_note(detail, group_id)
            if note is None:
                continue
            objects.append(note)
            identifier = f"{group_name}:{upstream_id or note.id}"
            payload = self.evidence.decode_note_original(
                detail.get("content"), detail.get("format"), identifier
            )
            if payload is None:
                continue
            artifact = self.converter.create_evidence_artifact(payload)
            objects.extend(
                [
                    artifact,
                    self.converter.create_evidence_relationship(
                        artifact.id,
                        note.id,
                        "actor-profile-note",
                        identifier,
                        None,
                        self.converter._optional_timestamp(
                            detail.get("updated_at") or detail.get("updated")
                        ),
                    ),
                ]
            )
        complete = complete and self.evidence.budget.exhausted == budget_exhaustions
        return self._deduplicate(objects), complete

    def _try_create_group_wallets(
        self, group_name: str, group_id: str
    ) -> tuple[list[Any], bool]:
        """Return explicitly group-associated wallet context without Indicators."""
        try:
            crypto = self.client.get_group_crypto(group_name)
        except RansomLookCycleBudgetExhausted:
            return [], False
        except RansomLookCapabilityUnavailable as exc:
            self.helper.connector_logger.info(
                "Skipping unavailable RansomLook cryptocurrency capability",
                {"capability": exc.capability, "status_code": exc.status_code},
            )
            return [], True
        except RansomLookAPIError as exc:
            self.helper.connector_logger.warning(
                "Unable to import optional RansomLook cryptocurrency wallets",
                {
                    "group_sha256": self._identity_hash(group_name),
                    "error_type": self._error_kind(exc),
                },
            )
            return [], False
        objects: list[Any] = []
        by_chain = crypto.get("by_chain", {})
        for chain in sorted(by_chain, key=lambda value: str(value).casefold()):
            for wallet_data in by_chain[chain]:
                wallet = self.converter.create_wallet(wallet_data, str(chain))
                if wallet is None:
                    self.helper.connector_logger.warning(
                        "Skipping malformed RansomLook cryptocurrency wallet",
                        {
                            "group_sha256": self._identity_hash(group_name),
                            "chain_sha256": self._identity_hash(str(chain)),
                        },
                    )
                    continue
                objects.extend(
                    [
                        wallet,
                        self.converter.create_relationship(
                            group_id, "related-to", wallet.id
                        ),
                    ]
                )
        return self._deduplicate(objects), True

    @staticmethod
    def _explicit_relation_values(
        record: dict[str, Any], fields: tuple[str, ...]
    ) -> set[str]:
        """Extract bounded scalar identifiers from explicit relation fields."""
        result: set[str] = set()
        for field_name in fields:
            value = record.get(field_name)
            values = value if isinstance(value, list) else [value]
            for item in values:
                if isinstance(item, dict):
                    for key in ("id", "uuid", "post_id", "claim_id"):
                        nested = item.get(key)
                        if isinstance(nested, (str, int)) and str(nested).strip():
                            result.add(str(nested).strip())
                elif isinstance(item, (str, int)) and str(item).strip():
                    result.add(str(item).strip())
        return result

    @classmethod
    def _explicit_post_ids(cls, record: dict[str, Any]) -> set[str]:
        return cls._explicit_relation_values(
            record,
            (
                "post_id",
                "post_ids",
                "post_uuid",
                "claim_id",
                "claim_ids",
                "posts",
                "claims",
            ),
        )

    @staticmethod
    def _post_ids(post: dict[str, Any]) -> set[str]:
        return {
            str(post[field]).strip()
            for field in ("id", "post_id", "uuid")
            if isinstance(post.get(field), (str, int)) and str(post[field]).strip()
        }

    def _try_get_leak_details(
        self,
        group_name: str | None = None,
        posts: list[dict[str, Any]] | None = None,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Fetch the bounded leak corpus once per cycle with isolated details."""
        del group_name, posts
        if self._leak_cache is not None:
            return self._leak_cache
        try:
            summaries = self.client.get_leaks()
        except RansomLookCycleBudgetExhausted:
            self._leak_cache = ([], False)
            return self._leak_cache
        except RansomLookCapabilityUnavailable as exc:
            self.helper.connector_logger.info(
                "Skipping unavailable RansomLook leak capability",
                {"capability": exc.capability, "status_code": exc.status_code},
            )
            self._leak_cache = ([], True)
            return self._leak_cache
        except RansomLookAPIError as exc:
            self.helper.connector_logger.warning(
                "Unable to import optional RansomLook leaks",
                {"error_type": self._error_kind(exc)},
            )
            self._leak_cache = ([], False)
            return self._leak_cache
        records: list[dict[str, Any]] = []
        complete = True
        for summary in summaries:
            leak_id = summary.get("id") or summary.get("uuid")
            detail = summary
            if isinstance(leak_id, (str, int)) and str(leak_id).strip():
                try:
                    detail = {**summary, **self.client.get_leak(leak_id)}
                except RansomLookCycleBudgetExhausted:
                    complete = False
                    break
                except RansomLookCapabilityUnavailable as exc:
                    self.helper.connector_logger.info(
                        "Skipping unavailable RansomLook leak detail",
                        {
                            "identifier_sha256": self._identity_hash(str(leak_id)),
                            "capability": exc.capability,
                            "status_code": exc.status_code,
                        },
                    )
                except RansomLookAPIError as exc:
                    self.helper.connector_logger.warning(
                        "Unable to import optional RansomLook leak detail",
                        {
                            "identifier_sha256": self._identity_hash(str(leak_id)),
                            "error_type": self._error_kind(exc),
                        },
                    )
                    complete = False
            records.append(detail)
        self._leak_cache = (records, complete)
        return self._leak_cache

    def _try_create_group_leak_intelligence(
        self, group_name: str, group_id: str, posts: list[dict[str, Any]]
    ) -> tuple[list[Any], dict[str, list[Any]], bool]:
        """Create exact-scoped torrent/leak context without fuzzy assertions."""
        budget_exhaustions = self.evidence.budget.exhausted
        profile: list[Any] = []
        claims: dict[str, list[Any]] = {
            self.converter.claim_identity(post): [] for post in posts
        }
        complete = True
        records: list[tuple[str, dict[str, Any]]] = []
        nested_context_remaining = self.config.ransomlook.max_records_per_endpoint
        nested_context_skipped = 0
        if self.config.ransomlook.import_torrents:
            try:
                records.extend(
                    ("torrent", item) for item in self.client.get_torrents(group_name)
                )
            except RansomLookCycleBudgetExhausted:
                complete = False
            except RansomLookCapabilityUnavailable as exc:
                self.helper.connector_logger.info(
                    "Skipping unavailable RansomLook torrent capability",
                    {"capability": exc.capability, "status_code": exc.status_code},
                )
                # Capability absence is a stable skip, unlike a transport or
                # malformed-response failure which remains retryable.
                pass
            except RansomLookAPIError as exc:
                self.helper.connector_logger.warning(
                    "Unable to import optional RansomLook torrents",
                    {
                        "group_sha256": self._identity_hash(group_name),
                        "error_type": self._error_kind(exc),
                    },
                )
                complete = False
        if self.config.ransomlook.import_leaks:
            leaks, leaks_complete = self._try_get_leak_details(group_name, posts)
            records.extend(("leak", item) for item in leaks)
            complete = complete and leaks_complete

        canonical_group = self.converter.canonical_identity(group_name)
        reserve_claim_evidence = self.config.ransomlook.import_post_evidence and any(
            post.get("screen") is not None or post.get("source") is not None
            for post in posts
        )
        for kind, record in records:
            explicit_groups = self._explicit_relation_values(
                record, ("group", "groups", "ransomware_group", "ransomware_groups")
            )
            group_match = any(
                self.converter.canonical_identity(value) == canonical_group
                for value in explicit_groups
            )
            relation_post_ids = self._explicit_post_ids(record)
            matching_posts = [
                post
                for post in posts
                if relation_post_ids and self._post_ids(post) & relation_post_ids
            ]
            # Search/query results and name/domain similarity are not attribution.
            if not matching_posts and not group_match:
                continue

            if kind == "torrent":
                evidence = self.converter.create_magnet_observable(record)
            else:
                owner = (
                    self.converter.create_incident(matching_posts[0]).id
                    if matching_posts
                    else group_id
                )
                evidence = self.converter.create_leak_note(record, owner)
            if evidence is None:
                continue

            ancillary: list[Any] = []
            if kind == "torrent":
                webseed_values = self._explicit_relation_values(
                    record, ("webseed", "webseeds", "web_seeds", "url_list")
                )
                sorted_webseeds = sorted(webseed_values)
                selected_webseeds = sorted_webseeds[:nested_context_remaining]
                nested_context_remaining -= len(selected_webseeds)
                nested_context_skipped += len(sorted_webseeds) - len(selected_webseeds)
                for webseed in selected_webseeds:
                    for observable in self.converter.create_website_observables(
                        webseed
                    ):
                        ancillary.extend(
                            [
                                observable,
                                self.converter.create_relationship(
                                    observable.id, "related-to", evidence.id
                                ),
                            ]
                        )
                if self.config.ransomlook.import_torrent_peers:
                    peer_values = sorted(
                        self._explicit_relation_values(record, ("peer", "peers"))
                    )
                    selected_peers = peer_values[:nested_context_remaining]
                    nested_context_remaining -= len(selected_peers)
                    nested_context_skipped += len(peer_values) - len(selected_peers)
                    for peer_value in selected_peers:
                        peer = self.converter.create_torrent_peer(peer_value)
                        if peer is not None:
                            ancillary.extend(
                                [
                                    peer,
                                    self.converter.create_relationship(
                                        peer.id, "related-to", evidence.id
                                    ),
                                ]
                            )
                torrent_carrier = next(
                    (
                        record.get(field)
                        for field in ("torrent", "torrent_file", "metainfo")
                        if record.get(field) is not None
                    ),
                    None,
                )
                if torrent_carrier is not None and not reserve_claim_evidence:
                    payload = self.evidence.decode_torrent_file(
                        torrent_carrier, f"torrent:{evidence.x_ransomlook_infohash}"
                    )
                    if payload is not None:
                        artifact = self.converter.create_evidence_artifact(payload)
                        ancillary.extend(
                            [
                                artifact,
                                self.converter.create_direct_leak_relationship(
                                    artifact.id, evidence.id, "torrent-metainfo"
                                ),
                            ]
                        )

            if matching_posts:
                for post in matching_posts:
                    incident_id = self.converter.create_incident(post).id
                    claim_key = self.converter.claim_identity(post)
                    claim_evidence = evidence
                    if kind == "leak":
                        claim_evidence = self.converter.create_leak_note(
                            record, incident_id
                        )
                    claims[claim_key].extend(
                        [
                            claim_evidence,
                            *ancillary,
                            self.converter.create_direct_leak_relationship(
                                claim_evidence.id, incident_id, kind
                            ),
                        ]
                    )
            elif group_match and self.config.ransomlook.enrich_actor_profiles:
                profile.extend(
                    [
                        evidence,
                        *ancillary,
                        self.converter.create_direct_leak_relationship(
                            evidence.id, group_id, kind
                        ),
                    ]
                )
        if nested_context_skipped:
            self.helper.connector_logger.warning(
                "Skipping excess nested RansomLook torrent context",
                {
                    "group_sha256": self._identity_hash(group_name),
                    "limit": self.config.ransomlook.max_records_per_endpoint,
                    "skipped": nested_context_skipped,
                },
            )
        complete = complete and self.evidence.budget.exhausted == budget_exhaustions
        return (
            self._deduplicate(profile),
            {key: self._deduplicate(value) for key, value in claims.items()},
            complete,
        )

    def _try_create_group_analysis_intelligence(
        self, group_name: str, group_id: str, posts: list[dict[str, Any]]
    ) -> tuple[list[Any], dict[str, list[Any]], bool]:
        """Convert only explicit, supported technical-analysis structures.

        The official RansomLook Swagger currently exposes no JSON analysis route.
        The API client therefore raises a capability signal and this path performs
        no scraping or route guessing.  The converter contract is ready for a
        future observed adapter and is exercised by sanitized fixtures.
        """
        budget_exhaustions = self.evidence.budget.exhausted
        claims: dict[str, list[Any]] = {
            self.converter.claim_identity(post): [] for post in posts
        }
        if not self.config.ransomlook.import_analyses:
            return [], claims, True
        try:
            analyses = self.client.get_group_analyses(group_name)
        except RansomLookCycleBudgetExhausted:
            return [], claims, False
        except RansomLookCapabilityUnavailable as exc:
            self.helper.connector_logger.info(
                "Skipping unavailable RansomLook analysis capability",
                {"capability": exc.capability, "status_code": exc.status_code},
            )
            # Capability absence is a known upstream state, not incomplete work
            # that should keep every group permanently pending.
            return [], claims, True
        except RansomLookAPIError as exc:
            self.helper.connector_logger.warning(
                "Unable to import optional RansomLook analyses",
                {
                    "group_sha256": self._identity_hash(group_name),
                    "error_type": self._error_kind(exc),
                },
            )
            return [], claims, False

        profile: list[Any] = []
        complete = True
        for analysis in analyses:
            try:
                converted = self._create_analysis_graph(analysis, group_id)
            except (TypeError, ValueError) as exc:
                self.helper.connector_logger.warning(
                    "Skipping malformed RansomLook technical analysis",
                    {
                        "group_sha256": self._identity_hash(group_name),
                        "error_type": self._error_kind(exc),
                    },
                )
                complete = False
                continue
            if not converted:
                complete = False
                continue
            relation_post_ids = self._explicit_post_ids(analysis)
            matching_posts = [
                post
                for post in posts
                if relation_post_ids and self._post_ids(post) & relation_post_ids
            ]
            if matching_posts:
                for post in matching_posts:
                    claims[self.converter.claim_identity(post)].extend(converted)
            else:
                profile.extend(converted)
        complete = complete and self.evidence.budget.exhausted == budget_exhaustions
        return (
            self._deduplicate(profile),
            {key: self._deduplicate(value) for key, value in claims.items()},
            complete,
        )

    def _create_analysis_graph(
        self, analysis: dict[str, Any], group_id: str
    ) -> list[Any]:
        """Build one bounded graph without inferring malware, TTPs, or IOCs."""
        identity = self.converter.analysis_identity(analysis)
        if identity is None:
            return []
        objects: list[Any] = []
        report_refs = [group_id]

        for value in (
            analysis.get("malware", [])
            if isinstance(analysis.get("malware"), list)
            else []
        ):
            malware = self.converter.create_analysis_malware(value)
            if malware is None:
                continue
            relation = self.converter.create_relationship(group_id, "uses", malware.id)
            objects.extend([malware, relation])
            report_refs.extend([malware.id, relation.id])

        techniques = analysis.get("attack_patterns")
        if not isinstance(techniques, list):
            techniques = analysis.get("ttps")
        for value in techniques if isinstance(techniques, list) else []:
            technique = self.converter.create_analysis_attack_pattern(value)
            if technique is None:
                continue
            relation = self.converter.create_relationship(
                group_id, "uses", technique.id
            )
            objects.extend([technique, relation])
            report_refs.extend([technique.id, relation.id])

        observables = analysis.get("observables")
        for value in observables if isinstance(observables, list) else []:
            observable = self.converter.create_analysis_observable(value)
            if observable is None:
                continue
            relation = self.converter.create_relationship(
                observable.id, "related-to", group_id
            )
            objects.extend([observable, relation])
            report_refs.extend([observable.id, relation.id])
            if self.config.ransomlook.create_indicators:
                indicator = self.converter.create_analysis_indicator(value, observable)
                if indicator is not None:
                    indicates = self.converter.create_relationship(
                        indicator.id, "indicates", observable.id
                    )
                    objects.extend([indicator, indicates])
                    report_refs.extend([indicator.id, indicates.id])

        carrier = next(
            (
                analysis.get(field)
                for field in ("document", "document_base64")
                if analysis.get(field) is not None
            ),
            None,
        )
        artifact = None
        if carrier is not None:
            payload = self.evidence.decode_analysis_document(
                carrier,
                analysis.get("document_mime_type") or analysis.get("format"),
                f"analysis:{identity}",
            )
            if payload is not None:
                artifact = self.converter.create_evidence_artifact(payload)
                objects.append(artifact)
                report_refs.append(artifact.id)

        report = self.converter.create_analysis_report(analysis, report_refs)
        if report is None:
            return []
        objects.append(report)
        if artifact is not None:
            objects.append(
                self.converter.create_evidence_relationship(
                    artifact.id,
                    report.id,
                    "actor-profile-analysis",
                    identity,
                    None,
                    self.converter._optional_timestamp(
                        analysis.get("published") or analysis.get("created")
                    ),
                )
            )
        return self._deduplicate(objects)

    def _create_group_infrastructure(
        self, metadata: dict[str, Any], group_id: str, group_name: str | None = None
    ) -> list[Any]:
        """Create typed actor-profile infrastructure for one ransomware group."""
        if not self.config.ransomlook.import_infrastructure:
            return []
        locations = metadata.get("locations")
        if not isinstance(locations, list):
            return []
        objects: list[Any] = []
        effective_group_name = group_name or group_id
        for location in locations:
            if not isinstance(location, dict):
                continue
            roles = self.converter.location_roles(location)
            if not self.config.ransomlook.import_sensitive_infrastructure and any(
                role in {"private", "file-server", "chat", "admin"} for role in roles
            ):
                continue
            converted = self.converter.create_location_infrastructure(
                effective_group_name, location
            )
            if not converted:
                continue
            infrastructure = converted[0]
            objects.extend(
                [
                    *converted,
                    self.converter.create_relationship(
                        group_id, "uses", infrastructure.id
                    ),
                ]
            )
            if self.config.ransomlook.import_location_evidence:
                objects.extend(
                    self._create_evidence(
                        location,
                        "location",
                        f"{effective_group_name}:{self.converter.location_identity(location.get('slug'))}",
                        infrastructure.id,
                        self.config.ransomlook.max_artifacts_per_location,
                        location.get("slug"),
                        self.converter._optional_timestamp(location.get("lastscrape")),
                    )
                )
        return self._deduplicate(objects)

    def _create_claim_graph(
        self,
        group: Any,
        post: dict[str, Any],
        discovered: datetime,
        direct_leak_objects: list[Any] | None = None,
        direct_analysis_objects: list[Any] | None = None,
        retry_reasons: list[str] | None = None,
    ) -> list[Any]:
        """Create one narrowly scoped graph for an observed ransomware claim."""
        victim = self.converter.create_victim(post["post_title"])
        incident = self.converter.create_incident(post)
        relationship_time = self.converter.claim_identity_timestamp(post)
        base_objects = [
            victim,
            incident,
            self.converter.create_relationship(
                incident.id, "attributed-to", group.id, relationship_time
            ),
            self.converter.create_relationship(
                incident.id, "targets", victim.id, relationship_time
            ),
        ]

        # The upstream post location is direct claim context. It belongs to this
        # Incident, not to every claim made by the same operation.
        post_link = self.converter.normalize_source_url(post.get("link"))
        for observable in self.converter.create_website_observables(post_link):
            base_objects.extend(
                [
                    observable,
                    self.converter.create_relationship(
                        observable.id, "related-to", incident.id, relationship_time
                    ),
                ]
            )

        if self.config.ransomlook.import_victim_websites:
            for observable in self.converter.create_website_observables(
                post.get("website")
            ):
                base_objects.extend(
                    [
                        observable,
                        self.converter.create_relationship(
                            observable.id, "related-to", victim.id, relationship_time
                        ),
                    ]
                )
        if self.config.ransomlook.import_post_evidence:
            accepted_evidence: list[EvidencePayload] = []
            evidence_objects = self._create_evidence(
                post,
                "claim",
                self.converter.claim_identity(post),
                incident.id,
                self.config.ransomlook.max_artifacts_per_claim,
                post_link,
                relationship_time,
                accepted_evidence,
                retry_reasons,
            )
        else:
            accepted_evidence = []
            evidence_objects = []
        direct_objects = self._deduplicate(
            [*(direct_leak_objects or []), *(direct_analysis_objects or [])]
        )

        def build_claim(
            evidence: list[Any],
            payloads: list[EvidencePayload],
            direct: list[Any],
        ) -> list[Any]:
            objects = self._deduplicate([*base_objects, *evidence, *direct])
            report_refs = [group.id, *(obj.id for obj in objects)]
            return [
                *objects,
                self.converter.create_report(post, report_refs, payloads),
            ]

        claim_objects = build_claim(evidence_objects, accepted_evidence, direct_objects)
        identity_hash = self._identity_hash(
            str(post.get("group_name", "")), str(post.get("post_title", ""))
        )
        if direct_objects and not self._claim_delivery_fits(group, claim_objects):
            self.metrics.optional_skips += 1
            self.helper.connector_logger.warning(
                "Skipping optional RansomLook claim context that exceeds delivery "
                "bounds",
                {
                    "identity_sha256": identity_hash,
                    "objects_skipped": len(direct_objects),
                },
            )
            direct_objects = []
            claim_objects = build_claim(
                evidence_objects, accepted_evidence, direct_objects
            )

        if evidence_objects and not self._claim_delivery_fits(group, claim_objects):
            self.metrics.optional_skips += 1
            self.helper.connector_logger.warning(
                "Skipping RansomLook claim evidence that exceeds delivery bounds",
                {
                    "identity_sha256": identity_hash,
                    "artifacts_skipped": len(accepted_evidence),
                },
            )
            evidence_objects = []
            accepted_evidence = []
            claim_objects = build_claim(
                evidence_objects, accepted_evidence, direct_objects
            )

        if not self._claim_delivery_fits(group, claim_objects):
            raise ValueError("RansomLook core claim exceeds configured delivery bounds")
        return claim_objects

    def _claim_delivery_fits(self, group: Any, claim_objects: list[Any]) -> bool:
        """Return whether one complete Report closure fits its transport bounds."""
        closure = self._with_attribution([group, *claim_objects])
        if len(closure) > self.config.ransomlook.max_objects_per_bundle:
            return False
        byte_limit = self.config.ransomlook.max_bundle_size_mb * 1024 * 1024
        estimated_bytes = (
            2048
            + (2 * len(closure))
            + sum(len(item.serialize().encode("utf-8")) for item in closure)
        )
        return estimated_bytes <= byte_limit

    def _create_evidence(
        self,
        record: dict[str, Any],
        scope: str,
        upstream_identifier: str,
        owner_id: str,
        item_limit: int,
        source_url: str | None,
        observed: datetime | None,
        accepted_payloads: list[EvidencePayload] | None = None,
        retry_reasons: list[str] | None = None,
    ) -> list[Any]:
        """Create passive evidence and owner/source relationships, fail-open."""
        objects: list[Any] = []
        source_objects = self.converter.create_website_observables(source_url)
        source_urls = [obj for obj in source_objects if obj.type == "url"]
        accepted = 0
        for kind in ("screen", "source"):
            value = record.get(kind)
            if value is None:
                continue
            if accepted >= item_limit:
                self.helper.connector_logger.warning(
                    "Skipping rejected RansomLook evidence",
                    {
                        "scope": scope,
                        "kind": kind,
                        "identifier_sha256": hashlib.sha256(
                            upstream_identifier.encode()
                        ).hexdigest()[:16],
                        "reason": "per-owner artifact count limit exhausted",
                    },
                )
                continue
            representations = 1
            if scope == "claim":
                representations = 3 if kind == "screen" else 2
            payload = self.evidence.decode(
                value,
                kind,
                scope,
                upstream_identifier,
                representations=representations,
            )
            if payload is None:
                if retry_reasons is not None and self.evidence.last_rejection_retryable:
                    retry_reasons.append("evidence-budget")
                continue
            accepted += 1
            if accepted_payloads is not None:
                accepted_payloads.append(payload)
            artifact = self.converter.create_evidence_artifact(payload)
            objects.extend(
                [
                    artifact,
                    self.converter.create_evidence_relationship(
                        artifact.id,
                        owner_id,
                        scope,
                        upstream_identifier,
                        source_url,
                        observed,
                    ),
                ]
            )
            for url in source_urls:
                objects.append(
                    self.converter.create_relationship(
                        artifact.id, "related-to", url.id, observed
                    )
                )
        return objects

    def _index_full_posts(
        self, posts: list[dict[str, Any]]
    ) -> dict[tuple[str, datetime], dict[str, Any]]:
        """Index detailed group posts for constant-time claim matching."""
        index: dict[tuple[str, datetime], dict[str, Any]] = {}
        for post in posts:
            title = post.get("post_title")
            if not isinstance(title, str):
                continue
            try:
                discovered = self.converter.parse_timestamp(post.get("discovered"))
            except (TypeError, ValueError):
                continue
            index[(title.strip(), discovered)] = post
        return index

    def _parse_indexed_post(
        self, post: dict[str, Any]
    ) -> tuple[str, str, datetime] | None:
        """Validate the identity fields of a lightweight post.

        Args:
            post: Lightweight RansomLook post record.

        Returns:
            Group, title, and normalized discovery time, or ``None`` if invalid.
        """
        group_name = post.get("group_name")
        post_title = post.get("post_title")
        if (
            not isinstance(group_name, str)
            or not group_name.strip()
            or not isinstance(post_title, str)
            or not post_title.strip()
        ):
            self.helper.connector_logger.warning(
                "Skipping incomplete RansomLook post",
                {
                    "group_name_type": type(group_name).__name__,
                    "post_title_type": type(post_title).__name__,
                },
            )
            return None
        group_name = group_name.strip()
        post_title = post_title.strip()
        if len(group_name) > 512 or len(post_title) > 1024:
            self.helper.connector_logger.warning(
                "Skipping RansomLook post with oversized identity fields",
                {
                    "group_name_length": len(group_name),
                    "post_title_length": len(post_title),
                },
            )
            return None
        try:
            discovered = self.converter.parse_timestamp(post.get("discovered"))
        except (TypeError, ValueError):
            self.helper.connector_logger.warning(
                "Skipping RansomLook post with invalid timestamp",
                {"identity_sha256": self._identity_hash(group_name, post_title)},
            )
            return None
        return group_name, post_title, discovered

    @staticmethod
    def _object_fingerprint(item: Any) -> str:
        """Hash canonical object content while excluding its version timestamp."""
        data = json.loads(item.serialize())
        data.pop("modified", None)
        return hashlib.sha256(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _version_objects(
        self,
        objects: list[Any],
        ledger: dict[str, dict[str, str]],
        observed_at: datetime,
        retention_at: datetime | None = None,
    ) -> tuple[list[Any], dict[str, dict[str, str]]]:
        """Advance mutable SDO versions and stage a post-delivery ledger.

        The caller commits the returned ledger only after OpenCTI worker
        reconciliation.  Failed delivery therefore cannot consume a revision.
        """
        staged = deepcopy(ledger)
        retention_at = retention_at or observed_at
        result: list[Any] = []
        for item in objects:
            item_type = getattr(item, "type", None)
            modified = getattr(item, "modified", None)
            if not isinstance(item_type, str) or modified is None:
                result.append(item)
                continue
            fingerprint = self._object_fingerprint(item)
            state_key = hashlib.sha256(item.id.encode()).hexdigest()
            current_modified = self.converter.parse_timestamp(str(modified))
            previous = staged.get(state_key)
            chosen = current_modified
            if isinstance(previous, dict):
                try:
                    prior_modified = self.converter.parse_timestamp(
                        previous.get("modified")
                    )
                except (TypeError, ValueError):
                    prior_modified = self.converter.SOURCE_EPOCH
                if previous.get("fingerprint") == fingerprint:
                    chosen = max(current_modified, prior_modified)
                else:
                    chosen = max(
                        current_modified,
                        prior_modified + timedelta(milliseconds=1),
                        observed_at,
                    )
            if chosen > current_modified:
                item = stix2.new_version(item, modified=chosen)
            staged[state_key] = {
                "fingerprint": fingerprint,
                "modified": chosen.isoformat(),
                "object_type": item_type,
                "last_seen": retention_at.isoformat(),
                "prunable": (
                    "true"
                    if self._is_prunable_version_entry(item, item_type)
                    else "false"
                ),
            }
            result.append(item)
        return result, self._compact_revision_ledger(staged)

    def _is_prunable_version_entry(self, item: Any, item_type: str) -> bool:
        """Return whether replay-bounded claim history may be LRU-pruned."""
        if item_type == "incident":
            return True
        if item_type == "report":
            return not hasattr(item, "x_ransomlook_analysis_id")
        if item_type == "relationship":
            source_ref = getattr(item, "source_ref", "")
            target_ref = getattr(item, "target_ref", "")
            return str(source_ref).startswith("incident--") or str(
                target_ref
            ).startswith("incident--")
        return False

    def _compact_revision_ledger(
        self, ledger: dict[str, dict[str, str]]
    ) -> dict[str, dict[str, str]]:
        """LRU-compact version history instead of creating a capacity cliff."""
        if len(ledger) <= self.REVISION_LEDGER_MAX_ENTRIES:
            return ledger
        target = max(1, int(self.REVISION_LEDGER_MAX_ENTRIES * 0.9))
        nonprunable = {
            key: value
            for key, value in ledger.items()
            if value.get("prunable") != "true"
        }
        prunable = {
            key: value
            for key, value in ledger.items()
            if value.get("prunable") == "true"
        }
        if len(nonprunable) >= target:
            compacted = dict(nonprunable)
            removed = len(prunable)
            protected_evictions = max(
                0,
                len(compacted) - self.REVISION_LEDGER_MAX_ENTRIES,
            )
            if protected_evictions:
                ordered = sorted(
                    compacted.items(),
                    key=lambda item: (
                        str(item[1].get("last_seen", "")),
                        item[0],
                    ),
                )
                removed_keys = {key for key, _ in ordered[:protected_evictions]}
                compacted = {
                    key: value
                    for key, value in compacted.items()
                    if key not in removed_keys
                }
                removed += protected_evictions
            self.metrics.revision_ledger_evictions += removed
            if removed:
                self.helper.connector_logger.warning(
                    "Compacted bounded RansomLook revision ledger",
                    {
                        "evicted": removed,
                        "evicted_nonprunable": protected_evictions,
                        "limit": self.REVISION_LEDGER_MAX_ENTRIES,
                    },
                )
            return compacted
        ordered = sorted(
            prunable.items(),
            key=lambda item: (
                str(item[1].get("last_seen", "")),
                item[0],
            ),
        )
        remove = max(0, len(ledger) - target)
        removed_keys = {key for key, _ in ordered[:remove]}
        compacted = {
            key: value for key, value in ledger.items() if key not in removed_keys
        }
        self.metrics.revision_ledger_evictions += remove
        self.helper.connector_logger.warning(
            "Compacted bounded RansomLook revision ledger",
            {"evicted": remove, "limit": self.REVISION_LEDGER_MAX_ENTRIES},
        )
        return compacted

    def _next_pending_claims(
        self,
        current: dict[str, dict[str, Any]],
        cycle: CollectionCycle,
    ) -> dict[str, dict[str, Any]]:
        result = deepcopy(current)
        for key in cycle.processed_claim_keys:
            result.pop(key, None)
        result.update(deepcopy(cycle.incomplete_claims))
        return self._compact_retry_records(
            result,
            self.config.ransomlook.max_pending_claims,
            "claim",
        )

    def _compact_retry_records(
        self,
        records: dict[str, dict[str, Any]],
        limit: int,
        scope: str,
    ) -> dict[str, dict[str, Any]]:
        """Retain a deterministic bounded retry/dead-letter sample without halting."""
        if len(records) <= limit:
            return records
        ordered = sorted(
            records.items(),
            key=lambda item: (
                item[1].get("status") != "pending",
                str(item[1].get("first_failed_at", "")),
                item[0],
            ),
        )
        compacted = dict(ordered[:limit])
        removed_records = [value for _, value in ordered[limit:]]
        removed = len(records) - len(compacted)
        if scope in {
            "claim",
            "deferred-window",
            "claim-state-load",
            "deferred-window-state-load",
        } and any(record.get("status") == "pending" for record in removed_records):
            self._unsafe_claim_cursor = True
        self.metrics.retry_state_evictions += removed
        self.helper.connector_logger.warning(
            "Compacted bounded RansomLook retry state",
            {"scope": scope, "evicted": removed, "limit": limit},
        )
        return compacted

    def _next_deferred_windows(
        self,
        current: dict[str, dict[str, Any]],
        cycle: CollectionCycle,
        now: datetime,
    ) -> dict[str, dict[str, Any]]:
        result = deepcopy(current)
        for key in cycle.resolved_deferred_keys:
            result.pop(key, None)
        for window in cycle.deferred_windows:
            key = self._deferred_window_key(window.start, window.end)
            previous = (
                cycle.deferred_window_metadata.get(key)
                or current.get(key)
                or result.get(key)
                or {}
            )
            attempts = min(
                self.config.ransomlook.max_claim_retries,
                int(previous.get("attempts", 0)) + 1,
            )
            first_failed_at = previous.get("first_failed_at")
            if not isinstance(first_failed_at, str):
                first_failed_at = now.isoformat()
            status = (
                "blocked"
                if attempts >= self.config.ransomlook.max_claim_retries
                else "pending"
            )
            try:
                if now - self.converter.parse_timestamp(first_failed_at) >= timedelta(
                    days=self.config.ransomlook.retry_max_age_days
                ):
                    status = "blocked"
            except (TypeError, ValueError):
                first_failed_at = now.isoformat()
            start_date = self._canonical_deferred_date(window.start)
            end_date = self._canonical_deferred_date(window.end)
            result[key] = {
                "start": start_date,
                "end": end_date,
                "reason": window.reason[:128],
                "attempts": attempts,
                "first_failed_at": first_failed_at,
                "status": status,
            }
        return self._compact_retry_records(
            result,
            self.config.ransomlook.max_pending_claims,
            "deferred-window",
        )

    def _next_route_registry(
        self,
        current: dict[str, dict[str, Any]],
        cycle: CollectionCycle,
        now: datetime,
    ) -> dict[str, dict[str, Any]]:
        """Retain only recent route aliases needed for timestamp corrections."""
        cutoff = now - timedelta(days=self.config.ransomlook.retry_max_age_days)
        result: dict[str, dict[str, str]] = {}
        for key, value in current.items():
            try:
                last_seen = self.converter.parse_timestamp(value.get("last_seen"))
            except (TypeError, ValueError):
                continue
            if last_seen >= cutoff:
                result[key] = deepcopy(value)
        result.update(deepcopy(cycle.route_registry_updates))
        if len(result) > self.ROUTE_REGISTRY_MAX_ENTRIES:
            ordered = sorted(
                result.items(),
                key=lambda item: (item[1]["last_seen"], item[0]),
                reverse=True,
            )
            removed = len(result) - self.ROUTE_REGISTRY_MAX_ENTRIES
            result = dict(ordered[: self.ROUTE_REGISTRY_MAX_ENTRIES])
            self.metrics.retry_state_evictions += removed
        return result

    def _group_retry_record(
        self,
        name: str,
        previous: dict[str, Any] | None,
        *,
        failed: bool,
        now: datetime,
    ) -> dict[str, Any]:
        previous = previous if isinstance(previous, dict) else {}
        attempts = min(
            self.config.ransomlook.max_enrichment_retries,
            int(previous.get("attempts", 0)) + (1 if failed else 0),
        )
        first_failed_at = previous.get("first_failed_at")
        if failed and not isinstance(first_failed_at, str):
            first_failed_at = now.isoformat()
        status = "pending"
        if attempts >= self.config.ransomlook.max_enrichment_retries:
            status = "blocked"
        if isinstance(first_failed_at, str):
            try:
                age = now - self.converter.parse_timestamp(first_failed_at)
                if age >= timedelta(days=self.config.ransomlook.retry_max_age_days):
                    status = "blocked"
            except (TypeError, ValueError):
                first_failed_at = now.isoformat()
        return {
            "name": name[:512],
            "attempts": attempts,
            "first_failed_at": first_failed_at,
            "status": status,
        }

    def process_message(self) -> None:
        """Run one collection cycle and update state only after successful delivery.

        Raises:
            Exception: Propagates collection or OpenCTI delivery failures after
                structured logging and work-item finalization.
        """
        now = datetime.now(timezone.utc)
        self._working_state = None
        self._unsafe_claim_cursor = False
        outcome = "failed"
        try:
            start, end = self._window(now)
            self.helper.connector_logger.info(
                "Starting RansomLook import",
                {"start": start.isoformat(), "end": end.isoformat()},
            )
            state = self._load_state()
            self._working_state = deepcopy(state)
            pending_claims = deepcopy(state["claims"].get("pending_claims", {}))
            deferred_windows = deepcopy(state["claims"].get("deferred_windows", {}))
            route_registry = deepcopy(state["claims"].get("route_registry", {}))
            pending_group_records = deepcopy(
                state["enrichment"].get("pending_groups", {})
            )
            if self.config.ransomlook.enrich_actor_profiles:
                pending_group_names = {
                    key: record["name"]
                    for key, record in pending_group_records.items()
                    if record.get("status") == "pending"
                }
            else:
                pending_group_names = {}
            cycle = self._collect_cycle(
                start,
                end,
                pending_group_names,
                pending_claims,
                deferred_windows,
                route_registry,
            )
            next_claims = self._next_pending_claims(pending_claims, cycle)
            next_deferred = self._next_deferred_windows(deferred_windows, cycle, now)
            next_routes = self._next_route_registry(route_registry, cycle, now)
            ledger = deepcopy(state["claims"].get("revision_ledger", {}))
            if cycle.claims:
                versioned_claims, staged_ledger = self._version_objects(
                    cycle.claims, ledger, now, retention_at=end
                )
                _, bundles_sent = self._deliver_objects(
                    versioned_claims,
                    f"RansomLook claims {start.isoformat()} to {end.isoformat()}",
                )
                ledger = staged_ledger
                message = (
                    f"Imported {len(cycle.claims)} claim STIX objects in "
                    f"{bundles_sent} bundle(s)"
                )
                self.helper.connector_logger.info(message)
            else:
                message = "No new RansomLook intelligence found"
                self.helper.connector_logger.info(message)

            if self.config.ransomlook.enrich_actor_profiles:
                for key, name in cycle.encountered_groups.items():
                    pending_group_records.setdefault(
                        key,
                        self._group_retry_record(
                            name,
                            None,
                            failed=False,
                            now=now,
                        ),
                    )
            else:
                pending_group_records = {}
            pending_group_records = self._compact_retry_records(
                pending_group_records,
                self.config.ransomlook.max_pending_groups,
                "actor-profile",
            )
            claims_end = None if self._unsafe_claim_cursor else end
            if claims_end is None:
                self.helper.connector_logger.warning(
                    "Retaining RansomLook claims cursor because retry state overflowed",
                    {"retry_state_evictions": self.metrics.retry_state_evictions},
                )
            self._save_state(
                claims_end=claims_end,
                pending_claims=next_claims,
                deferred_windows=next_deferred,
                route_registry=next_routes,
                pending_groups=pending_group_records,
                revision_ledger=ledger,
            )

            for enrichment in cycle.enrichments:
                delivered = False
                staged_ledger = ledger
                try:
                    if enrichment.objects:
                        versioned, staged_ledger = self._version_objects(
                            enrichment.objects, ledger, now
                        )
                        self._deliver_objects(
                            versioned,
                            f"RansomLook actor profile {enrichment.name}",
                        )
                    delivered = True
                except Exception as exc:  # optional delivery is isolated
                    self.metrics.optional_skips += 1
                    self.helper.connector_logger.warning(
                        "Unable to deliver optional RansomLook enrichment",
                        {
                            "group_sha256": self._identity_hash(enrichment.name),
                            "error_type": self._error_kind(exc),
                        },
                    )
                if delivered and enrichment.complete:
                    pending_group_records.pop(enrichment.key, None)
                    ledger = staged_ledger
                else:
                    pending_group_records[enrichment.key] = self._group_retry_record(
                        enrichment.name,
                        pending_group_records.get(enrichment.key),
                        failed=True,
                        now=now,
                    )
                    pending_group_records = self._compact_retry_records(
                        pending_group_records,
                        self.config.ransomlook.max_pending_groups,
                        "actor-profile",
                    )
                    if delivered:
                        ledger = staged_ledger
                self._save_state(
                    pending_groups=pending_group_records,
                    revision_ledger=ledger,
                )

            active_pending = any(
                record.get("status") == "pending"
                for record in pending_group_records.values()
            )
            if not active_pending:
                self._save_state(
                    enrichment_end=end,
                    pending_groups=pending_group_records,
                    revision_ledger=ledger,
                )
            outcome = "success"
        except Exception as exc:
            self.helper.connector_logger.error(
                "RansomLook import failed", {"error_type": self._error_kind(exc)}
            )
            raise
        finally:
            self._log_run_metrics(outcome)
            self._working_state = None

    def _validated_delivery_bundles(self, objects: list[Any]) -> Iterator[str]:
        """Validate one graph and stream bounded dependency-complete bundles."""
        if not objects:
            raise ValueError("RansomLook logical delivery contains no objects")

        object_ids: set[str] = set()
        object_by_id: dict[str, Any] = {}
        ordered_ids: list[str] = []
        for item in objects:
            item_id = getattr(item, "id", None)
            if not isinstance(item_id, str) or item_id in object_ids:
                raise ValueError("RansomLook logical delivery has invalid object IDs")
            object_ids.add(item_id)
            object_by_id[item_id] = item
            ordered_ids.append(item_id)

        dependencies: dict[str, set[str]] = {}
        serialized_sizes: dict[str, int] = {}
        for item in objects:
            serialized = item.serialize()
            serialized_sizes[item.id] = len(serialized.encode("utf-8"))
            data = json.loads(serialized)
            item_dependencies: set[str] = set()
            for key, value in data.items():
                if key.endswith("_ref"):
                    references = [value]
                elif key.endswith("_refs") and isinstance(value, list):
                    references = value
                else:
                    continue
                if any(
                    isinstance(reference, str) and reference not in object_ids
                    for reference in references
                ):
                    raise ValueError(
                        "RansomLook logical delivery contains unresolved STIX "
                        "dependencies"
                    )
                item_dependencies.update(
                    reference
                    for reference in references
                    if isinstance(reference, str) and reference != item.id
                )
            dependencies[item.id] = item_dependencies

        object_limit = self.config.ransomlook.max_objects_per_bundle
        byte_limit = self.config.ransomlook.max_bundle_size_mb * 1024 * 1024
        referenced_ids = {
            dependency
            for item_dependencies in dependencies.values()
            for dependency in item_dependencies
        }
        roots = [item_id for item_id in ordered_ids if item_id not in referenced_ids]
        covered: set[str] = set()
        chunks: list[set[str]] = []
        current_chunk: set[str] = set()

        def closure(root: str) -> set[str]:
            result: set[str] = set()
            pending = [root]
            while pending:
                item_id = pending.pop()
                if item_id in result:
                    continue
                result.add(item_id)
                pending.extend(dependencies[item_id] - result)
            return result

        def add_closure(root: str) -> None:
            nonlocal current_chunk
            dependency_closure = closure(root)
            if len(dependency_closure) > object_limit:
                raise ValueError(
                    "RansomLook dependency closure exceeds the object limit"
                )
            if closure_size(dependency_closure) > byte_limit:
                raise ValueError(
                    "RansomLook dependency closure exceeds the serialized byte limit"
                )
            combined = current_chunk | dependency_closure
            if current_chunk and (
                len(combined) > object_limit or closure_size(combined) > byte_limit
            ):
                chunks.append(current_chunk)
                current_chunk = set()
            current_chunk.update(dependency_closure)
            covered.update(dependency_closure)

        def closure_size(item_ids: set[str]) -> int:
            # Allow for the bundle wrapper, separators, and sequence metadata in
            # addition to the already serialized objects. The final exact check
            # below remains authoritative.
            return (
                2048
                + (2 * len(item_ids))
                + sum(serialized_sizes[item_id] for item_id in item_ids)
            )

        for root in roots:
            add_closure(root)
        # Cyclic graphs have no sink root. Cover any remaining strongly connected
        # portion as one closure, duplicating already covered dependencies when
        # necessary so every submitted bundle remains independently complete.
        for item_id in ordered_ids:
            if item_id not in covered:
                add_closure(item_id)
        if current_chunk:
            chunks.append(current_chunk)

        for chunk_ids in chunks:
            bundle = self.helper.stix2_create_bundle(
                [
                    object_by_id[item_id]
                    for item_id in ordered_ids
                    if item_id in chunk_ids
                ]
            )
            if len(bundle.encode("utf-8")) > byte_limit:
                raise ValueError(
                    "RansomLook dependency bundle exceeds the serialized byte limit"
                )
            yield bundle

    def _wait_for_work_completion(self, work_id: str, submitted_bundles: int) -> None:
        """Reconcile one multipart work with a connector-owned hard timeout."""
        timeout = self.config.ransomlook.work_reconciliation_timeout_seconds
        deadline = time.monotonic() + timeout
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("OpenCTI work reconciliation timed out")
            work = self.helper.api.work.get_work(work_id)
            if not isinstance(work, dict):
                raise RuntimeError("OpenCTI returned invalid work state")
            errors = work.get("errors")
            if isinstance(errors, list) and errors:
                raise RuntimeError("OpenCTI worker reported import errors")
            status = work.get("status")
            if status == "complete":
                tracking = work.get("tracking")
                if not isinstance(tracking, dict):
                    raise RuntimeError("OpenCTI work has no import tracking")
                expected = tracking.get("import_expected_number")
                processed = tracking.get("import_processed_number")
                if (
                    not isinstance(expected, int)
                    or not isinstance(processed, int)
                    or expected < submitted_bundles
                    or processed < expected
                ):
                    raise RuntimeError(
                        "OpenCTI work completed with incomplete tracking"
                    )
                return
            if status in {"error", "cancelled"}:
                raise RuntimeError("OpenCTI work did not complete successfully")
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))

    def _deliver_objects(self, objects: list[Any], name: str) -> tuple[str | None, int]:
        """Deliver one atomic work unit and close its work item."""
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, name, is_multipart=True
        )
        try:
            bundles = self._validated_delivery_bundles(objects)
            sent = 0
            for bundle in bundles:
                # Each bounded input is dependency-complete. Keep it atomic so
                # concurrent workers cannot process a Report before one of the
                # Relationships in the same closure.
                self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                    no_split=True,
                )
                sent += 1
            if work_id is not None:
                self.helper.api.work.to_processed(
                    work_id,
                    f"Imported {len(objects)} STIX objects in {sent} bundle(s)",
                )
                self._wait_for_work_completion(work_id, sent)
            self.metrics.imported_objects += len(objects)
            self.metrics.delivered_bundles += sent
            return work_id, sent
        except Exception:
            if work_id is not None:
                try:
                    self.helper.api.work.to_processed(
                        work_id, "RansomLook bundle delivery failed", in_error=True
                    )
                except Exception as work_exc:
                    self.helper.connector_logger.error(
                        "Unable to close failed RansomLook work item",
                        {"error_type": self._error_kind(work_exc)},
                    )
            raise

    def _load_state(self) -> dict[str, Any]:
        """Return bounded state v4 while preserving forward-compatible keys."""
        raw = self.helper.get_state()
        state = dict(raw) if isinstance(raw, dict) else {}
        claims = state.get("claims")
        if not isinstance(claims, dict):
            claims = {}
        enrichment = state.get("enrichment")
        if not isinstance(enrichment, dict):
            enrichment = {}

        def valid_key(value: Any) -> bool:
            return (
                isinstance(value, str)
                and len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
            )

        def valid_attempts(value: Any, maximum: int = 100) -> bool:
            return (
                isinstance(value, int)
                and not isinstance(value, bool)
                and 0 <= value <= maximum
            )

        def normalized_timestamp(value: Any, *, optional: bool = False) -> str | None:
            if optional and value is None:
                return None
            try:
                return self.converter.parse_timestamp(value).isoformat()
            except (TypeError, ValueError):
                return None

        raw_pending_claims = claims.get("pending_claims")
        if not isinstance(raw_pending_claims, dict):
            raw_pending_claims = {}
        pending_claims: dict[str, dict[str, Any]] = {}
        for _key, value in raw_pending_claims.items():
            if (
                not isinstance(value, dict)
                or value.get("status") not in {"pending", "blocked"}
                or not isinstance(value.get("group_name"), str)
                or not 0 < len(value["group_name"]) <= 512
                or not isinstance(value.get("post_title"), str)
                or not 0 < len(value["post_title"]) <= 1024
                or normalized_timestamp(value.get("discovered")) is None
                or not valid_attempts(value.get("attempts"))
            ):
                continue
            attempts = min(value["attempts"], self.config.ransomlook.max_claim_retries)
            first_failed_at = normalized_timestamp(
                value.get("first_failed_at"), optional=True
            )
            if value.get("first_failed_at") is not None and first_failed_at is None:
                continue
            reasons = value.get("reasons")
            if not isinstance(reasons, list) or not all(
                isinstance(reason, str) and 0 < len(reason) <= 64
                for reason in reasons[:10]
            ):
                continue
            context = value.get("context")
            if not isinstance(context, dict):
                context = {}
            safe_context = {
                name: str(context[name])[:4096]
                for name in ("id", "post_id", "uuid", "link", "website")
                if isinstance(context.get(name), (str, int))
                and str(context[name]).strip()
            }
            record = {
                "group_name": value["group_name"],
                "post_title": value["post_title"],
                "discovered": normalized_timestamp(value.get("discovered")),
                "identity_discovered": normalized_timestamp(
                    value.get("identity_discovered") or value.get("discovered")
                ),
                "context": safe_context,
                "reasons": sorted(set(reasons[:10])),
                "attempts": attempts,
                "first_failed_at": first_failed_at,
                "status": (
                    "blocked"
                    if attempts >= self.config.ransomlook.max_claim_retries
                    else value["status"]
                ),
            }
            retry_post = self._pending_claim_post(record)
            if retry_post is None:
                continue
            pending_claims[self._claim_state_key_from_post(retry_post)] = record
        pending_claims = self._compact_retry_records(
            pending_claims,
            self.config.ransomlook.max_pending_claims,
            "claim-state-load",
        )

        raw_deferred = claims.get("deferred_windows")
        if not isinstance(raw_deferred, dict):
            raw_deferred = {}
        deferred_windows: dict[str, dict[str, Any]] = {}
        for _key, value in raw_deferred.items():
            if (
                not isinstance(value, dict)
                or value.get("status") not in {"pending", "blocked"}
                or normalized_timestamp(value.get("start")) is None
                or normalized_timestamp(value.get("end")) is None
                or not valid_attempts(value.get("attempts"))
            ):
                continue
            first_failed_at = normalized_timestamp(value.get("first_failed_at"))
            if first_failed_at is None:
                continue
            start_date = self._canonical_deferred_date(value.get("start"))
            end_date = self._canonical_deferred_date(value.get("end"))
            attempts = min(value["attempts"], self.config.ransomlook.max_claim_retries)
            key = self._deferred_window_key(start_date, end_date)
            deferred_windows[key] = {
                "start": start_date,
                "end": end_date,
                "reason": str(value.get("reason", "unknown"))[:128],
                "attempts": attempts,
                "first_failed_at": first_failed_at,
                "status": (
                    "blocked"
                    if attempts >= self.config.ransomlook.max_claim_retries
                    else value["status"]
                ),
            }
        deferred_windows = self._compact_retry_records(
            deferred_windows,
            self.config.ransomlook.max_pending_claims,
            "deferred-window-state-load",
        )

        raw_ledger = claims.get("revision_ledger")
        if not isinstance(raw_ledger, dict):
            raw_ledger = {}
        revision_ledger: dict[str, dict[str, str]] = {}
        for key, value in raw_ledger.items():
            if (
                not valid_key(key)
                or not isinstance(value, dict)
                or not valid_key(value.get("fingerprint"))
                or normalized_timestamp(value.get("modified")) is None
            ):
                continue
            object_type = value.get("object_type")
            if not isinstance(object_type, str) or not 0 < len(object_type) <= 64:
                object_type = "unknown"
            last_seen = normalized_timestamp(
                value.get("last_seen") or value.get("modified")
            )
            if last_seen is None:
                continue
            revision_ledger[key] = {
                "fingerprint": value["fingerprint"],
                "modified": normalized_timestamp(value.get("modified")),
                "object_type": object_type,
                "last_seen": last_seen,
                "prunable": "true" if value.get("prunable") == "true" else "false",
            }
        revision_ledger = self._compact_revision_ledger(revision_ledger)

        raw_routes = claims.get("route_registry")
        if not isinstance(raw_routes, dict):
            raw_routes = {}
        route_registry: dict[str, dict[str, Any]] = {}
        for key, value in raw_routes.items():
            if not valid_key(key) or not isinstance(value, dict):
                continue
            last_seen = normalized_timestamp(value.get("last_seen"))
            occurrences = self._route_registry_occurrences(value)
            if not occurrences:
                continue
            if last_seen is None:
                last_seen = max(
                    str(occurrence["last_seen"])
                    for occurrence in occurrences.values()
                    if isinstance(occurrence.get("last_seen"), str)
                )
            route_registry[key] = {
                "last_seen": last_seen,
                "occurrences": occurrences,
            }
        if len(route_registry) > self.ROUTE_REGISTRY_MAX_ENTRIES:
            route_registry = dict(
                sorted(
                    route_registry.items(),
                    key=lambda item: (item[1]["last_seen"], item[0]),
                    reverse=True,
                )[: self.ROUTE_REGISTRY_MAX_ENTRIES]
            )

        raw_pending_groups = enrichment.get("pending_groups")
        if not isinstance(raw_pending_groups, dict):
            raw_pending_groups = {}
        pending_groups: dict[str, dict[str, Any]] = {}
        for key, value in raw_pending_groups.items():
            if not isinstance(key, str):
                continue
            if (
                isinstance(value, dict)
                and isinstance(value.get("name"), str)
                and 0 < len(value["name"]) <= 512
                and value.get("status") in {"pending", "blocked"}
                and valid_attempts(value.get("attempts"))
            ):
                first_failed_at = normalized_timestamp(
                    value.get("first_failed_at"), optional=True
                )
                if value.get("first_failed_at") is not None and first_failed_at is None:
                    continue
                attempts = min(
                    value["attempts"], self.config.ransomlook.max_enrichment_retries
                )
                pending_groups[key] = {
                    "name": value["name"],
                    "attempts": attempts,
                    "first_failed_at": first_failed_at,
                    "status": (
                        "blocked"
                        if attempts >= self.config.ransomlook.max_enrichment_retries
                        else value["status"]
                    ),
                }
        pending_groups = self._compact_retry_records(
            pending_groups,
            self.config.ransomlook.max_pending_groups,
            "actor-profile-state-load",
        )

        claims["pending_claims"] = pending_claims
        claims["deferred_windows"] = deferred_windows
        claims["revision_ledger"] = revision_ledger
        claims["route_registry"] = route_registry
        enrichment["pending_groups"] = pending_groups
        state.update(
            {
                "state_version": self.STATE_VERSION,
                "claims": claims,
                "enrichment": enrichment,
            }
        )
        return state

    def _save_state(
        self,
        claims_end: datetime | None = None,
        enrichment_end: datetime | None = None,
        pending_groups: dict[str, dict[str, Any]] | None = None,
        pending_claims: dict[str, dict[str, Any]] | None = None,
        deferred_windows: dict[str, dict[str, Any]] | None = None,
        route_registry: dict[str, dict[str, Any]] | None = None,
        revision_ledger: dict[str, dict[str, str]] | None = None,
    ) -> None:
        """Persist independent progress while retaining forward-compatible keys."""
        cached = getattr(self, "_working_state", None)
        state = deepcopy(cached) if isinstance(cached, dict) else self._load_state()
        if claims_end is not None:
            state["claims"]["last_successful_run"] = claims_end.isoformat()
        if enrichment_end is not None:
            state["enrichment"]["last_successful_run"] = enrichment_end.isoformat()
        if pending_groups is not None:
            state["enrichment"]["pending_groups"] = deepcopy(pending_groups)
        if pending_claims is not None:
            state["claims"]["pending_claims"] = deepcopy(pending_claims)
        if deferred_windows is not None:
            state["claims"]["deferred_windows"] = deepcopy(deferred_windows)
        if route_registry is not None:
            state["claims"]["route_registry"] = deepcopy(route_registry)
        if revision_ledger is not None:
            state["claims"]["revision_ledger"] = deepcopy(revision_ledger)
        self._working_state = deepcopy(state)
        self.helper.set_state(state)

    def run(self) -> None:
        """Start the OpenCTI helper's interval scheduler."""
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
