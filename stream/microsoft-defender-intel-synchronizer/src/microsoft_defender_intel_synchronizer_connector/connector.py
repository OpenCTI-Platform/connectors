"""Microsoft Defender Intel Synchronizer Connector main class."""

import json
import re
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Final

from .api_handler import DefenderApiHandler
from .config_variables import ConfigConnector
from .rbac_scope import (
    RbacConfigError,
    resolve_rbac_scope_or_abort,
)
from .types import RBACScope, ScopeKey
from .utils import (
    FILE_HASH_TYPES_MAPPER,
    defender_certificate_dedup_key,
    defender_file_dedup_key,
    indicator_value,
    is_defender_supported_domain,
)

EPOCH_UTC: Final = datetime(1970, 1, 1, tzinfo=timezone.utc)


def safe_confidence(item):
    """Returns integer confidence value, defaulting to 0 on error."""
    try:
        return int(item.get("confidence", 0))
    except (ValueError, TypeError):
        return 0


def parse_modified(item):
    """Parse an ISO modified timestamp to datetime (UTC)."""
    value = item.get("modified")

    if not value:
        return EPOCH_UTC

    try:
        # normalize trailing Z to +00:00 so fromisoformat works
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return EPOCH_UTC

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt if dt >= EPOCH_UTC else EPOCH_UTC


# Hash-based Defender indicator types are keyed on hex fingerprints.
# Defender preserves whatever case the value was first submitted with,
# so a tenant that previously ran with an uppercase-emitting pipeline
# will return ``ABCDEF…`` here while the connector now emits
# ``abcdef…`` (``_convert_indicator_to_observables`` / the
# ``defender_*_dedup_key`` helpers in ``utils`` both already
# ``.lower()`` the extracted hash). Without normalising both sides of
# the dedup key the planner would treat the two forms as different
# indicators and re-create a duplicate on every sync cycle.
# Lower-casing here is safe (hex hashes are case-insensitive by
# definition) and stripping is defensive for any whitespace Defender
# might round-trip.
_HASH_INDICATOR_TYPES: Final = frozenset(
    {"FileSha1", "FileSha256", "FileMd5", "CertificateThumbprint"}
)


def _normalize_indicator_value(indicator_type: str, value: Any) -> str:
    """Canonicalise an indicator value for the dedup key.

    For hash-based ``indicator_type`` values the function returns
    ``value.strip().lower()`` so that ``ABCDEF…`` and ``abcdef…``
    collapse to the same key. For every other indicator type the
    value is returned unchanged (it was already canonicalised by
    ``indicator_value()`` earlier in the pipeline).

    Non-string inputs (``None`` / unexpected shapes from a Defender
    response) collapse to the empty string so callers do not need
    to defensively type-check before building the key.
    """
    if not isinstance(value, str):
        return ""
    if indicator_type in _HASH_INDICATOR_TYPES:
        return value.strip().lower()
    return value


def _normalize_scope_ids_from_def(ind: dict[str, Any]) -> tuple[int, ...]:
    """Return the Defender indicator's RBAC scope ids as a sorted tuple.

    Empty / missing / non-int-coercible values collapse to ``()``,
    matching the "tenant-wide" scope key shape used elsewhere in the
    planner.
    """
    ids = ind.get("rbacGroupIds") or []
    try:
        return tuple(sorted(int(x) for x in ids))
    except (ValueError, TypeError):
        return tuple()


def key_from_def(ind: dict[str, Any]) -> ScopeKey:
    """Compute the dedup key for a Defender-side indicator.

    Returns ``(indicatorType, normalised_value, scope_ids)`` where
    ``normalised_value`` is case-folded for hash-based types so
    upper-case ``indicatorValue`` round-trips from older Defender
    runs do not produce duplicate keys for the same hash. See
    :func:`_normalize_indicator_value` for the normalisation
    contract.
    """
    indicator_type = ind.get("indicatorType", "")
    return (
        indicator_type,
        _normalize_indicator_value(indicator_type, ind.get("indicatorValue", "")),
        _normalize_scope_ids_from_def(ind),
    )


def key_from_candidate(
    indicator_type: str,
    indicator_value: str,
    rbac_scope_pair: RBACScope | None,
) -> ScopeKey:
    """Compute the dedup key for an OpenCTI-side candidate.

    Mirrors :func:`key_from_def` so the planner can look up an
    OpenCTI candidate in the same ``ScopeKey``-indexed dict it
    populated from the Defender response. The hash-value
    normalisation applied here keeps the two key spaces aligned
    regardless of case differences from upstream feeds.
    """
    scope_ids = [] if not rbac_scope_pair else rbac_scope_pair[1]
    normalised_value = _normalize_indicator_value(indicator_type, indicator_value)
    try:
        return (
            indicator_type,
            normalised_value,
            tuple(sorted(int(x) for x in scope_ids)),
        )
    except (ValueError, TypeError):
        return (indicator_type, normalised_value, tuple())


def sort_key(item: dict) -> tuple:
    """
    Sort key used by the connector:
      1) collection rank (first-configured = highest priority)
      2) confidence (highest first)
      3) modified (newest first)
    This mirrors the logic used in run().
    """
    rank = int(item.get("_collection_rank", sys.maxsize))
    conf = safe_confidence(item)
    mod = parse_modified(item)  # datetime

    return (
        rank,  # smaller rank first
        -conf,  # higher confidence first
        -mod.timestamp(),  # newer first
    )


def chunker_list(a, n):
    """
    Split a list into chunks of size n.
    :param a: List to be split
    :param n: Size of each chunk
    :return: List of chunks
    """
    return [a[i : i + n] for i in range(0, len(a), n)]


class MicrosoftDefenderIntelSynchronizerConnector:
    """
    Specifications of the Stream connector

    This class encapsulates the main actions, expected to be run by any stream connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector has the capability to listen to live streams from the OpenCTI platform.
    It is highly useful for creating connectors that can react and make decisions in real time.
    Actions on OpenCTI will apply the changes to the third-party connected platform
    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.
    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = self.config.helper
        self.api = DefenderApiHandler(self.helper, self.config)
        if not self.api.preflight():
            self.helper.connector_logger.error(
                "Preflight checks failed; connector will not run."
            )
            time.sleep(120)
            sys.exit(1)
        self._rbac_map: dict[str, int] = {}

    def _convert_indicator_to_observables(
        self, node: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Convert a GraphQL indicator node into Defender-ready observables.

        - Extracts observable (type, value) pairs from STIX-like pattern strings.
        - Normalizes and refangs values using indicator_value().
        - Merges parent indicator metadata (score, confidence, valid_until, etc.)
        into each observable so downstream logic has full context.

        Returns a list of enriched observable dicts; returns an empty list on error.
        """
        try:
            node = dict(node)
            # Normalize timestamps so downstream logic (sorting/state) works uniformly
            node.setdefault("created", node.get("created_at"))
            node.setdefault("modified", node.get("updated_at"))

            entity_type = (node.get("entity_type") or "").lower()
            observables: list[dict[str, Any]] = []

            # Skip expired indicators early (observables do not have valid_until)
            if entity_type == "indicator":
                valid_until = node.get("valid_until")
                if isinstance(valid_until, str):
                    try:
                        vu = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                        if vu <= datetime.now(timezone.utc):
                            return []
                    except (ValueError, TypeError):
                        # these are expected and happen too often to log
                        pass

                pattern = node.get("pattern") or ""
                mot = (node.get("x_opencti_main_observable_type") or "").lower()

                # File hashes
                # Enforce single-observable contract: prefer SHA-256, then SHA-1.
                # If a file hash is found we will NOT extract other atomic observables
                # from the same STIX pattern (prevents file-hash + domain duplicates).
                found_atomic = False
                if m := re.search(
                    r"\[file:hashes\.'SHA-256'\s*=\s*'([A-Fa-f0-9]{64})'\]",
                    pattern,
                ):
                    observables.append(
                        {"type": "file", "hashes": {"sha256": m.group(1).lower()}}
                    )
                    found_atomic = True
                elif m := re.search(
                    r"\[file:hashes\.'SHA-1'\s*=\s*'([A-Fa-f0-9]{40})'\]",
                    pattern,
                ):
                    observables.append(
                        {"type": "file", "hashes": {"sha1": m.group(1).lower()}}
                    )
                    found_atomic = True

                # Atomics
                # Intentional design: this connector emits at most one observable per STIX pattern.
                # STIX patterns may contain multiple atoms (AND/OR) and even multiple supported
                # observable types, but Microsoft Defender indicators are single-valued.
                # To enforce that contract, we extract only the first supported observable found
                # in the pattern and ignore any additional matches.
                # We use re.search (not findall/finditer) and break on first match deliberately.
                if not found_atomic:
                    regexes: list[tuple[str, str]] = [
                        ("url", r"\[url:value\s*=\s*'([^']+)'\]"),
                        ("domain-name", r"\[domain-name:value\s*=\s*'([^']+)'\]"),
                        ("domain-name", r"\[hostname:value\s*=\s*'([^']+)'\]"),
                        ("ipv4-addr", r"\[ipv4-addr:value\s*=\s*'([^']+)'\]"),
                        ("ipv6-addr", r"\[ipv6-addr:value\s*=\s*'([^']+)'\]"),
                    ]
                    for typ, rx in regexes:
                        if m := re.search(rx, pattern):
                            observables.append({"type": typ, "value": m.group(1)})
                            # Stop after the first match for supported types
                            break

                # Fallback when pattern missing but name + type are explicit
                if (
                    not observables
                    and (name := node.get("name"))
                    and isinstance(name, str)
                ):
                    # Normalize Hostname to domain-name
                    if mot == "hostname":
                        mot = "domain-name"
                    if mot in {"domain-name", "url", "ipv4-addr", "ipv6-addr"}:
                        observables.append({"type": mot, "value": name})
            else:
                # Observable nodes (globalSearch) carry the atomic value directly.
                #
                # ``entity_type`` arrives lower-cased from the caller but the
                # OpenCTI GraphQL layer is inconsistent about hyphenation: the
                # ``__typename`` of an observable node comes back as the
                # hyphenated STIX type (``ipv4-addr``, ``ipv6-addr``,
                # ``x509-certificate``, …) for some entry points and as the
                # non-hyphenated camel-case-stripped form (``ipv4addr``,
                # ``ipv6addr``, ``x509certificate``, …) for others. Looking up
                # only one of the two forms silently drops every observable
                # of the other shape, so we normalise by stripping ``-`` from
                # the key before lookup — both ``ipv4-addr`` and ``ipv4addr``
                # then map to the same Defender indicator type.
                type_map = {
                    "domainname": "domain-name",
                    "hostname": "domain-name",  # Normalize hostname to domain-name for Defender
                    "url": "url",
                    "ipv4addr": "ipv4-addr",
                    "ipv6addr": "ipv6-addr",
                    "emailaddr": "email-addr",
                    "hashedobservable": "file",
                    "x509certificate": "x509-certificate",
                }
                obs_type = type_map.get(entity_type.replace("-", ""))
                if not obs_type:
                    return []

                # Prefer explicit observable_value, fall back to name when available
                value = node.get("observable_value") or node.get("name")

                # File/hash handling
                if obs_type in {"file", "x509-certificate"}:
                    hashes: dict[str, str] = {}
                    for h in node.get("hashes", []) or []:
                        algo = str(h.get("algorithm", "")).lower()
                        hash_val = h.get("hash")
                        if not hash_val:
                            continue
                        mapped = FILE_HASH_TYPES_MAPPER.get(algo)
                        if mapped:
                            hashes[mapped] = str(hash_val).lower()
                    if hashes:
                        observables.append({"type": obs_type, "hashes": hashes})
                elif value:
                    observables.append({"type": obs_type, "value": value})

                # Some observables expose description via x_opencti_description
                if node.get("x_opencti_description") and not node.get("description"):
                    node["description"] = node.get("x_opencti_description")

            # Normalize non-file values
            cleaned: list[dict[str, Any]] = []
            for ob in observables:
                if ob["type"] in {"file", "x509-certificate"}:
                    cleaned.append(ob)
                    continue

                if v := indicator_value(ob["value"]):
                    ob["value"] = v

                    if ob["type"] == "domain-name" and not is_defender_supported_domain(
                        ob["value"]
                    ):
                        # Skip invalid domain starting with underscore
                        # (e.g., _sip._tls.example.com) which are not supported by Defender
                        continue

                    cleaned.append(ob)

            # --- Merge parent node fields into each observable ---
            merged: list[dict[str, Any]] = []
            for ob in cleaned:
                merged.append(
                    node | ob
                )  # merges node metadata and observable atomically

            return merged

        except (ValueError, TypeError, AttributeError, KeyError, re.error) as exc:
            node_id = getattr(node, "get", lambda *_: "unknown")("id", "unknown")
            self.helper.connector_logger.warning(
                "[CREATE] Cannot convert indicator node",
                {"opencti_id": node_id, "error": str(exc)},
            )
            return []

    # Fetch not only indicators but also objects that may be Alerted on or that may be Allow-listed.
    # This allows for closer integration of the Intelligence pipeline with the EDR.
    # Microsoft Defender for Endpoint understands the following items.
    INDICATOR_QUERY: Final = """
query GetFeedElements($filters: FilterGroup, $count: Int, $cursor: ID) {
  globalSearch(filters: $filters, first: $count, after: $cursor) {
    edges {
      node {
        id
        entity_type
        standard_id
        ... on Indicator {
          created: created_at
          modified: updated_at
          valid_until
          description
          entity_type
          x_opencti_main_observable_type
          name
          pattern
          confidence
          x_opencti_score
          revoked
          x_opencti_detection
        }
        ... on DomainName {
          observable_value
          created_at
          updated_at
          x_opencti_score
          x_opencti_description
        }
        ... on Hostname {
          observable_value
          created_at
          updated_at
          x_opencti_score
          x_opencti_description
        }
        ... on Url {
          observable_value
          created_at
          updated_at
          x_opencti_score
          x_opencti_description
        }
        ... on IPv4Addr {
          observable_value
          created_at
          updated_at
          x_opencti_score
          x_opencti_description
        }
        ... on IPv6Addr {
          observable_value
          created_at
          updated_at
          x_opencti_score
          x_opencti_description
        }
        ... on HashedObservable {
          observable_value
          created_at
          updated_at
          x_opencti_score
          x_opencti_description
          hashes {
            algorithm
            hash
          }
        }
        ... on X509Certificate {
          subject
          issuer
          serial_number
          validity_not_before
          validity_not_after
          created_at
          updated_at
          x_opencti_score
          x_opencti_description
          hashes {
            algorithm
            hash
          }
        }
      }
    }
    pageInfo {
      endCursor
      hasNextPage
    }
  }
}
    """

    def fetch_indicators_batched(
        self, filters, max_size=15000, batch_size=500, collection_name=None
    ):
        """
        Fetch feed elements (indicators + observables) in batches using cursor-based pagination.
        Stops at the end of the collection or when max_size is reached.
        """
        self.helper.connector_logger.info(
            "Fetching indicators for collection", {"collection": collection_name}
        )
        indicators = []
        cursor = None
        total_fetched = 0
        batch_num = 1
        while total_fetched < max_size:
            variables = {
                "filters": filters,
                "count": min(batch_size, max_size - total_fetched),
            }
            if cursor:
                variables["cursor"] = cursor
            self.helper.connector_logger.debug(
                "Fetching batch",
                {
                    "batch_num": batch_num,
                    "collection": collection_name,
                    "cursor": cursor,
                    "batch_size": variables["count"],
                    "total_fetched": total_fetched,
                },
            )
            try:
                result = self.helper.api.query(self.INDICATOR_QUERY, variables)
                data = result["data"]["globalSearch"]
                edges = data.get("edges") or []
                if not edges:
                    self.helper.connector_logger.debug(
                        "No more edges returned for batch, stopping.",
                        {"batch_num": batch_num, "collection_str": collection_name},
                    )
                    break
                for edge in edges:
                    indicators.append(edge["node"])
                    total_fetched += 1
                    if total_fetched >= max_size:
                        break
                page_info = data.get("pageInfo", {})
                cursor = page_info.get("endCursor")
                has_next_page = page_info.get("hasNextPage", False)
                self.helper.connector_logger.debug(
                    "Batch retrieved",
                    {
                        "batch_num": batch_num,
                        "collection_str": collection_name,
                        "indicators count": len(edges),
                        "cursor": cursor,
                        "has_next_page": has_next_page,
                    },
                )
                batch_num += 1
                # Stop if there are no more results
                if not has_next_page or not cursor or len(edges) == 0:
                    self.helper.connector_logger.debug(
                        "Batch has no more pages, stopping.",
                        {"batch_num": batch_num - 1, "collection": collection_name},
                    )
                    break
            except (KeyError, TypeError, ValueError) as e:
                self.helper.connector_logger.error(
                    "GraphQL query failed",
                    {"error": str(e), "variables": variables},
                )
                break
        self.helper.connector_logger.info(
            "Fetched indicators for collection",
            {"fetched": len(indicators), "collection": collection_name},
        )
        return indicators

    def run(self) -> None:
        """
        Main function to run the connector.
        This function contains the main logic of the connector.
        It fetches indicators from OpenCTI and Microsoft Defender,
        compares them, and creates or deletes indicators in Microsoft Defender as needed.
        The function runs in an infinite loop, sleeping for the configured interval between runs.
        """

        def handle_sigint(_signum, _frame):
            self.helper.connector_logger.info(
                "Received interrupt signal, shutting down gracefully."
            )
            sys.exit(0)

        signal.signal(signal.SIGINT, handle_sigint)

        while True:
            start_time = time.time()
            try:
                state = self.helper.get_state() or {}
                opencti_all_indicators = []
                defender_indicators_to_delete = []
                opencti_indicators_to_create = []

                now_iso = (
                    datetime.now(timezone.utc) + timedelta(minutes=10)
                ).isoformat()

                validity_filter = {
                    "key": "valid_until",
                    "operator": "gt",
                    "values": [now_iso],
                    "mode": "or",
                }

                # Prepare a mapping of collection to its rank (order in config)
                collection_rank = {
                    col: i for i, col in enumerate(self.config.taxii_collections)
                }

                # Effective global cap: respect Defender hard limit and admin-configured limit
                effective_global_limit = min(
                    15000, int(self.config.max_indicators or 15000)
                )

                # Get OpenCTI indicators
                for collection in self.config.taxii_collections:
                    if collection not in state:
                        state[collection] = {}
                    query = """
                        query TaxiiCollections($id: String!) {
                            taxiiCollection(id: $id) {
                                filters
                            }
                        }
                    """
                    try:
                        result = self.helper.api.query(query, {"id": collection})
                    except ValueError as ve:
                        # Check for FORBIDDEN_ACCESS error
                        if (
                            isinstance(ve.args[0], dict)
                            and ve.args[0].get("name") == "FORBIDDEN_ACCESS"
                        ):
                            self.helper.connector_logger.error(
                                "FORBIDDEN_ACCESS: The connector user does not have the required 'Manage data sharing' capability. Please ensure the user has this permission in OpenCTI.",
                                {"error": ve.args[0]},
                            )
                            raise
                        self.helper.connector_logger.error(
                            "ValueError during TAXII collection query",
                            {"error": str(ve)},
                        )
                        raise
                    taxii_collection = result["data"].get("taxiiCollection")
                    if taxii_collection is not None and "filters" in taxii_collection:
                        filters = taxii_collection["filters"]
                        filters = json.loads(filters)
                        filters["filters"].append(validity_filter)

                        pol = self.config.taxii_overrides.get(collection, {}) or {}
                        collection_limit = pol.get("max_indicators")
                        effective_collection_limit = effective_global_limit
                        if collection_limit:
                            effective_collection_limit = min(
                                effective_global_limit, collection_limit
                            )

                        opencti_indicators = self.fetch_indicators_batched(
                            filters,
                            max_size=effective_collection_limit,
                            collection_name=collection,
                        )

                        if opencti_indicators:
                            try:
                                first_node = opencti_indicators[0]
                                # ``globalSearch`` results can include
                                # non-Indicator nodes that expose the
                                # update timestamp as ``updated_at``
                                # rather than the Indicator-specific
                                # ``modified`` field. Fall back to
                                # ``updated_at`` so the state remains
                                # meaningful (and stops silently
                                # storing ``None``) for those nodes.
                                state[collection]["last_timestamp"] = first_node.get(
                                    "modified"
                                ) or first_node.get("updated_at")
                            except (IndexError, TypeError, AttributeError) as e:
                                self.helper.connector_logger.warning(
                                    "[STATE] Could not extract timestamp from first node",
                                    {"error": e},
                                )
                        state[collection]["last_count"] = len(opencti_indicators)
                        opencti_indicators = [
                            {
                                **opencti_indicator,
                                "_collection": collection,
                                "_collection_rank": collection_rank[collection],
                                "_collection_limit": effective_collection_limit,
                            }
                            for opencti_indicator in opencti_indicators
                        ]
                        opencti_all_indicators.extend(opencti_indicators)
                    else:
                        self.helper.connector_logger.error(
                            "TAXII collection not found or has no filters",
                            {"id": collection},
                        )

                self.helper.connector_logger.info(
                    "Found indicators in TAXII collections",
                    {"total_indicators": len(opencti_all_indicators)},
                )

                # RBAC scoping
                rbac_scope: RBACScope | None = None
                all_rbac_groups = self.config.used_rbac_groups()
                if all_rbac_groups:
                    name_to_id: dict[str, int] = {}
                    try:
                        # Go through the API handler so the request
                        # reuses the centralised token-refresh logic
                        # in ``_send_request``. Calling
                        # ``self.api.session.get`` directly used to
                        # bypass that check, which let a stale Bearer
                        # header reach Defender after a long OpenCTI
                        # fetch / processing pass and fail with 401
                        # before the next ``_send_request`` could
                        # renew it.
                        name_to_id, _ = self.api.fetch_rbac_groups()

                        # Cache for per-collection mapping later in this run
                        self._rbac_map = name_to_id

                        # --- VALIDATE THE UNION (global + per-collection) ---
                        # This ensures any per-collection RBAC names are known now,
                        # preventing KeyError later when we map names -> ids.
                        _ = resolve_rbac_scope_or_abort(all_rbac_groups, name_to_id)

                        # Resolve *global* scope for API writes (if configured)
                        if self.config.rbac_group_names:
                            rbac_scope = resolve_rbac_scope_or_abort(
                                self.config.rbac_group_names, name_to_id
                            )
                            if not rbac_scope:
                                raise RbacConfigError("RBAC scope is invalid.")
                            self.helper.connector_logger.info(
                                "[RBAC] Resolved RBAC groups for scoped writes",
                                {"group_count": len(rbac_scope[0])},
                            )
                    except RbacConfigError as e:
                        # Defensive catch - should be handled above, but keep for clarity.
                        # ``RbacConfigError`` carries structured details on
                        # ``e.metadata`` (see ``rbac_scope.RbacConfigError``);
                        # ``BaseException.args`` only contains the message, so
                        # we read the missing-group list from ``e.metadata``.
                        unrecognized = e.metadata.get("missing_groups")
                        self.helper.connector_logger.error(
                            "[RBAC] Unknown device groups in config; synchronization aborted.",
                            {
                                "unrecognized_groups": unrecognized,
                                "available_count": len(name_to_id),
                                "available_groups": sorted(name_to_id.keys()),
                                "error": str(e),
                            },
                        )
                        return
                    except (KeyError, TypeError, ValueError, AttributeError) as e:
                        self.helper.connector_logger.error(
                            "[RBAC] Failed to load RBAC groups; aborting run.",
                            {"error": str(e)},
                        )
                        return
                # Share scope with API writer so both arrays are emitted on writes
                self.api.set_rbac_scope(rbac_scope)

                # Get Microsoft Defender Indicators
                defender_indicators = self.api.get_indicators()

                self.helper.connector_logger.info(
                    "Found indicators in Microsoft Defender",
                    {"count": len(defender_indicators)},
                )

                # Sort: 1) collection rank (first-configured = highest priority),
                #       2) confidence (highest first),
                #       3) modified (newest first)
                opencti_all_indicators.sort(key=sort_key)

                # Cut at effective global cap (never above Defender hard limit)
                opencti_all_indicators = opencti_all_indicators[:effective_global_limit]

                # Build Defender in-memory indexes for de-dup decisions
                # Key = (indicatorType, indicatorValue, normalized scope ids)
                # Action/metadata deliberately ignored (we may change action)
                # Tenant-wide is represented by empty RBAC arrays in API.
                # ------------------------------------------------------------
                # ``key_from_def`` / ``key_from_candidate`` live at module
                # scope so the dedup contract (hash-value case folding,
                # scope-id normalisation) is unit-tested in
                # ``tests/test_key_normalization.py``. Aliasing them here
                # keeps the call-site shape unchanged.
                _key_from_def = key_from_def
                _key_from_candidate = key_from_candidate

                all_by_key: dict[ScopeKey, dict[str, Any]] = {}
                owned_by_key: dict[ScopeKey, dict[str, Any]] = {}
                owner_id = (self.config.client_id or "").lower()
                for d in defender_indicators:
                    k = _key_from_def(d)
                    # prefer latest by lastUpdateTime if collision
                    prev = all_by_key.get(k)
                    if not prev or d.get("lastUpdateTime", "") > prev.get(
                        "lastUpdateTime", ""
                    ):
                        all_by_key[k] = d
                    if str(d.get("createdBy", "")).lower() == owner_id:
                        owned_by_key[k] = d

                # Use dicts for O(1) lookups
                defender_external_ids = {
                    d["externalId"]: d for d in defender_indicators if "externalId" in d
                }
                # Subset: only those we OWN (createdBy == client_id), for safe updates/deletes
                defender_owned_external_ids = {
                    eid: d
                    for eid, d in defender_external_ids.items()
                    if str(d.get("createdBy", "")).lower() == owner_id
                }
                owned_id_set = set(defender_owned_external_ids.keys())
                all_id_set = set(defender_external_ids.keys())

                opencti_ids = set()

                for opencti_indicator in opencti_all_indicators:
                    opencti_id = opencti_indicator.get("id")
                    opencti_ids.add(opencti_id)

                # Deletions (ownership-safe):
                # - UPDATE_ONLY_OWNED=true (default): delete ONLY owned indicators missing from OpenCTI
                # - UPDATE_ONLY_OWNED=false: delete all missing indicators (owned + non-owned)
                if getattr(self.config, "update_only_owned", True):
                    # Owned only
                    for (
                        ext_id,
                        defender_indicator,
                    ) in defender_owned_external_ids.items():
                        if ext_id not in opencti_ids:
                            defender_indicators_to_delete.append(defender_indicator)
                    # Non-owned missing -> warn once
                    missing_non_owned = [
                        ext_id
                        for ext_id in (all_id_set - opencti_ids)
                        if ext_id in defender_external_ids
                        and ext_id not in owned_id_set
                    ]
                    if missing_non_owned:
                        self.helper.connector_logger.warning(
                            "[Plan] Non-owned indicators are absent from OpenCTI; "
                            "skipping delete (UPDATE_ONLY_OWNED=true).",
                            {"missing_non_owned_ids": len(missing_non_owned)},
                        )
                else:
                    # Allowed to delete non-owned as well
                    for ext_id, defender_indicator in defender_external_ids.items():
                        if ext_id not in opencti_ids:
                            defender_indicators_to_delete.append(defender_indicator)

                # Find OpenCTI indicators to create using KEY-based de-dup:
                #  - Key: (type, value, scopeIds) - action/metadata ignored
                #  - Do NOT create scoped duplicates if tenant-wide exists (empty scope)
                defender_external_ids_set = set(defender_external_ids.keys())

                # Helper to check ownership for a given key
                def _owned_for_key(k: ScopeKey) -> bool:
                    existing = all_by_key.get(k)
                    return bool(
                        existing
                        and str(existing.get("createdBy", "")).lower() == owner_id
                    )

                allow_update_non_owned = not getattr(
                    self.config, "update_only_owned", True
                )

                for opencti_indicator in opencti_all_indicators:
                    observables = (
                        self._convert_indicator_to_observables(opencti_indicator) or []
                    )
                    for observable_data in observables:
                        # --- Per-collection policy overrides (if present) ---
                        collection_id = opencti_indicator.get("_collection")
                        overrides = getattr(self.config, "taxii_overrides", {}) or {}
                        policy = (
                            overrides.get(collection_id, {}) if collection_id else {}
                        )

                        # If there are overrides, apply them explicitly (no broad swallow-all).
                        if isinstance(policy, dict) and policy:
                            # Simple field overrides
                            if policy.get("action") is not None:
                                observable_data["__policy_action"] = str(
                                    policy["action"]
                                )
                            if policy.get("expire_time") is not None:
                                observable_data["__policy_expire_time_days"] = int(
                                    policy["expire_time"]
                                )
                            if policy.get("recommended_actions") is not None:
                                observable_data["__policy_recommended_actions"] = str(
                                    policy["recommended_actions"]
                                )
                            if policy.get("educate_url") is not None:
                                observable_data["__policy_educate_url"] = str(
                                    policy["educate_url"]
                                )

                            # Per-collection RBAC (names -> ids).
                            #
                            # Apply the same trim / drop-blanks / dedupe
                            # normalisation as ``resolve_rbac_scope_or_abort``
                            # — otherwise a config carrying e.g.
                            # ``"  endpoints  "`` would pass validation
                            # (which strips) but mismatch ``self._rbac_map``
                            # here (which would look up the un-stripped
                            # name) and falsely raise "RBAC groups vanished
                            # during run".
                            normalised_names: list[str] = []
                            seen_names: set[str] = set()
                            for raw_name in policy.get("rbac_group_names") or []:
                                if raw_name is None:
                                    continue
                                trimmed = str(raw_name).strip()
                                if not trimmed or trimmed in seen_names:
                                    continue
                                seen_names.add(trimmed)
                                normalised_names.append(trimmed)

                            if normalised_names:
                                # Fail-closed: ensure configured names still
                                # exist in the run-time RBAC map. If any are
                                # missing, raise so the run aborts (connector
                                # will re-init).
                                missing_names = [
                                    n
                                    for n in normalised_names
                                    if n not in self._rbac_map
                                ]
                                if missing_names:
                                    raise RbacConfigError(
                                        "RBAC groups vanished during run",
                                        {"missing_groups": missing_names},
                                    )

                                # Safe to map now
                                ids = [self._rbac_map[n] for n in normalised_names]

                                # Attach both arrays; API handler will prefer
                                # these over global scope.
                                observable_data["rbacGroupNames"] = normalised_names
                                observable_data["rbacGroupIds"] = ids
                            # else: all configured names were blank -> no
                            # per-collection RBAC override; the observable
                            # inherits the global scope downstream.

                        # Map observable type -> Defender indicatorType label
                        # (We reuse IOC_TYPES mapping implicitly in api handler;
                        # here we guard by CREATABLE types to avoid noisy attempts.)
                        obs_type = observable_data.get("type", "")
                        # File hashes are normalized in api_handler; only gate on allowed indicator types
                        # Keep selection minimal here; api_handler will finally filter again.
                        # Skip early if obviously not creatable (e.g., email-addr)
                        mapped_writable = False
                        if obs_type in (
                            "domain-name",
                            "hostname",
                            "url",
                            "ipv4-addr",
                            "ipv6-addr",
                            "file",
                            "x509-certificate",
                        ):
                            mapped_writable = True
                        if not mapped_writable:
                            continue

                        # Decide the candidate key for de-dup.
                        # For file observables, the actual hash-type selection and normalization
                        # (e.g., sha1 vs sha256) are handled in the api_handler. At this layer we
                        # treat all allowed observable types uniformly and rely on:
                        #   1) the externalId fast-path below, and
                        #   2) the generic (indicatorType, value, scope) key-based path.

                        # Use externalId fast-path first (unchanged behavior)
                        observable_id = observable_data.get("id")
                        if observable_id in defender_external_ids_set:
                            continue

                        # Key path: check if (type, value, scope) already exists OR tenant-wide exists for same value
                        # We need an approximate indicatorType/value for keying; use the raw value and obs type label.
                        # The api layer will finalize cleaning; keying here prevents obvious duplicates.
                        raw_value = observable_data.get("value") or ""
                        # Map obs type to a Defender indicatorType label used in keys (same as utils.IOC_TYPES)
                        if obs_type in ("domain-name", "hostname"):
                            key_type = "DomainName"
                            clean_value = indicator_value(raw_value)
                        elif obs_type in ("ipv4-addr", "ipv6-addr"):
                            key_type = "IpAddress"
                            clean_value = indicator_value(raw_value)
                        elif obs_type == "url":
                            key_type = "Url"
                            clean_value = indicator_value(raw_value)
                        elif obs_type == "file":
                            # Derive the dedup key from the observable's
                            # hashes (SHA-256 preferred over SHA-1; MD5
                            # is excluded because Defender rejects
                            # ``FileMd5`` create requests). Multiple
                            # OpenCTI indicators commonly share the same
                            # SHA value (different ``externalId`` but
                            # same hash), so relying on ``externalId``
                            # alone would create duplicate Defender
                            # indicators and burn through the 15k tenant
                            # quota.
                            #
                            # ``None`` here means the file observable
                            # carries no Defender-supported hash (MD5
                            # only, or no ``hashes`` at all). Such an
                            # observable can never produce a creatable
                            # Defender payload — ``_build_request_body``
                            # drops MD5-only file observables and
                            # rejects ones with no hash entirely — so
                            # we MUST skip staging it. Otherwise the
                            # planner would re-stage the same
                            # uncreatable observable every cycle,
                            # consuming part of the 15k candidate
                            # budget and producing zero-result create
                            # attempts on every sync.
                            file_key = defender_file_dedup_key(observable_data)
                            if file_key is None:
                                self.helper.connector_logger.debug(
                                    "[Plan] Skipping file observable: no "
                                    "Defender-supported hash (SHA-256 / SHA-1).",
                                    {"observable_id": observable_id},
                                )
                                continue
                            key_type, clean_value = file_key
                        elif obs_type == "x509-certificate":
                            # Certificate observables carry the
                            # thumbprint in ``hashes`` rather than in
                            # ``value`` — deriving the dedup key from
                            # ``raw_value`` would always be empty and
                            # the loop would ``continue`` before staging
                            # the indicator (Defender thumbprint
                            # indicators were silently dropped from the
                            # planning pass before this fix). Mirror
                            # ``defender_file_dedup_key`` for files.
                            #
                            # ``None`` here means the certificate has
                            # no usable thumbprint hash —
                            # ``_build_request_body`` requires a
                            # thumbprint and would drop the observable,
                            # so staging it would waste planner budget
                            # on a no-op every cycle (same reasoning as
                            # the file branch above).
                            cert_key = defender_certificate_dedup_key(observable_data)
                            if cert_key is None:
                                self.helper.connector_logger.debug(
                                    "[Plan] Skipping x509-certificate observable: "
                                    "no usable thumbprint hash (SHA-1 / SHA-256 / MD5).",
                                    {"observable_id": observable_id},
                                )
                                continue
                            key_type, clean_value = cert_key
                        else:
                            continue

                        if not clean_value:
                            continue
                        rbac_for_key = rbac_scope
                        if isinstance(observable_data.get("rbacGroupIds"), list):
                            rbac_for_key = (
                                observable_data.get("rbacGroupNames", []) or [],
                                observable_data["rbacGroupIds"] or [],
                            )
                        cand_key = _key_from_candidate(
                            key_type, clean_value, rbac_for_key
                        )
                        tenantwide_key = (key_type, clean_value, tuple())

                        existing = all_by_key.get(cand_key)
                        if existing:
                            # Same-key indicator already exists; do NOT create a duplicate.
                            # We also make ownership explicit for auditability and future update logic.
                            if _owned_for_key(cand_key):
                                # Owned: currently we do not stage updates here; just document the decision.
                                self.helper.connector_logger.debug(
                                    "[Plan] Owned indicator exists; skipping create.",
                                    {"key": cand_key},
                                )
                            else:
                                if allow_update_non_owned:
                                    # You *may* later add an explicit update here; for now we just avoid duplicate create.
                                    self.helper.connector_logger.debug(
                                        "[Plan] Non-owned indicator exists; skipping create "
                                        "(UPDATE_ONLY_OWNED=false) allows updates.",
                                        {"key": cand_key},
                                    )
                                else:
                                    # Strict: do not touch non-owned indicators.
                                    self.helper.connector_logger.warning(
                                        "[Plan] Non-owned indicator exists; skipping create and not updating "
                                        "(UPDATE_ONLY_OWNED=true).",
                                        {"key": cand_key},
                                    )
                            continue

                        # Tenant-wide already present for this (type,value): it covers all scopes -> no scoped duplicate
                        if tenantwide_key in all_by_key:
                            self.helper.connector_logger.warning(
                                "[Plan] Tenant-wide indicator exists; skipping scoped duplicate.",
                                {"type": key_type, "value": raw_value},
                            )
                            continue

                        # New indicator (no same-key, no tenant-wide) -> stage create
                        opencti_indicators_to_create.append(observable_data)

                # Dedup
                defender_indicators_to_delete = {
                    obj["id"]: obj
                    for obj in reversed(defender_indicators_to_delete)
                    if "id" in obj
                }
                defender_indicators_to_delete = list(
                    defender_indicators_to_delete.values()
                )
                defender_indicators_to_delete_ids = [
                    defender_indicator_to_delete["id"]
                    for defender_indicator_to_delete in defender_indicators_to_delete
                ]
                self.helper.connector_logger.info(
                    "Deleting indicators",
                    {"count": len(defender_indicators_to_delete_ids)},
                )
                if defender_indicators_to_delete_ids:
                    defender_indicators_to_delete_ids_chunked = chunker_list(
                        defender_indicators_to_delete_ids, 500
                    )
                    for (
                        defender_indicators_to_delete_ids_chunk
                    ) in defender_indicators_to_delete_ids_chunked:
                        try:
                            self.api.delete_indicators(
                                defender_indicators_to_delete_ids_chunk
                            )
                            if not self.config.passive_only:
                                msg = "Deleted indicators"
                            else:
                                msg = "[DRY-RUN] Would delete"
                            self.helper.connector_logger.info(
                                msg,
                                {"count": len(defender_indicators_to_delete_ids_chunk)},
                            )
                        except Exception as e:
                            self.helper.connector_logger.error(
                                "Cannot delete indicators",
                                {
                                    "error": str(e),
                                    "ids": defender_indicators_to_delete_ids_chunk,
                                },
                            )
                # Wait a few seconds to allow Defender to free up capacity
                if not self.config.passive_only and defender_indicators_to_delete_ids:
                    time.sleep(20)

                opencti_indicators_to_create = {
                    obj["id"]: obj
                    for obj in reversed(opencti_indicators_to_create)
                    if "id" in obj
                }
                opencti_indicators_to_create = list(
                    opencti_indicators_to_create.values()
                )
                self.helper.connector_logger.info(
                    "[CREATE] Creating indicators...",
                    {"count": len(opencti_indicators_to_create)},
                )
                if opencti_indicators_to_create:
                    opencti_indicators_to_create_chunked = chunker_list(
                        opencti_indicators_to_create, 500
                    )
                    for (
                        opencti_indicators_to_create_chunk
                    ) in opencti_indicators_to_create_chunked:
                        try:
                            data = self.api.post_indicators(
                                opencti_indicators_to_create_chunk
                            )
                            if not self.config.passive_only:
                                msg = "Created indicators"
                            else:
                                msg = "[DRY-RUN] Would create"
                            self.helper.connector_logger.info(
                                msg,
                                {
                                    "indicators_created": data.get(
                                        "total_count",
                                        len(opencti_indicators_to_create_chunk),
                                    )
                                    - data.get("failed_count", 0),
                                    "indicators_total": data.get(
                                        "total_count",
                                        len(opencti_indicators_to_create_chunk),
                                    ),
                                },
                            )
                        except (KeyError, TypeError, ValueError) as e:
                            self.helper.connector_logger.error(
                                "Cannot create indicators",
                                {
                                    "error": str(e),
                                    "count": len(opencti_indicators_to_create_chunk),
                                },
                            )
                self.helper.set_state(state)
            except Exception as e:
                self.helper.connector_logger.error(
                    "An error occurred during the run", {"error": str(e)}
                )
            # Adjust sleep to maintain accurate interval
            elapsed = time.time() - start_time
            sleep_time = max(0, self.config.interval - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)
