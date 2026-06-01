"""
Module for parsing Splunk search results into STIX observables.

This module provides functionality to convert Splunk search results into STIX 2.1
observables, handling various types of data including URLs, User-Agents, DNS queries,
IP addresses, hostnames, user accounts, and files.
"""

import json
from datetime import datetime
from typing import List, Optional, Tuple, Union

import pytz
import stix2
from pycti import (
    CustomObservableHostname,
    CustomObservableUserAgent,
    Identity,
    StixSightingRelationship,
)

from .infrastructure import InfrastructureBuilder
from .services.sourcetype_resolver import SourcetypeResolver as _SourcetypeResolver
from .utils import (
    detect_observable_type,
    get_hash_type,
    is_domain_name,
    is_hostname,
    is_ipv4,
    is_ipv6,
)

# Module-level resolver — loaded once at import time, shared across all calls.
_resolver = _SourcetypeResolver()
_infra_builder = InfrastructureBuilder()


def _parse_ts(val) -> Optional[datetime]:
    if val is None:
        return None
    # numeric (epoch seconds)
    if isinstance(val, (int, float)) or (
        isinstance(val, str) and val.replace(".", "", 1).isdigit()
    ):
        try:
            return datetime.fromtimestamp(float(val), tz=pytz.UTC)
        except Exception:
            pass
    # ISO-8601 strings (with or without Z)
    if isinstance(val, str):
        try:
            s = val.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return datetime.fromisoformat(s).astimezone(pytz.UTC)
        except Exception:
            return None
    return None


def create_sighting(
    observable_id: str,
    author: Identity,
    source_identity: Optional[Identity] = None,
    first_seen: Optional[datetime] = None,
    last_seen: Optional[datetime] = None,
    confidence: Optional[int] = None,
    description: Optional[str] = None,
    sighting_marking_id: Optional[str] = None,
    count: int = 1,
    observable_value: str = "",
    splunk_identity_id: Optional[str] = None,
    labels: Optional[List[str]] = None,
) -> stix2.Sighting:
    """
    Create a STIX Sighting object for a given observable.

    Args:
        observable_id: ID of the observable that was sighted
        author: The main SIEM platform Identity object
        source_identity: Optional Identity object representing the specific sourcetype
        first_seen: When the observable was first seen
        last_seen: When the observable was last seen
        confidence: Optional confidence score
        description: Optional description
        sighting_marking_id: Optional TLP marking-definition ID
        count: Number of raw Splunk events aggregated into this sighting
        observable_value: String value of the observable (used as merge key by _merge_sightings)
    """
    now = datetime.now(pytz.UTC)
    # Use provided timestamps or default to now
    first_seen_time = first_seen or now
    last_seen_time = last_seen or now

    creator_id = splunk_identity_id if splunk_identity_id else author.id
    # where_sighted_refs must be an Identity SDO. Priority:
    #   1. source_identity  — vendor SecurityPlatform from sourcetype map
    #   2. splunk_identity_id — Splunk System identity (identity_class="system")
    #   3. author.id       — last-resort fallback
    where_sighted_id = (
        source_identity.id
        if source_identity
        else (splunk_identity_id or author.id)
    )
    sighting_props = {
        "id": StixSightingRelationship.generate_id(
            observable_id,
            source_identity.id if source_identity else (splunk_identity_id or author.id),
            first_seen_time,
            last_seen_time,
        ),
        "type": "sighting",
        "created": now,
        "modified": now,
        "created_by_ref": creator_id,
        "where_sighted_refs": [where_sighted_id],
        # Use fake indicator ID in sighting_of_ref as per OpenCTI pattern
        "sighting_of_ref": "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e",
        "first_seen": first_seen_time,
        "last_seen": last_seen_time,
        "count": max(1, count),
        "allow_custom": True,
        "x_opencti_sighting_of_ref": observable_id,
        "x_opencti_detection": True,
        "x_opencti_created_by_ref": creator_id,
        "x_opencti_observable_value": observable_value,
    }

    if confidence is not None:
        sighting_props["confidence"] = confidence
        sighting_props["x_opencti_score"] = confidence  # Set directly on the object

    if description:
        sighting_props["description"] = description

    if (
        sighting_marking_id
        and isinstance(sighting_marking_id, str)
        and sighting_marking_id.startswith("marking-definition--")
    ):
        sighting_props["object_marking_refs"] = [sighting_marking_id]

    if labels:
        sighting_props["labels"] = labels

    return stix2.Sighting(**sighting_props)


def is_no_results_row(row: dict) -> bool:
    """Return True when a Splunk result row is the appendpipe synthetic no-results row.

    The ``observable_value`` field is the canonical signal because it is
    explicitly set by the appendpipe pattern.  The sourcetype/index fallback
    is only used for custom queries that may not include the appendpipe pattern
    and therefore won't have an ``observable_value`` field at all.

    This design avoids false positives: a real row where sourcetype happens to
    be 'N/A' but observable_value is a genuine IP address is NOT treated as
    a no-results row.
    """
    if "observable_value" in row:
        ov = str(row["observable_value"] or "").strip().lower()
        return ov in ("no results", "n/a", "")
    # Fallback: custom queries without appendpipe; both fields must be N/A
    st = str(row.get("sourcetype") or "").strip().lower()
    ix = str(row.get("index") or "").strip().lower()
    return st == "n/a" and ix == "n/a"


def create_negative_sighting(
    indicator_stix_id: str,
    indicator_name: str,
    search_type: str,
    earliest: str,
    latest: str,
    splunk_host: str,
    query: str,
    author: Identity,
    confidence: int = 100,
    sighting_marking_id: Optional[str] = None,
    template_name: Optional[str] = None,
    splunk_identity_id: Optional[str] = None,
) -> stix2.Sighting:
    """Create a STIX negative sighting expressing confirmed absence of an indicator.

    Per STIX 2.1, a Sighting 'denotes the belief that something was seen.'  A
    count of 0 contradicts this definition.  Instead we use OpenCTI's
    ``x_opencti_negative`` extension to express 'actively searched, confirmed
    absent.'  The ``count`` field is intentionally omitted.

    Args:
        indicator_stix_id: Full STIX ID of the indicator (``indicator--...``)
        indicator_name: Human-readable name for the description
        search_type: Label for the search type (e.g. 'dest', 'src', 'custom')
        earliest: Splunk earliest_time used in the search
        latest: Splunk latest_time used in the search
        splunk_host: Hostname of the Splunk instance
        query: SPL query that was executed
        author: Organization Identity for the Splunk instance
        confidence: Confidence score (default 100 — certain absence)
        sighting_marking_id: Optional TLP marking-definition ID
    """
    now = datetime.now(pytz.UTC)
    creator_id = splunk_identity_id if splunk_identity_id else author.id
    desc_lines = [f"No results found in Splunk for {indicator_name}"]
    if template_name:
        desc_lines.append(f"Search template: {template_name}")
    desc_lines.append(f"Search type: {search_type}")
    desc_lines.append(f"Time range: {earliest} \u2192 {latest}")
    desc_lines.append(f"Splunk instance: {splunk_host}")
    description = "\n".join(desc_lines)

    sighting_props = {
        "id": StixSightingRelationship.generate_id(
            indicator_stix_id,
            splunk_identity_id or author.id,
            now,
            now,
        ),
        "type": "sighting",
        "created": now,
        "modified": now,
        "created_by_ref": creator_id,
        "sighting_of_ref": indicator_stix_id,
        "where_sighted_refs": [splunk_identity_id or author.id],
        "first_seen": now,
        "last_seen": now,
        "allow_custom": True,
        "x_opencti_negative": True,
        "x_opencti_detection": True,
        "x_opencti_created_by_ref": creator_id,
        "confidence": confidence,
        "description": description,
    }

    if (
        sighting_marking_id
        and isinstance(sighting_marking_id, str)
        and sighting_marking_id.startswith("marking-definition--")
    ):
        sighting_props["object_marking_refs"] = [sighting_marking_id]

    return stix2.Sighting(**sighting_props)


def _build_observable(
    obs_type: str, value: str, custom_props: dict, result: dict
) -> Optional[stix2.base._STIXBase]:
    """Create a STIX observable of the given type from a string value.

    Returns None if the type is not supported or the value is unusable.
    """
    try:
        if obs_type == "IPv4-Addr":
            return stix2.IPv4Address(value=value, allow_custom=True, **custom_props)
        if obs_type == "IPv6-Addr":
            return stix2.IPv6Address(value=value, allow_custom=True, **custom_props)
        if obs_type == "Domain-Name":
            return stix2.DomainName(value=value, allow_custom=True, **custom_props)
        if obs_type == "Url":
            return stix2.URL(value=value, allow_custom=True, **custom_props)
        if obs_type == "Email-Addr":
            return stix2.EmailAddress(value=value, allow_custom=True, **custom_props)
        if obs_type == "StixFile":
            hash_type = get_hash_type(value)
            if hash_type:
                return stix2.File(
                    hashes={hash_type: value}, allow_custom=True, **custom_props
                )
            return stix2.File(name=value, allow_custom=True, **custom_props)
        if obs_type == "Hostname":
            from pycti import CustomObservableHostname as _HostnameObs

            return _HostnameObs(value=value, allow_custom=True, **custom_props)
        if obs_type == "Text":
            # OpenCTI Text observable — skip if not supported in this env
            return None
    except Exception:
        return None
    return None


def _extract_observable_string_value(observable: stix2.base._STIXBase) -> str:
    """Return the primary string value from a STIX observable for use as a merge key."""
    for attr in ("value", "name", "account_login", "path"):
        val = getattr(observable, attr, None)
        if val:
            return str(val)
    # File: try first hash value
    hashes = getattr(observable, "hashes", None)
    if hashes:
        for v in hashes.values():
            return str(v)
    return str(getattr(observable, "id", ""))


def create_sourcetype_identity(
    sourcetype: str,
    vendor_product: Optional[str],
    author: Identity,
    marking_id: Optional[str] = None,
) -> Identity:
    """
    Create a STIX Identity object for a Splunk sourcetype.

    Args:
        sourcetype: The Splunk sourcetype string
        vendor_product: Optional vendor product name
        author: The main SIEM platform Identity object for reference

    Returns:
        stix2.Identity: An Identity object representing the data source
    """
    name = vendor_product if vendor_product else sourcetype
    return stix2.Identity(
        id=Identity.generate_id(name=name, identity_class="system"),
        allow_custom=True,
        name=name,
        identity_class="system",
        created_by_ref=author.id,
        x_opencti_created_by_ref=author.id,
        x_opencti_identity_type="System",  # or perhaps "data-source"
        x_opencti_identity_subtype="splunk_sourcetype",
        description=f"Data source for Splunk sourcetype {sourcetype}",
        object_marking_refs=[marking_id] if marking_id else [],
    )


# --- Inserted: System Identity helper ---
def create_system_identity(
    hostname: str,
    author: Identity,
    labels: Optional[List[str]] = None,
    marking_id: Optional[str] = None,
    description: Optional[str] = None,
) -> Identity:
    """
    Create a STIX System Identity object for a host/system.

    Args:
        hostname: The system/host name (e.g., FQDN or short host)
        author: The main SIEM/OpenCTI platform Identity
        labels: Optional list of labels to attach (e.g., ["sourcetype::wineventlog"])
        marking_id: Optional marking-definition id
        description: Optional description for the system

    Returns:
        stix2.Identity: An Identity object representing the system/host
    """
    # Normalize and build labels
    obj_labels = labels or []

    return stix2.Identity(
        id=Identity.generate_id(name=hostname, identity_class="system"),
        allow_custom=True,
        name=hostname,
        identity_class="system",
        created_by_ref=author.id,
        x_opencti_created_by_ref=author.id,
        x_opencti_identity_type="System",
        description=description or f"System generated from Splunk host '{hostname}'",
        object_marking_refs=[marking_id] if marking_id else [],
        objectLabel=obj_labels,
    )


def _splunk_field(result: dict, *keys: str) -> Optional[str]:
    """Return first non-empty/non-dash field value from result, or None."""
    _MISSING = frozenset({"-", "n/a", "none", "unknown", "", "0.0.0.0", "::"})
    for k in keys:
        v = str(result.get(k) or "").strip()
        if v and v.lower() not in _MISSING:
            return v
    return None


def parse_observables_and_incident(
    helper,
    result: dict,
    author: stix2.Identity,
    marking_id: str = None,
    sighting_marking_id: str = None,
    observable_field: str = "observable_value",
    observable_type_override: Optional[str] = None,
    template_name: Optional[str] = None,
    splunk_identity_id: Optional[str] = None,
) -> Tuple[List[stix2.base._Observable], Optional[stix2.Identity], List[stix2.Sighting]]:
    """
    Parse Splunk search results into STIX observables and incidents.

    This function processes a Splunk search result dictionary and converts relevant fields
    into STIX 2.1 observables. It can handle both standard Splunk fields and enriched
    fields from Enterprise Security's Threat Intelligence framework if present.

    Standard fields handled:
    - URLs, User-Agents, DNS queries/answers
    - User accounts
    - Source and destination IPs/hostnames
    - Files and directories
    - Host (system identity), Sourcetypes (as labels/software), and vendor products

    Threat Intel fields (if present via enrichment):
    - threat_key: Unique identifier for the intel entry
    - threat_match_value: The actual value that matched
    - threat_match_type: Type of indicator (ip, domain, hash, etc)
    - threat_label: Labels or categories for the intel
    - threat_source: Source of the intelligence
    - threat_time: Time the intel was created/updated
    - threat_description: Context about the intel
    - confidence: Confidence score (0-100)

    Args:
        result (dict): A dictionary containing Splunk search results
        author (dict): Dictionary containing author information with 'id' key
        marking_id (str, optional): STIX marking-definition ID for object markings.
        sighting_marking_id (str, optional): STIX marking-definition ID to apply to Sightings.

    Returns:
        tuple containing:
            - list[stix2.base._Observable]: STIX observable objects
            - stix2.Identity: Source Identity object or None
            - list[stix2.Sighting]: Sightings with proper attribution

    Example:
        # Standard search result
        result = {
            'src': '192.168.1.1',
            'dest': 'example.com'
        }

        # Or enriched result with threat intel
        result = {
            'src': '192.168.1.1',
            'threat_match_value': '192.168.1.1',
            'threat_match_type': 'ip',
            'threat_label': 'malicious-ip',
            'confidence': '90'
        }
    """
    helper.connector_logger.debug(f"Parsing result: {result}")
    SIGHTABLE_TYPES = (
        stix2.IPv4Address,
        stix2.IPv6Address,
        stix2.DomainName,
        stix2.URL,
        stix2.File,
        stix2.Software,
        CustomObservableHostname,
        CustomObservableUserAgent,
    )

    observables = []
    sightings = []
    source_identity = None
    marking_refs = (
        [marking_id]
        if (
            isinstance(marking_id, str)
            and marking_id.startswith("marking-definition--")
        )
        else []
    )
    custom_props = {
        "x_opencti_created_by_ref": author.id,
        **({"object_marking_refs": marking_refs} if marking_refs else {}),
    }

    # Define invalid values to filter out
    invalid_values = {"unknown", "none", "n/a", "-", "0.0.0.0", "::", ""}

    # Prepare host value if present (used for both observable + system identity)
    host_val = result.get("host")

    # Add threat intel context to custom_props if available
    if result.get("threat_key"):
        custom_props.update(
            {
                "x_opencti_labels": result.get("threat_label", "").split(","),
                "x_opencti_score": int(result.get("confidence", 75)),
                "x_opencti_description": result.get("threat_description", ""),
                "x_opencti_external_reference": {
                    "source_name": result.get("threat_source", "splunk"),
                    "external_id": result.get("threat_key"),
                    "description": result.get("threat_description", ""),
                },
            }
        )

    # Handle Sourcetype — resolve via mapping, create vendor + platform identities
    sourcetype_val = result.get("sourcetype")
    vendor_product = result.get("vendor_product")
    mapping: Optional[dict] = None
    _effective_creator_id: Optional[str] = splunk_identity_id
    _is_unmapped: bool = False
    if sourcetype_val and sourcetype_val.lower() not in invalid_values:
        helper.connector_logger.debug(
            f"[PARSER] Processing sourcetype: {sourcetype_val}"
        )
        _is_unmapped = not _resolver.is_mapped(sourcetype_val)
        mapping = _resolver.resolve(sourcetype_val)
        if mapping.get("skip"):
            helper.connector_logger.debug(
                f"[PARSER] Skipping sourcetype '{sourcetype_val}' (skip=True in mapping)"
            )
            return [], None, []

        vendor = mapping["vendor"]
        product = mapping["product"]
        entity_type = mapping.get("entity_type", "Software")

        # Always create a vendor Organization Identity
        try:
            vendor_identity = stix2.Identity(
                id=Identity.generate_id(name=vendor, identity_class="organization"),
                name=vendor,
                identity_class="organization",
                allow_custom=True,
                created_by_ref=author.id,
                x_opencti_created_by_ref=author.id,
                **({
                    "object_marking_refs": marking_refs
                } if marking_refs else {}),
            )
            observables.append(vendor_identity)
            _effective_creator_id = vendor_identity.id
            helper.connector_logger.debug(
                f"[PARSER] Created vendor Identity: {vendor}"
            )
        except Exception as e:
            helper.connector_logger.error(
                f"[PARSER] Failed to create vendor Identity for '{vendor}': {e}"
            )
            vendor_identity = None

        if entity_type == "Infrastructure" and vendor_identity is not None:
            infrastructure_data = _infra_builder.build(mapping)
            if infrastructure_data:
                try:
                    infrastructure_obj = stix2.Infrastructure(
                        **infrastructure_data,
                        allow_custom=True,
                        created_by_ref=vendor_identity.id,
                        x_opencti_created_by_ref=vendor_identity.id,
                        **({"object_marking_refs": marking_refs} if marking_refs else {}),
                    )
                    observables.append(infrastructure_obj)
                    helper.connector_logger.debug(
                        f"[PARSER] Created Infrastructure object: {infrastructure_data.get('name')}"
                    )
                except Exception as e:
                    helper.connector_logger.error(
                        f"[PARSER] Failed to create Infrastructure for '{mapping.get('product', sourcetype_val)}': {e}"
                    )

            # SecurityPlatform Identity goes into where_sighted_refs (Identity SDO required).
            # identity_class MUST be "securityplatform" (all-lowercase) — this is what
            # triggers OpenCTI's securityPlatformAdd mutation instead of the generic
            # identityAdd / System path.
            platform_name = f"{vendor} {product}"
            infra_types = mapping.get("infrastructure_types", [])
            platform_type = infra_types[0] if infra_types else None
            platform_desc = mapping.get("description") or (
                f"{product} is a security platform by {vendor}."
                + (f" Platform type: {platform_type}." if platform_type else "")
            )
            try:
                platform_identity = stix2.Identity(
                    id=Identity.generate_id(
                        name=platform_name, identity_class="securityplatform"
                    ),
                    name=platform_name,
                    identity_class="securityplatform",
                    description=platform_desc,
                    allow_custom=True,
                    custom_properties={
                        "security_platform_type": platform_type,
                        "x_opencti_type": "SecurityPlatform",
                    },
                    created_by_ref=vendor_identity.id,
                    x_opencti_created_by_ref=vendor_identity.id,
                    **({
                        "object_marking_refs": marking_refs
                    } if marking_refs else {}),
                )
                observables.append(platform_identity)
                source_identity = platform_identity
                helper.connector_logger.debug(
                    f"[PARSER] Created SecurityPlatform Identity: {platform_name}"
                )
            except Exception as e:
                helper.connector_logger.error(
                    f"[PARSER] Failed to create SecurityPlatform Identity for '{platform_name}': {e}"
                )
        # Software case: vendor Identity already added; no platform Identity needed

    # Handle URL
    if result.get("url"):
        observables.append(
            stix2.URL(value=result["url"], allow_custom=True, **custom_props)
        )

    # Handle User-Agent
    if result.get("http_user_agent"):
        observables.append(
            CustomObservableUserAgent(
                value=result["http_user_agent"], allow_custom=True, **custom_props
            )
        )

    # Handle DNS query and answer
    if result.get("query"):
        observables.append(
            stix2.DomainName(value=result["query"], allow_custom=True, **custom_props)
        )
    if result.get("answer") and is_ipv4(result["answer"]):
        observables.append(
            stix2.IPv4Address(value=result["answer"], allow_custom=True, **custom_props)
        )

    # Handle user account
    if result.get("user") and result["user"].lower() not in invalid_values:
        observables.append(
            stix2.UserAccount(
                account_login=result["user"],
                display_name=result["user"],
                allow_custom=True,
                **custom_props,
            )
        )

    # Custom observable: when observable_field or observable_type_override is set,
    # create a single typed observable from the specified result field instead of
    # (or in addition to) the built-in src/dest/url multi-field logic.
    if observable_field != "observable_value" or observable_type_override:
        custom_obs_value = str(
            result.get(observable_field) or result.get("observable_value") or ""
        ).strip()
        if custom_obs_value and custom_obs_value.lower() not in invalid_values:
            obs_type = observable_type_override or detect_observable_type(
                custom_obs_value
            )
            if obs_type == "Text":
                helper.connector_logger.warning(
                    "[PARSER] Could not auto-detect observable type — falling back to Text",
                    {"value": custom_obs_value},
                )
            custom_obs = _build_observable(
                obs_type, custom_obs_value, custom_props, result
            )
            if custom_obs is not None:
                observables.append(custom_obs)
        # When a custom field/type is explicitly set, skip the built-in field logic below
        # by clearing src/dest so those blocks are no-ops (already appended custom obs above)
        result = dict(result)  # shallow copy so we don't mutate the caller's dict
        result["src"] = ""
        result["dest"] = ""

    # Handle source IP/hostname
    if result.get("src") and result["src"].lower() not in invalid_values:
        src_val = result["src"]
        if is_ipv4(src_val):
            observables.append(
                stix2.IPv4Address(value=src_val, allow_custom=True, **custom_props)
            )
        elif is_ipv6(src_val):
            observables.append(
                stix2.IPv6Address(value=src_val, allow_custom=True, **custom_props)
            )
        elif is_domain_name(src_val):
            observables.append(
                stix2.DomainName(value=src_val, allow_custom=True, **custom_props)
            )
        elif is_hostname(src_val):
            observables.append(
                CustomObservableHostname(
                    value=src_val, allow_custom=True, **custom_props
                )
            )

    # Handle destination IP/hostname
    if result.get("dest") and result["dest"].lower() not in invalid_values:
        dest_val = result["dest"]
        if is_hostname(dest_val):
            observables.append(
                CustomObservableHostname(
                    value=dest_val, allow_custom=True, **custom_props
                )
            )
        elif is_ipv4(dest_val):
            observables.append(
                stix2.IPv4Address(value=dest_val, allow_custom=True, **custom_props)
            )
        elif is_ipv6(dest_val):
            observables.append(
                stix2.IPv6Address(value=dest_val, allow_custom=True, **custom_props)
            )
        elif is_domain_name(dest_val):
            observables.append(
                stix2.DomainName(value=dest_val, allow_custom=True, **custom_props)
            )

    # Handle host observable (treat like a primary system identifier)
    if host_val and str(host_val).lower() not in invalid_values:
        if is_ipv4(host_val):
            observables.append(
                stix2.IPv4Address(value=host_val, allow_custom=True, **custom_props)
            )
        elif is_ipv6(host_val):
            observables.append(
                stix2.IPv6Address(value=host_val, allow_custom=True, **custom_props)
            )
        elif is_domain_name(host_val):
            observables.append(
                stix2.DomainName(value=host_val, allow_custom=True, **custom_props)
            )
        elif is_hostname(host_val):
            observables.append(
                CustomObservableHostname(
                    value=host_val, allow_custom=True, **custom_props
                )
            )

    # Handle file observables
    if result.get("file_hash") or result.get("file_name"):
        file_props = {}
        if result.get("file_name"):
            file_props["name"] = result["file_name"]
        if result.get("file_hash"):
            hash_type = get_hash_type(result["file_hash"])
            if hash_type:
                file_props["hashes"] = {hash_type: result["file_hash"]}

        # Create Directory object first if we have a path
        if result.get("file_path"):
            directory = stix2.Directory(
                path=result["file_path"], allow_custom=True, **custom_props
            )
            observables.append(directory)
            file_props["parent_directory_ref"] = directory.id

        if result.get("file_size"):
            file_props["size"] = int(result["file_size"])

        if file_props:  # Only create if we have any properties
            observables.append(
                stix2.File(allow_custom=True, **file_props, **custom_props)
            )
    helper.connector_logger.debug(f"[PARSER] Created {len(observables)} observables")

    # Parse Splunk event count — fall back to 1 for invalid values
    try:
        event_count = int(result.get("count") or 1)
        if event_count < 1:
            event_count = 1
    except (ValueError, TypeError):
        event_count = 1

    # Build human-readable sighting description
    if result.get("threat_description"):
        description = result["threat_description"]
    elif result.get("description"):
        description = result["description"]
    else:
        # Header: platform + optional template name
        if mapping and not mapping.get("skip"):
            dm_str = ", ".join(mapping.get("datamodels", [])) or "N/A"
            header_lines = [
                f"Observed in {mapping['vendor']} {mapping['product']}",
                f"sourcetype: {sourcetype_val}, data models: {dm_str}",
            ]
        else:
            header_lines = ["Observed in Splunk"]
        if template_name:
            header_lines.append(f"Search template: {template_name}")

        # sourcetype | index line
        # When mapping is set, sourcetype is already in the first header line;
        # only add index if present to avoid redundancy.
        st_val = _splunk_field(result, "sourcetype")
        idx_val = _splunk_field(result, "index")
        si_parts = []
        if not mapping and st_val:
            si_parts.append(f"sourcetype: {st_val}")
        if idx_val:
            si_parts.append(f"index: {idx_val}")
        if si_parts:
            header_lines.append(" | ".join(si_parts))

        # Detail fields — only lines where at least one value is present
        detail_lines = []

        # src → dest
        src_val = _splunk_field(result, "src", "src_ip")
        dest_val = _splunk_field(result, "dest", "dest_ip")
        if src_val or dest_val:
            sd_parts = []
            if src_val:
                sd_parts.append(f"src: {src_val}")
            if dest_val:
                sd_parts.append(f"dest: {dest_val}")
            _arrow = " \u2192 "
            detail_lines.append(_arrow.join(sd_parts))

        # action | direction
        action_val = _splunk_field(result, "action")
        direction_val = _splunk_field(result, "direction")
        ad_parts = []
        if action_val:
            ad_parts.append(f"action: {action_val}")
        if direction_val:
            ad_parts.append(f"direction: {direction_val}")
        if ad_parts:
            detail_lines.append(" | ".join(ad_parts))

        # bytes | bytes_in | bytes_out
        bytes_total = _splunk_field(result, "total_bytes", "bytes")
        bytes_in = _splunk_field(result, "total_bytes_in", "bytes_in")
        bytes_out = _splunk_field(result, "total_bytes_out", "bytes_out")
        b_parts = []
        if bytes_total:
            b_parts.append(f"bytes: {bytes_total}")
        if bytes_in:
            b_parts.append(f"bytes_in: {bytes_in}")
        if bytes_out:
            b_parts.append(f"bytes_out: {bytes_out}")
        if b_parts:
            detail_lines.append(" | ".join(b_parts))

        # app | user
        app_val = _splunk_field(result, "app")
        user_val = _splunk_field(result, "user")
        au_parts = []
        if app_val:
            au_parts.append(f"app: {app_val}")
        if user_val:
            au_parts.append(f"user: {user_val}")
        if au_parts:
            detail_lines.append(" | ".join(au_parts))

        # events
        detail_lines.append(f"events: {event_count}")

        # window
        e_time_val = _splunk_field(result, "e_time", "first_seen")
        l_time_val = _splunk_field(result, "l_time", "last_seen")
        if e_time_val or l_time_val:
            w_parts = []
            if e_time_val:
                w_parts.append(e_time_val)
            if l_time_val:
                w_parts.append(l_time_val)
            _arrow = " \u2192 "
            detail_lines.append(f"window: {_arrow.join(w_parts)}")

        if detail_lines:
            description = "\n".join(header_lines) + "\n\n" + "\n".join(detail_lines)
        else:
            description = "\n".join(header_lines)

    # Prefix description for unmapped sourcetypes so analysts can filter easily
    if _is_unmapped and sourcetype_val:
        description = (
            f"[UNMAPPED SOURCETYPE: {sourcetype_val}] "
            f"No platform mapping found for sourcetype '{sourcetype_val}'. "
            f"Defaulting to Splunk as the observing platform.\n\n"
            + description
        )

    # Prefer standardized names if present; fall back to e_time/l_time; finally _time
    first_seen = (
        _parse_ts(result.get("first_seen"))
        or _parse_ts(result.get("e_time"))
        or _parse_ts(result.get("_time"))
    )

    last_seen = (
        _parse_ts(result.get("last_seen"))
        or _parse_ts(result.get("l_time"))
        or first_seen
    )

    sighting_labels = ["unmapped-sourcetype"] if _is_unmapped else None
    for observable in observables:
        if isinstance(observable, SIGHTABLE_TYPES):
            confidence = int(result.get("confidence", 80))
            obs_str_value = _extract_observable_string_value(observable)
            sighting = create_sighting(
                observable_id=observable.id,
                author=author,
                source_identity=source_identity,
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=confidence,
                description=description,
                sighting_marking_id=sighting_marking_id,
                count=event_count,
                observable_value=obs_str_value,
                splunk_identity_id=_effective_creator_id,
                labels=sighting_labels,
            )
            sightings.append(sighting)
    helper.connector_logger.debug(f"[PARSER] Created {len(sightings)} sightings")
    return observables, source_identity, sightings
