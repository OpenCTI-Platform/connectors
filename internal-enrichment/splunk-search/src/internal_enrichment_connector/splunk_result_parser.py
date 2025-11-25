"""
Module for parsing Splunk search results into STIX observables.

This module provides functionality to convert Splunk search results into STIX 2.1
observables, handling various types of data including URLs, User-Agents, DNS queries,
IP addresses, hostnames, user accounts, and files.
"""

from datetime import datetime
from typing import Union, Optional, Tuple, List
import json
import pytz
from .utils import (
    get_hash_type,
    is_ipv4,
    is_ipv6,
    is_domain_name,
    is_hostname,
)
from pycti import (
    CustomObservableHostname,
    CustomObservableUserAgent,
    Identity,
    StixSightingRelationship,
)

import stix2


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
    """
    now = datetime.now(pytz.UTC)
    # Use provided timestamps or default to now
    first_seen_time = first_seen or now
    last_seen_time = last_seen or now

    sighting_props = {
        "id": StixSightingRelationship.generate_id(
            observable_id,
            source_identity.id if source_identity else author.id,
            first_seen_time,
            last_seen_time,
        ),
        "type": "sighting",
        "created": now,
        "modified": now,
        "created_by_ref": author.id,
        "where_sighted_refs": [source_identity.id if source_identity else author.id],
        # Use fake indicator ID in sighting_of_ref as per OpenCTI pattern
        "sighting_of_ref": "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e",
        "first_seen": first_seen_time,
        "last_seen": last_seen_time,
        "count": 1,
        "allow_custom": True,
        "x_opencti_sighting_of_ref": observable_id,
        "x_opencti_detection": True,
        "x_opencti_created_by_ref": author.id,
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

    return stix2.Sighting(**sighting_props)


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


def parse_observables_and_incident(
    helper,
    result: dict,
    author: stix2.Identity,
    marking_id: str = None,
    sighting_marking_id: str = None,
) -> Tuple[List[stix2.base._Observable], Optional[Identity], List[stix2.Sighting]]:
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

    # Handle Sourcetype as Software and (optionally) bind to a System (host)
    sourcetype_val = result.get("sourcetype")
    vendor_product = result.get("vendor_product")
    if sourcetype_val:
        helper.connector_logger.debug(
            f"[PARSER] Processing sourcetype: {sourcetype_val}"
        )
        # Always create a Software observable representing the sourcetype
        observables.append(
            stix2.Software(
                name=sourcetype_val,
                allow_custom=True,
                created_by_ref=author.id,
                **custom_props,
            )
        )

        # If we also have a host, upsert a System Identity for that host and
        # attach a normalized sourcetype label for fast filtering in OpenCTI
        if host_val and str(host_val).lower() not in invalid_values:
            try:
                st_label = f"sourcetype::{sourcetype_val}"
                system_identity = create_system_identity(
                    hostname=host_val,
                    author=author,
                    labels=[st_label],
                    marking_id=marking_id,
                    description=(
                        f"System '{host_val}' observed emitting sourcetype '{sourcetype_val}'"
                        + (
                            f" for vendor/product '{vendor_product}'"
                            if vendor_product
                            else ""
                        )
                    ),
                )
                source_identity = system_identity
                helper.connector_logger.debug(
                    f"[PARSER] Created/selected system identity for host: {host_val} with label {st_label}"
                )
            except Exception as e:
                helper.connector_logger.error(
                    f"[PARSER] Failed to create system identity for host '{host_val}': {e}"
                )

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
    # Use the system identity (if created) as the source of the sighting; falls back to author otherwise
    # Create sightings
    if result.get("threat_description"):
        description = result["threat_description"]
    elif result.get("description"):
        description = result["description"]
    else:
        description = f"{json.dumps(result)}"
    # Prefer standardized names if present; fall back to your e_time/l_time; finally _time
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
    for observable in observables:
        if isinstance(observable, SIGHTABLE_TYPES):  # Fixed the condition
            confidence = int(result.get("confidence", 80))
            sighting = create_sighting(
                observable_id=observable.id,
                author=author,
                source_identity=source_identity,
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=confidence,
                description=description,
                sighting_marking_id=sighting_marking_id,
            )
            sightings.append(sighting)
    helper.connector_logger.debug(f"[PARSER] Created {len(sightings)} sightings")
    return observables, source_identity, sightings
