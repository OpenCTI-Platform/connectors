"""
OpenCTI relationship-schema check for STIX relationships.

OpenCTI rejects a stix-core-relationship whose type is not allowed between the
two entity types ("The relationship type X is not allowed between A and B"),
which surfaces as work errors in the UI. The authoritative list of allowed
types is served by the platform itself through the ``schemaRelationsTypesMapping``
GraphQL query: ``[{key: "<FromType>_<ToType>", values: [<relationship types>]}]``
with concrete OpenCTI entity types as keys. ``related-to`` and ``revoked-by``
are accepted between any two entities and are not listed in that mapping.

This replaces the former stix2-validator based check, which validated against
the STIX 2.1 *suggested* relationships (not OpenCTI's schema) and swapped
source/target on warnings, changing the meaning of the relationship.
"""

from typing import Any, Dict, Optional, Set

ALWAYS_ALLOWED_RELATIONSHIP_TYPES = {"related-to", "revoked-by"}

SCHEMA_QUERY = """
    query LuminarRelationsTypesMapping {
        schemaRelationsTypesMapping {
            key
            values
        }
    }
"""

# STIX type -> OpenCTI entity type for types whose mapping is unconditional.
_DIRECT_TYPES = {
    "attack-pattern": "Attack-Pattern",
    "campaign": "Campaign",
    "course-of-action": "Course-Of-Action",
    "grouping": "Grouping",
    "incident": "Incident",
    "indicator": "Indicator",
    "infrastructure": "Infrastructure",
    "intrusion-set": "Intrusion-Set",
    "malware": "Malware",
    "malware-analysis": "Malware-Analysis",
    "note": "Note",
    "observed-data": "Observed-Data",
    "opinion": "Opinion",
    "report": "Report",
    "tool": "Tool",
    "vulnerability": "Vulnerability",
    # Observables (pycti StixCyberObservable naming)
    "artifact": "Artifact",
    "autonomous-system": "Autonomous-System",
    "directory": "Directory",
    "domain-name": "Domain-Name",
    "email-addr": "Email-Addr",
    "email-message": "Email-Message",
    "file": "StixFile",
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "mac-addr": "Mac-Addr",
    "mutex": "Mutex",
    "network-traffic": "Network-Traffic",
    "process": "Process",
    "software": "Software",
    "url": "Url",
    "user-account": "User-Account",
    "windows-registry-key": "Windows-Registry-Key",
    "x509-certificate": "X509-Certificate",
}

_LOCATION_TYPES = {"Administrative-Area", "City", "Country", "Position", "Region"}

_IDENTITY_CLASSES = {
    "individual": "Individual",
    "class": "Sector",
    "system": "System",
    "securityplatform": "SecurityPlatform",
}


def resolve_opencti_type(stix_object: Dict[str, Any]) -> Optional[str]:
    """Return the OpenCTI entity type the platform will create for a STIX
    object, following the same rules as pycti's ``import_from_stix2``.

    Returns None when the type cannot be determined from the object alone.
    """
    stix_type = stix_object.get("type")
    if stix_type in _DIRECT_TYPES:
        return _DIRECT_TYPES[stix_type]
    if stix_type == "threat-actor":
        # pycti: any explicit type other than threat-actor-individual is a
        # Threat-Actor-Group.
        explicit = stix_object.get("x_opencti_type")
        if isinstance(explicit, str) and explicit:
            if explicit.lower() == "threat-actor-individual":
                return "Threat-Actor-Individual"
            return "Threat-Actor-Group"
        resource_level = stix_object.get("resource_level")
        if isinstance(resource_level, str) and resource_level.lower() == "individual":
            return "Threat-Actor-Individual"
        return "Threat-Actor-Group"
    if stix_type == "identity":
        return _IDENTITY_CLASSES.get(
            stix_object.get("identity_class", ""), "Organization"
        )
    if stix_type == "location":
        explicit = stix_object.get("x_opencti_location_type")
        if isinstance(explicit, str) and explicit:
            # Unknown values cannot be checked reliably.
            return explicit if explicit in _LOCATION_TYPES else None
        if "city" in stix_object:
            return "City"
        if "country" in stix_object:
            return "Country"
        if "region" in stix_object:
            return "Region"
        return "Position"
    return None


class RelationshipSchema:
    """Allowed relationship types per (from, to) OpenCTI entity type pair."""

    def __init__(self, mapping: Optional[Dict[str, Set[str]]]) -> None:
        # None means the schema is unknown: every check is inconclusive.
        self.mapping = mapping

    @property
    def available(self) -> bool:
        return self.mapping is not None

    @classmethod
    def from_platform(cls, api_client: Any, logger: Any) -> "RelationshipSchema":
        """Load the mapping from the connected OpenCTI platform.

        A failure is not fatal: the connector keeps running without the
        check, and the platform remains the final authority.
        """
        try:
            result = api_client.query(SCHEMA_QUERY)
            entries = result["data"]["schemaRelationsTypesMapping"]

            mapping: Dict[str, Set[str]] = {}
            for entry in entries:
                if not isinstance(entry, dict):
                    continue

                key = entry.get("key")
                if not isinstance(key, str) or not key:
                    continue

                values = entry.get("values")
                if not isinstance(values, list):
                    continue

                rel_types = {v for v in values if isinstance(v, str) and v}
                if not rel_types:
                    continue

                mapping[key] = rel_types

            logger.info(
                "[CONNECTOR] Loaded OpenCTI relationship schema",
                {"pairs": len(mapping)},
            )
            return cls(mapping)
        except Exception as err:  # pylint: disable=broad-exception-caught
            logger.warning(
                "[CONNECTOR] Could not load OpenCTI relationship schema; "
                "relationship types will not be checked",
                {"error": f"{err.__class__.__name__}: {err}"},
            )
            return cls(None)

    def is_allowed(
        self,
        relationship_type: str,
        source: Dict[str, Any],
        target: Dict[str, Any],
    ) -> Optional[bool]:
        """True/False when the platform schema decides, None when unknown."""
        if relationship_type in ALWAYS_ALLOWED_RELATIONSHIP_TYPES:
            return True
        if self.mapping is None:
            return None
        source_type = resolve_opencti_type(source)
        target_type = resolve_opencti_type(target)
        if source_type is None or target_type is None:
            return None
        return relationship_type in self.mapping.get(f"{source_type}_{target_type}", ())
