"""Page sizes for GTI collection requests.

Threat actor and malware family objects are large: a page of 40 is 11-15 MB
(more with inline relationships). Responses that size were measured being cut
off mid-transfer 6 times in 8, which failed the whole collection for the run;
pages of 5 MB or less completed 8 times in 8. These types
are therefore fetched 10 per page (~3-4 MB); the others stay at the API's 40.
"""

DEFAULT_PAGE_LIMIT = 40

# Keyed by GTI collection_type (filter value).
COLLECTION_PAGE_LIMITS: dict[str, int] = {
    "threat-actor": 10,
    "malware-family": 10,
}

# Keyed by relationship sub-entity type (`/collections/{id}/{subentity_type}`).
SUBENTITY_PAGE_LIMITS: dict[str, int] = {
    "threat_actors": 10,
    "malware_families": 10,
}


def collection_page_limit(collection_type: str) -> int:
    """Return the page size for a GTI collection type."""
    return COLLECTION_PAGE_LIMITS.get(collection_type, DEFAULT_PAGE_LIMIT)


def subentity_page_limit(subentity_type: str) -> int:
    """Return the page size for a relationship sub-entity type."""
    return SUBENTITY_PAGE_LIMITS.get(subentity_type, DEFAULT_PAGE_LIMIT)
