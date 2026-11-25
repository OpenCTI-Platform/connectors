"""Threats a GTI report links to in its text but not through its relationships.

GTI analysts link threat actors, malware families, campaigns and software
toolkits to their GTI page in the report content and analyst comment
(`https://www.virustotal.com/gui/collection/threat-actor--<uuid>`), often without
listing them in the report relationships. These links give the exact GTI
collection ID, unlike matching names, which also matches common words.
"""

import re
from collections.abc import Iterable

# GTI collection ID prefixes of threats. Software toolkits use "malware--" IDs,
# so their type is only known once the collection is fetched (collection_type).
LINKED_THREAT_PATTERN = re.compile(
    r"virustotal\.com/gui/collection/"
    r"((?:threat-actor|malware|campaign)--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
    r"-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)

# GTI collection_type -> report sub-entity type.
SUBENTITY_TYPE_BY_COLLECTION_TYPE: dict[str, str] = {
    "threat-actor": "threat_actors",
    "malware-family": "malware_families",
    "campaign": "campaigns",
    "software-toolkit": "software_toolkits",
}


def linked_threat_ids(texts: Iterable[object]) -> list[str]:
    """Return the GTI threat collection IDs linked in the texts, in order, once each.

    Values other than strings (e.g. a missing field) are skipped.
    """
    ids: dict[str, None] = {}
    for text in texts:
        if not isinstance(text, str):
            continue
        for match in LINKED_THREAT_PATTERN.finditer(text):
            ids.setdefault(match.group(1).lower(), None)
    return list(ids)


def subentity_type_of(collection: dict[str, object]) -> str | None:
    """Return the report sub-entity type of a raw GTI collection, if it is a threat."""
    attributes = collection.get("attributes")
    collection_type = (
        attributes.get("collection_type") if isinstance(attributes, dict) else None
    )
    return SUBENTITY_TYPE_BY_COLLECTION_TYPE.get(str(collection_type))
