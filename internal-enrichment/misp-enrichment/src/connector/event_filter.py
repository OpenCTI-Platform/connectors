"""Event-level filters applied to the MISP events retrieved for an enrichment."""

import re
from typing import Any

from connector.settings import MispConfig


def _org_identifiers(org: dict[str, Any] | None) -> set[str]:
    """Return the lower-cased name and UUID of a MISP organisation."""
    org = org or {}
    return {str(org[key]).strip().lower() for key in ("name", "uuid") if org.get(key)}


def _normalize(orgs: list[str]) -> set[str]:
    return {org.strip().lower() for org in orgs if org.strip()}


class EventFilter:
    """
    Keep a MISP event only if it satisfies every configured filter (logical AND):

    - its creator organisation (Event.Orgc) is in the include list, if any,
      and not in the exclude list;
    - its owner organisation (Event.Org) is in the include list, if any,
      and not in the exclude list;
    - its name (Event.info) matches the name regex, if any.

    Organisations are compared by name or UUID, case-insensitively.
    """

    def __init__(self, config: MispConfig) -> None:
        self.creator_orgs = _normalize(config.event_filter_creator_orgs)
        self.creator_orgs_not = _normalize(config.event_filter_creator_orgs_not)
        self.owner_orgs = _normalize(config.event_filter_owner_orgs)
        self.owner_orgs_not = _normalize(config.event_filter_owner_orgs_not)
        self.name_regex = (
            re.compile(config.event_filter_name_regex)
            if config.event_filter_name_regex
            else None
        )

    def accepts(self, event: dict[str, Any]) -> bool:
        creator = _org_identifiers(event.get("Orgc"))
        owner = _org_identifiers(event.get("Org"))

        if self.creator_orgs and not creator & self.creator_orgs:
            return False
        if creator & self.creator_orgs_not:
            return False
        if self.owner_orgs and not owner & self.owner_orgs:
            return False
        if owner & self.owner_orgs_not:
            return False
        if self.name_regex and not self.name_regex.search(event.get("info") or ""):
            return False
        return True
