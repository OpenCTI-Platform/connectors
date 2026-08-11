"""Pure-function utilities for the Metras Stream connector.

No side effects, no HTTP, no STIX, no config access.
"""

import re


def slugify(value: str, max_len: int = 200) -> str:
    """Lowercase, hyphenated slug — for deterministic, stable names."""
    if not value:
        return "unnamed"
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower().strip()).strip("-")
    return (slug or "unnamed")[:max_len]
