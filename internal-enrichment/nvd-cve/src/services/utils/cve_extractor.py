import re
from typing import Any

# Matches standard CVE identifiers (e.g. CVE-2024-1234, CVE-2021-44228)
# Handles case-insensitivity and common defanging such as CVE[-]2024[-]1234 or CVE_2024_1234
# Operational bound: accept long identifiers while preventing oversized API queries.
# The final word boundary rejects longer suffixes entirely instead of truncating them.
CVE_REGEX = re.compile(
    r"\bCVE(?:\[-\]|[-_\u2010-\u2015])(\d{4})(?:\[-\]|[-_\u2010-\u2015])(\d{4,32})\b",
    re.IGNORECASE,
)


def extract_cve_ids(text: str | None) -> list[str]:
    """Extract and normalize unique CVE IDs from a text string, preserving order."""
    if not text or not isinstance(text, str):
        return []

    seen: set[str] = set()
    results: list[str] = []
    for match in CVE_REGEX.finditer(text):
        year, number = match.group(1), match.group(2)
        normalized = f"CVE-{year}-{number}"
        if normalized not in seen:
            seen.add(normalized)
            results.append(normalized)
    return results


def extract_cves_from_entity(
    stix_entity: dict[str, Any] | None,
    enrichment_entity: dict[str, Any] | None = None,
) -> list[str]:
    """Extract unique CVE identifiers from an entity's name, description, content, and fields.

    Inspects both the STIX dictionary representation (`stix_entity`) and the
    GraphQL resolved representation (`enrichment_entity`) across container and
    entity text fields (`name`, `description`, `content`, `x_opencti_content`,
    `abstract`, ` attribute_abstract`, `subject`).
    """
    stix_entity = stix_entity or {}
    enrichment_entity = enrichment_entity or {}

    candidate_fields = (
        "name",
        "description",
        "content",
        "x_opencti_content",
        "abstract",
        "attribute_abstract",
        "subject",
    )

    chunks: list[str] = []
    for source in (stix_entity, enrichment_entity):
        for field in candidate_fields:
            val = source.get(field)
            if isinstance(val, str) and val.strip():
                chunks.append(val)

    combined_text = "\n".join(chunks)
    return extract_cve_ids(combined_text)
