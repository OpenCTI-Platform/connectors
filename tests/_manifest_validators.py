"""Shared manifest validators for test assertions.

We intentionally use simple predicate functions instead of a dataclass / Pydantic model:
- keep tests straightforward
- avoid adding Pydantic dependency in ci-requirements.txt
- enforce strict checks with no accidental type casting or implicit defaults
"""

from datetime import date
from typing import Any

VALID_USE_CASES = {
    "Adversary & Campaign Insights",
    "Vulnerability & Exploit Awareness",
    "Infrastructure & Attack Surface Visibility",
    "Detection & Response Enablement",
    "Fraud, Financial Crime & Cryptocurrency Monitoring",
    "Brand, Digital Risk & Underground Exposure",
    "Third-Party & Supply Chain Oversight",
    "Cloud, SaaS & Platform Security",
    "Geopolitical, Physical & Hybrid Risk Analysis",
    "Market Vertical & Mission-Specific Intelligence",
    "FIMI & Disinformation",
    "Other",
}

VALID_SOLUTION_CATEGORIES = {
    "Threat Intelligence Feed",
    "Endpoint Detection & Response",
    "SIEM & Security Analytics",
    "Malware Analysis & Sandbox",
    "SOAR & Security Automation",
    "Vulnerability & Exposure Management",
    "Attack Surface Management",
    "Network Security",
    "Email Security",
    "AI Security",
    "Incident Response & Case Management",
    "Digital Risk Protection",
    "Governance, Risk & Compliance",
    "Cloud Security",
    "Enrichment & Reputation",
    "Import, Export & Sharing",
    "Other",
}

VALID_LICENSE_TYPES = {
    "Free",
    "Commercial",
}
VALID_CONTAINER_TYPES = {
    "EXTERNAL_IMPORT",
    "INTERNAL_ENRICHMENT",
    "INTERNAL_EXPORT_FILE",
    "INTERNAL_IMPORT_FILE",
    "STREAM",
}
SOURCE_CODE_PREFIX = "https://github.com/OpenCTI-Platform/connectors/"
CONTAINER_IMAGE_PREFIX = "opencti/connector-"


# Validate by value


def is_valid_str(value: Any) -> bool:
    """Validate non-empty strings."""
    return isinstance(value, str) and value.strip() != ""


def is_boolean(value: Any) -> bool:
    """Validate that a value is a boolean."""
    return isinstance(value, bool)


def is_valid_date_str(value: Any) -> bool:
    """Validate that a value is a date string in ISO-8601 format."""
    try:
        date.fromisoformat(value)
        return True
    except (TypeError, ValueError):
        return False


# Validate by field


def is_valid_use_cases(value: Any) -> bool:
    """Validate allowed use_cases values and that there are 1 to 3 items."""
    return (
        isinstance(value, list)
        and 1 <= len(value) <= 3
        and all(isinstance(item, str) and item in VALID_USE_CASES for item in value)
    )


def is_valid_solution_categories(value: Any) -> bool:
    """Validate allowed solution_categories values and that there are 1 to 3 items."""
    return (
        isinstance(value, list)
        and 1 <= len(value) <= 3
        and all(
            isinstance(item, str) and item in VALID_SOLUTION_CATEGORIES
            for item in value
        )
    )


def is_valid_license_type(value: Any) -> bool:
    """Validate license_type as an accepted literal value."""
    return isinstance(value, str) and value in VALID_LICENSE_TYPES


def is_valid_max_confidence_level(value: Any) -> bool:
    """Validate max_confidence_level as an integer in the inclusive range 0..100."""
    return isinstance(value, int) and 0 <= value <= 100


def is_valid_source_code(value: Any) -> bool:
    """Validate source_code as a URL under the connectors repository prefix."""
    return isinstance(value, str) and value.startswith(SOURCE_CODE_PREFIX)


def is_valid_container_image(value: Any) -> bool:
    """Validate container_image against the expected image-name prefix."""
    return isinstance(value, str) and value.startswith(CONTAINER_IMAGE_PREFIX)


def is_valid_container_type(value: Any) -> bool:
    """Validate container_type against accepted connector type literals."""
    return value in VALID_CONTAINER_TYPES
