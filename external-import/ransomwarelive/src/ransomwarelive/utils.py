from datetime import datetime

import tldextract
import validators
from pydantic import TypeAdapter


def threat_description_generator(group_name: str, group_data) -> str:
    """
    Retrieve description of a group name

    Params:
        group_name: group name in string
        group_data: data json response
    Return:
        description in string
    """
    matching_items = [
        item for item in group_data if item.get("name", None) == group_name
    ]

    if matching_items and matching_items[0].get("description") not in [
        None,
        "",
        " ",
        "null",
    ]:
        description = matching_items[0].get("description", "No description available")
    else:
        description = "No description available"

    return description


def safe_datetime(value: str | None) -> datetime | None:
    """Safely parses a string into a naive datetime object (without timezone).
    Returns None if the input is None or not a valid ISO 8601 datetime string.
    Can avoid errors where fields are missing or incorrectly formed.

    Param:
        value: The input string to validate and convert to datetime.
    Return:
        datetime | None : A naive datetime object if the input is valid, otherwise None.
    Examples:
        self.safe_datetime("2025-01-01 07:20:50.000000", "attack_date")
        > datetime.datetime(2025, 1, 1, 7, 20, 50, 0)

        self.safe_datetime(None, "attack_date")
        > None

        self.safe_datetime("invalid-date", "attack_date")
        > None
    """
    return TypeAdapter(datetime).validate_python(value)


def is_domain(value: str) -> bool:
    """
    Valid domain name regex including internationalized domain name

    Param:
        value: domain in string
    Return:
        A boolean
    """
    return validators.domain(value)


def domain_extractor(url: str):
    """
    Extracts the domain from a URL

    Param:
        url: url in string
    Return:
        domain from url or None
    """
    if validators.domain(url):
        return url

    domain = tldextract.extract(url).top_domain_under_public_suffix
    if validators.domain(domain):
        return domain

    return None
