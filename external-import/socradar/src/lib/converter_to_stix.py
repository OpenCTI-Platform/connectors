import re
from datetime import timedelta
from functools import lru_cache

import pycti
import stix2
import stix2.exceptions
from lib.api_client import RadarFeedItem

REGEX_PATTERNS = {
    "md5": r"^[a-fA-F\d]{32}$",
    "sha1": r"^[a-fA-F\d]{40}$",
    "sha256": r"^[a-fA-F\d]{64}$",
    "ipv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
    "ipv6": r"^(?:[a-fA-F\d]{1,4}:){7}[a-fA-F\d]{1,4}$",
    "domain": r"^(?=.{1,255}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,6}$",
    "url": r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
}


class ConverterError(Exception):
    """Custom wrapper for exceptions raised in ConverterToStix"""


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self):
        self.tlp_marking = stix2.TLP_WHITE

    @lru_cache
    def _create_organization_author(
        self, name: str, description: str
    ) -> stix2.Identity:
        """
        Create an author of type 'organization'. Uses `lru_cache` for performance.
        :return: Author as STIX2.1 Identity
        """
        author = stix2.Identity(
            id=pycti.Identity.generate_id(
                name=name,
                identity_class="organization",
            ),
            name=name,
            identity_class="organization",
            description=description,
        )
        return author

    def _is_pattern(self, value: str, pattern_name: str) -> bool:
        """
        Check if a value match a pattern type.
        :param value: Value to check
        :param pattern_name: Type of pattern
        :return: True if the value is of `pattern_name` type, otherwise False
        """
        return bool(re.match(REGEX_PATTERNS[pattern_name], value))

    def _create_stix_pattern(self, value: str, feed_type: str) -> str:
        """
        Build a STIX pattern from feed_type or fallback detection (handles ip, domain, url, hash, etc.).
        :param value: Indicator's value
        :param feed_type: Type of value
        :return: A STIX pattern
        """
        value_type = feed_type.lower()
        if value_type == "ip":
            if self._is_pattern(value, "ipv4"):
                return f"[ipv4-addr:value = '{value}']"
            elif self._is_pattern(value, "ipv6"):
                return f"[ipv6-addr:value = '{value}']"

        known_patterns = {
            "url": lambda v: f"[url:value = '{v}']",
            "domain": lambda v: f"[domain-name:value = '{v}']",
            "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
            "ipv6": lambda v: f"[ipv6-addr:value = '{v}']",
            "md5": lambda v: f"[file:hashes.'MD5' = '{v}']",
            "sha1": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
            "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
        }

        if value_type in known_patterns:
            return known_patterns[value_type](value)

        # Fallback detection
        for pattern_type, regex in REGEX_PATTERNS.items():
            if re.match(regex, value):
                # e.g. pattern_type == md5 -> "[file:hashes.'MD5' = '...']"
                if pattern_type in known_patterns:
                    return known_patterns[pattern_type](value)

        # Otherwise, custom
        return f"[x-custom:value = '{value}']"

    def process_on(
        self, feed_item: RadarFeedItem
    ) -> list[stix2.Identity | stix2.Indicator]:
        """
        Process a feed's item to create STIX2.1 Identity and Indicator.
        :param feed_item: SOCRadar feed's item to process
        :return: STIX2.1 Identity and Indicator
        """
        value = feed_item.feed
        if not value:
            raise ConverterError(
                "Missing required 'feed' value to create indicator",
                {"feed_item": feed_item},
            )

        feed_type = feed_item.feed_type or "ip"
        maintainer = feed_item.maintainer_name or "Unknown"

        valid_from = feed_item.first_seen_date
        valid_until = feed_item.latest_seen_date
        if valid_until <= valid_from:
            valid_until = valid_from + timedelta(hours=1)

        try:
            pattern = self._create_stix_pattern(value, feed_type)

            creator = self._create_organization_author(
                name=maintainer,
                description=f"Feed Provider: {maintainer}",
            )
            indicator = stix2.Indicator(
                id=pycti.Indicator.generate_id(pattern),
                name=f"{feed_type.upper()}: {value}",
                description=f"Source: {maintainer}\nValue: {value}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=valid_from,
                valid_until=valid_until,
                created_by_ref=creator.id,
                object_marking_refs=[self.tlp_marking],
                labels=["malicious-activity", feed_type],
            )

            return [creator, indicator]
        except stix2.exceptions.STIXError as err:
            raise ConverterError(
                "Error converting feed's item: {err}",
                {"feed_item": feed_item, "error": err},
            ) from err
