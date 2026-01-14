"""
STIX 2.1 Converter

Converts Echo CTI IOC data to STIX 2.1 format.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from stix2 import Bundle, ExternalReference, Identity, Indicator


class STIXConverter:
    """Converts Echo CTI IOC data to STIX 2.1 format."""

    # Fixed UUID for Echo CTI (deterministic)
    ECHO_CTI_IDENTITY_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    # IOC type -> STIX pattern mapping
    PATTERN_MAPPING = {
        "ip": "[ipv4-addr:value = '{value}']",
        "ipv4": "[ipv4-addr:value = '{value}']",
        "ipv6": "[ipv6-addr:value = '{value}']",
        "ip-range": "[ipv4-addr:value = '{value}']",
        "url": "[url:value = '{value}']",
        "domain": "[domain-name:value = '{value}']",
        "hash": "[file:hashes.'{hash_type}' = '{value}']",
        "md5": "[file:hashes.'MD5' = '{value}']",
        "sha1": "[file:hashes.'SHA-1' = '{value}']",
        "sha256": "[file:hashes.'SHA-256' = '{value}']",
        "sha512": "[file:hashes.'SHA-512' = '{value}']",
        "email": "[email-addr:value = '{value}']",
    }

    # Hash type detection by length
    HASH_LENGTHS = {
        32: "MD5",
        40: "SHA-1",
        64: "SHA-256",
        128: "SHA-512",
    }

    def __init__(
        self,
        author_name: str = "Echo CTI",
        author_id: Optional[str] = None,
        default_confidence: int = 50,
        marking_refs: Optional[List[str]] = None,
    ):
        """
        Initialize the STIX converter.

        Args:
            author_name: Author name (for Identity)
            author_id: Custom author ID
            default_confidence: Default confidence level (0-100)
            marking_refs: Marking definition references
        """
        self.logger = logging.getLogger("stix_converter")
        self.author_name = author_name
        self.default_confidence = default_confidence
        self.marking_refs = marking_refs or []

        # Create Echo CTI Identity
        identity_id = author_id or f"identity--{self.ECHO_CTI_IDENTITY_UUID}"
        self.identity = Identity(
            id=identity_id,
            name=author_name,
            identity_class="organization",
            description="Echo CTI Threat Intelligence Platform",
        )

    def detect_ioc_type(self, value: str, hint_type: Optional[str] = None) -> str:
        """
        Detect IOC type from its value.

        Args:
            value: IOC value
            hint_type: Type hint from API

        Returns:
            IOC type
        """
        if hint_type:
            hint_type = hint_type.lower()
            if hint_type in self.PATTERN_MAPPING:
                return hint_type

        # URL check
        if re.match(r"^https?://", value, re.IGNORECASE):
            return "url"

        # IPv4 check
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return "ip"

        # IPv6 check
        if re.match(r"^[a-fA-F0-9:]+$", value) and ":" in value:
            return "ipv6"

        # IP range check (CIDR)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", value):
            return "ip-range"

        # Hash check (hex characters)
        if re.match(r"^[a-fA-F0-9]+$", value):
            hash_len = len(value)
            if hash_len in self.HASH_LENGTHS:
                return self.HASH_LENGTHS[hash_len].lower().replace("-", "")

        # Domain check
        if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$", value):
            return "domain"

        # Email check
        if re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
            return "email"

        # Default to domain
        return "domain"

    def get_hash_type(self, value: str) -> str:
        """Determine hash type from its value."""
        hash_len = len(value)
        return self.HASH_LENGTHS.get(hash_len, "SHA-256")

    def create_pattern(self, value: str, ioc_type: str) -> str:
        """
        Create STIX pattern.

        Args:
            value: IOC value
            ioc_type: IOC type

        Returns:
            STIX pattern string
        """
        # Escape special characters
        escaped_value = value.replace("\\", "\\\\").replace("'", "\\'")

        if ioc_type in ["hash", "md5", "sha1", "sha256", "sha512"]:
            hash_type = self.get_hash_type(value)
            pattern_template = self.PATTERN_MAPPING.get(
                "hash", "[file:hashes.'{hash_type}' = '{value}']"
            )
            return pattern_template.format(hash_type=hash_type, value=escaped_value)

        pattern_template = self.PATTERN_MAPPING.get(
            ioc_type, "[domain-name:value = '{value}']"
        )
        return pattern_template.format(value=escaped_value)

    def convert_ioc(
        self,
        ioc_data: Dict[str, Any],
        feed_type: Optional[str] = None,
    ) -> Optional[Indicator]:
        """
        Convert a single IOC to STIX Indicator.

        Args:
            ioc_data: IOC data
            feed_type: Feed type

        Returns:
            STIX Indicator object or None
        """
        try:
            # Get IOC value - check different field names
            value = (
                ioc_data.get("value")
                or ioc_data.get("indicator")
                or ioc_data.get("ioc")
                or ioc_data.get("data")
            )

            if not value:
                self.logger.warning(f"IOC value not found: {ioc_data}")
                return None

            # Determine type
            ioc_type = (
                ioc_data.get("type") or ioc_data.get("ioc_type") or feed_type
            )
            detected_type = self.detect_ioc_type(str(value), ioc_type)

            # Create STIX pattern
            pattern = self.create_pattern(str(value), detected_type)

            # Date information
            created_str = ioc_data.get("created_at") or ioc_data.get("first_seen")
            modified_str = ioc_data.get("updated_at") or ioc_data.get("last_seen")

            created = None
            modified = None

            if created_str:
                try:
                    if isinstance(created_str, str):
                        created = datetime.fromisoformat(
                            created_str.replace("Z", "+00:00")
                        )
                    elif isinstance(created_str, (int, float)):
                        created = datetime.fromtimestamp(created_str)
                except Exception:
                    pass

            if modified_str:
                try:
                    if isinstance(modified_str, str):
                        modified = datetime.fromisoformat(
                            modified_str.replace("Z", "+00:00")
                        )
                    elif isinstance(modified_str, (int, float)):
                        modified = datetime.fromtimestamp(modified_str)
                except Exception:
                    pass

            # Confidence level
            confidence = ioc_data.get("confidence", self.default_confidence)
            if isinstance(confidence, str):
                try:
                    confidence = int(confidence)
                except ValueError:
                    confidence = self.default_confidence

            # Build description
            description_parts = [f"Echo CTI IOC: {value}"]

            if ioc_data.get("vendor"):
                description_parts.append(f"Vendor: {ioc_data['vendor']}")

            if ioc_data.get("tag") or ioc_data.get("tags"):
                tags = ioc_data.get("tag") or ioc_data.get("tags")
                if isinstance(tags, list):
                    tags = ", ".join(tags)
                description_parts.append(f"Tags: {tags}")

            if ioc_data.get("state"):
                description_parts.append(f"State: {ioc_data['state']}")

            description = " | ".join(description_parts)

            # External references
            external_refs = []
            if ioc_data.get("source_url") or ioc_data.get("reference"):
                external_refs.append(
                    ExternalReference(
                        source_name="Echo CTI",
                        url=ioc_data.get("source_url") or ioc_data.get("reference"),
                    )
                )

            # Create Indicator
            indicator_kwargs = {
                "name": f"Echo CTI: {value}",
                "description": description,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": created or datetime.now(),
                "created_by_ref": self.identity.id,
                "confidence": min(100, max(0, confidence)),
                "labels": [detected_type, "echocti"],
                "id": Indicator.generate_id(pattern),
            }

            if modified:
                indicator_kwargs["modified"] = modified

            if external_refs:
                indicator_kwargs["external_references"] = external_refs

            if self.marking_refs:
                indicator_kwargs["object_marking_refs"] = self.marking_refs

            indicator = Indicator(id=indicator_kwargs["id"], **indicator_kwargs)
            return indicator

        except Exception as e:
            self.logger.error(f"IOC conversion error: {e} - Data: {ioc_data}")
            return None

    def convert_feeds(
        self,
        feeds: List[Dict[str, Any]],
        feed_type: Optional[str] = None,
    ) -> Bundle:
        """
        Convert IOC list to STIX Bundle.

        Args:
            feeds: IOC list
            feed_type: Feed type

        Returns:
            STIX Bundle
        """
        objects = [self.identity]
        converted_count = 0

        for ioc_data in feeds:
            indicator = self.convert_ioc(ioc_data, feed_type)
            if indicator:
                objects.append(indicator)
                converted_count += 1

        self.logger.info(
            f"Converted {converted_count} out of {len(feeds)} IOCs to STIX format"
        )

        return Bundle(objects=objects, allow_custom=True)
