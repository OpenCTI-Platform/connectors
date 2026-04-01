"""
USTA STIX 2.1 Converter.

Converts raw USTA Threat Stream API responses into valid STIX 2.1 objects
suitable for ingestion by OpenCTI.  Uses deterministic IDs via pycti's
generate_id() to ensure correct deduplication on the platform.

Handles six data families:
  - Malicious URLs           →  Indicator + IPv4-Addr / DomainName / URL + Malware SDO
  - Phishing Sites           →  Indicator + DomainName / URL
  - Malware Hashes           →  Indicator + File (StixFile) + Malware SDO
  - Compromised Credentials  →  Incident + UserAccount + URL + IPv4-Addr + Malware SDO + Note
  - Credit Card Tickets      →  Incident + Identity + Note
  - Deep Sight Tickets       →  Report + ThreatActor / Identity + Relationships + Note
"""

# pylint: disable=too-many-lines

from __future__ import annotations

import base64
import html as html_lib
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import stix2
from pycti import Identity as PyctiIdentity
from pycti import Incident as PyctiIncident
from pycti import Indicator as PyctiIndicator
from pycti import Malware as PyctiMalware
from pycti import Note as PyctiNote
from pycti import OpenCTIConnectorHelper
from pycti import Report as PyctiReport
from pycti import StixCoreRelationship
from pycti import ThreatActor as PyctiThreatActor


class ConverterToStix:
    """
    Converts USTA Threat Stream API records into STIX 2.1 objects for OpenCTI.

    Each public ``convert_*`` method accepts a single raw API record dict and
    returns a flat list of STIX objects (SDOs, SCOs, SROs) ready to be added
    to a bundle.  All IDs are generated deterministically so that re-importing
    the same record produces identical IDs, enabling correct deduplication on
    the OpenCTI platform.

    TLP is applied at the connector level via *tlp_level*, but individual Deep
    Sight ticket records may carry their own TLP that overrides the default.
    The connector must include all four standard TLP marking definitions in
    every bundle (available via ``TLP_MARKINGS``) to prevent
    ``cleanup_inconsistent_bundle`` from dropping objects whose per-record TLP
    differs from the connector default.
    """

    # Map motivation strings from the API to STIX 2.1 motivation vocabulary values
    _MOTIVATION_MAP: dict[str, str] = {
        "money": "personal-gain",
        "ideological": "ideology",
        "individual_satisfaction": "personal-satisfaction",
        "state_supported_operation": "organizational-gain",
    }

    # Map TLP level strings to their corresponding STIX 2.1 MarkingDefinition objects.
    # "clear" and "white" both resolve to TLP:WHITE for backwards compatibility.
    TLP_MARKING_MAP: dict[str, stix2.MarkingDefinition] = {
        "clear": stix2.TLP_WHITE,
        "white": stix2.TLP_WHITE,
        "green": stix2.TLP_GREEN,
        "amber": stix2.TLP_AMBER,
        "red": stix2.TLP_RED,
    }

    # All standard TLP marking definition objects — must be included in every
    # bundle so that cleanup_inconsistent_bundle never drops per-record TLP refs.
    TLP_MARKINGS: list[stix2.MarkingDefinition] = [
        stix2.TLP_WHITE,
        stix2.TLP_GREEN,
        stix2.TLP_AMBER,
        stix2.TLP_RED,
    ]

    # Base URL for deep-linking tickets back to the USTA portal via ExternalReference
    USTA_TICKET_BASE_URL = "https://usta.prodaft.com/intelligence/tickets/"

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        helper: OpenCTIConnectorHelper,
        author_name: str = "USTA",
        tlp_level: str = "amber",
        confidence_level: int = 80,
        store_credential_password: bool = False,
    ) -> None:
        """
        Initialise the converter with connector-wide defaults.

        Args:
            helper: OpenCTI connector helper, used for logging throughout
                conversion.
            author_name: Display name for the STIX Identity SDO that will be
                set as the ``created_by_ref`` on every produced object.
            tlp_level: Default TLP marking level applied to all produced
                objects.  Accepted values: ``"clear"``, ``"white"``,
                ``"green"``, ``"amber"``, ``"red"``.  Deep Sight ticket
                records may carry their own TLP that overrides this default.
            confidence_level: Integer 0–100 assigned to all produced STIX
                objects.
            store_credential_password: When ``True``, raw passwords from
                Account Takeover Prevention records are written to the STIX
                UserAccount credential field.  Disabled by default to avoid
                storing plaintext credentials in the platform.
        """
        self.helper = helper
        self.confidence = confidence_level
        self.store_credential_password = store_credential_password

        # TLP marking
        self.tlp_level = tlp_level.lower()
        self.tlp_marking: stix2.MarkingDefinition = self.TLP_MARKING_MAP.get(
            self.tlp_level, stix2.TLP_AMBER
        )

        # Author identity (deterministic ID)
        self.author = stix2.Identity(
            id=PyctiIdentity.generate_id(author_name, "organization"),
            name=author_name,
            identity_class="organization",
            description=(
                "USTA Threat Intelligence Platform — PRODAFT's threat-intelligence "
                "service covering malicious URLs, phishing sites, malware hashes, "
                "compromised credentials, credit-card fraud, and Deep Sight "
                "intelligence reports."
            ),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _escape_stix_value(value: str) -> str:
        """Escape backslashes and single quotes for STIX patterns."""
        return value.replace("\\", "\\\\").replace("'", "\\'")

    @staticmethod
    def _parse_datetime(value: str | None) -> str:
        """Safely parse an ISO datetime string, normalize to UTC with Z suffix."""
        if not value:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, AttributeError):
            return value

    @staticmethod
    def _extract_host(url_string: str) -> str:
        """Extract the host from a URL-like string, handling IPv6 literals and bare hosts."""
        if not url_string or url_string.startswith("/"):
            return ""

        # Full URL with scheme: http://host:port/path, http://[::1]:443/
        parsed = urlparse(url_string)
        if parsed.hostname:
            return parsed.hostname

        # Scheme-relative parse covers: bare "host", "host/path", "host:port",
        # bracketed "[::1]:port", and IPv4-with-port in one shot
        parsed = urlparse(f"//{url_string}")
        if parsed.hostname:
            return parsed.hostname

        # Last resort: raw IP literals that may be invalid in standard URL syntax.
        # First, handle bare IPv4/IPv6 like "2001:db8::1" which urlparse() cannot
        # treat as a hostname when unbracketed.
        try:
            ipaddress.ip_address(url_string)
            return url_string
        except ValueError:
            pass
            # Then handle unbracketed IPv6 with an appended port, e.g. "2001:db8::1:443".
        if ":" in url_string:
            host_candidate, _sep, _port = url_string.rpartition(":")
            if host_candidate:
                try:
                    ipaddress.ip_address(host_candidate)
                    return host_candidate
                except ValueError:
                    pass

        return ""

    @staticmethod
    def _is_ip(value: str) -> bool:
        """Return True if value is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """Return True if value is a valid IPv6 address."""
        try:
            return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
        except ValueError:
            return False

    @staticmethod
    def _strip_html(html_text: str) -> str:
        """Strip HTML tags, converting block elements to newlines and unescaping entities."""
        if not html_text:
            return ""
        text = re.sub(r"<br\s*/?>", "\n", html_text, flags=re.IGNORECASE)
        text = re.sub(r"</p>|</li>|</div>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(r"<li\s*>", "\n• ", text, flags=re.IGNORECASE)
        text = re.sub(r"<[^>]+>", "", text)
        text = html_lib.unescape(text)
        lines = [line.strip() for line in text.splitlines()]
        return "\n".join(line for line in lines if line).strip()

    def _make_usta_ext_ref(self, ticket_id: Any) -> stix2.ExternalReference | None:
        """Build an ExternalReference pointing to the USTA ticket portal URL."""
        if not ticket_id:
            return None
        return stix2.ExternalReference(
            source_name="USTA",
            url=f"{self.USTA_TICKET_BASE_URL}{ticket_id}",
            description=f"USTA ticket <#{ticket_id}>",
        )

    def _make_relationship(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        relationship_type: str,
        source_id: str,
        target_id: str,
        start_time: str | None = None,
        stop_time: str | None = None,
        tlp_marking: stix2.MarkingDefinition | None = None,
    ) -> stix2.Relationship:
        """Create a deterministic STIX Relationship."""
        marking = tlp_marking if tlp_marking is not None else self.tlp_marking
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type,
                source_id,
                target_id,
                start_time,
                stop_time,
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            start_time=start_time,
            stop_time=stop_time,
            created_by_ref=self.author.id,
            object_marking_refs=[marking.id],
            confidence=self.confidence,
            allow_custom=True,
        )

    def _create_malware_sdo(self, malware_name: str) -> stix2.Malware:
        """Create a STIX Malware SDO with deterministic ID."""
        return stix2.Malware(
            id=PyctiMalware.generate_id(malware_name),
            name=malware_name,
            is_family=True,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            confidence=self.confidence,
            allow_custom=True,
        )

    # ------------------------------------------------------------------
    # Observable creation helpers
    # ------------------------------------------------------------------

    def _create_ipv4_observable(self, ip_value: str) -> stix2.IPv4Address:
        """Create an IPv4-Addr SCO with deterministic ID.

        The stix2 library auto-generates a deterministic UUIDv5 based on
        the 'value' contributing property per the STIX 2.1 specification.
        """
        return stix2.IPv4Address(
            value=ip_value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )

    def _create_ipv6_observable(self, ip_value: str) -> stix2.IPv6Address:
        """Create an IPv6-Addr SCO with deterministic ID."""
        return stix2.IPv6Address(
            value=ip_value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )

    def _create_domain_observable(self, domain_value: str) -> stix2.DomainName:
        """Create a Domain-Name SCO with deterministic ID."""
        return stix2.DomainName(
            value=domain_value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )

    def _create_url_observable(self, url_value: str) -> stix2.URL:
        """Create a URL SCO with deterministic ID."""
        return stix2.URL(
            value=url_value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )

    def _create_file_observable(
        self,
        md5: str | None = None,
        sha1: str | None = None,
        sha256: str | None = None,
    ) -> stix2.File:
        """Create a File SCO with deterministic ID based on hash values.

        The stix2 library generates a deterministic UUIDv5 from the
        hashes dict (ID contributing property for File objects).
        """
        hashes: dict[str, str] = {}
        if md5:
            hashes["MD5"] = md5
        if sha1:
            hashes["SHA-1"] = sha1
        if sha256:
            hashes["SHA-256"] = sha256

        if not hashes:
            raise ValueError(
                "At least one hash value is required to create a File SCO."
            )

        return stix2.File(
            hashes=hashes,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )

    # ------------------------------------------------------------------
    # Public conversion methods (one per IOC family)
    # ------------------------------------------------------------------

    def convert_malicious_url(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        self, record: dict[str, Any]
    ) -> list:
        """
        Convert a single malicious-URL record to a list of STIX objects.

        Expected record shape (from API):
        {
            "id": "uuid",
            "url": "1.2.3.4:8080",
            "host": "1.2.3.4",
            "is_domain": false,
            "ip_addresses": ["1.2.3.4"],
            "tags": ["Ghost RAT"],
            "valid_from": "...",
            "valid_until": "...",
            "created": "..."
        }
        """
        stix_objects: list = []

        url_value = record.get("url", "")
        host_value = record.get("host", "") or self._extract_host(url_value)
        is_domain = record.get("is_domain", False)
        ip_addresses = record.get("ip_addresses", [])
        tags = record.get("tags", [])
        valid_from = self._parse_datetime(record.get("valid_from"))
        valid_until = self._parse_datetime(record.get("valid_until"))

        if not url_value:
            return stix_objects

        # --- Determine the main observable pattern ---
        observable_objects: list = []
        pattern_parts: list[str] = []

        if is_domain and host_value and not self._is_ip(host_value):
            # Domain observable
            domain_obs = self._create_domain_observable(host_value)
            observable_objects.append(domain_obs)
            pattern_parts.append(
                f"[domain-name:value = '{self._escape_stix_value(host_value)}']"
            )
        elif ip_addresses:
            for ip_addr in ip_addresses:
                escaped_ip = self._escape_stix_value(ip_addr)
                if self._is_ipv6(ip_addr):
                    ip_obs = self._create_ipv6_observable(ip_addr)
                    observable_objects.append(ip_obs)
                    pattern_parts.append(f"[ipv6-addr:value = '{escaped_ip}']")
                elif self._is_ip(ip_addr):
                    ip_obs = self._create_ipv4_observable(ip_addr)
                    observable_objects.append(ip_obs)
                    pattern_parts.append(f"[ipv4-addr:value = '{escaped_ip}']")
        elif host_value:
            escaped_host = self._escape_stix_value(host_value)
            if self._is_ip(host_value):
                ip_obs = self._create_ipv4_observable(host_value)
                observable_objects.append(ip_obs)
                pattern_parts.append(f"[ipv4-addr:value = '{escaped_host}']")
            else:
                domain_obs = self._create_domain_observable(host_value)
                observable_objects.append(domain_obs)
                pattern_parts.append(f"[domain-name:value = '{escaped_host}']")

        # Also create a URL observable if the url field contains a path or port.
        # Skip path-only values (starting with /) — prepending a scheme would
        # produce an invalid URL like http:///path/to/resource.
        if (
            url_value
            and not url_value.startswith("/")
            and ("/" in url_value or ":" in url_value)
        ):
            # Normalise to include scheme for URL observable if missing
            normalised_url = url_value
            if not normalised_url.startswith(("http://", "https://")):
                normalised_url = f"http://{normalised_url}"
            url_obs = self._create_url_observable(normalised_url)
            observable_objects.append(url_obs)
            # Include the full URL in the pattern to avoid collapsing distinct
            # URLs on the same host/IP into a single Indicator.
            escaped_url = self._escape_stix_value(normalised_url)
            pattern_parts.append(f"[url:value = '{escaped_url}']")

        stix_objects.extend(observable_objects)

        # --- Build the STIX pattern ---
        if not pattern_parts:
            # Path-only values (e.g. /api/path) cannot be given a valid absolute
            # URL scheme — no meaningful indicator can be created.
            if url_value.startswith("/"):
                return stix_objects
            # Fallback: treat entire url value as a URL pattern
            if not url_value.startswith(("http://", "https://")):
                url_value_norm = f"http://{url_value}"
            else:
                url_value_norm = url_value
            pattern = f"[url:value = '{self._escape_stix_value(url_value_norm)}']"
        elif len(pattern_parts) == 1:
            pattern = pattern_parts[0]
        else:
            pattern = " OR ".join(pattern_parts)

        # --- Create the Indicator ---
        indicator_name = url_value
        description_parts = ["Malicious URL indicator reported by USTA.\n"]
        if tags:
            description_parts.append(f"Associated malware: {', '.join(tags)}.")

        indicator = stix2.Indicator(
            id=PyctiIndicator.generate_id(pattern),
            name=indicator_name,
            description=" ".join(description_parts),
            pattern=pattern,
            pattern_type="stix",
            valid_from=valid_from,
            valid_until=valid_until,
            labels=["malicious-activity"] + [t.lower().replace(" ", "-") for t in tags],
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            confidence=self.confidence,
            custom_properties={
                "x_opencti_score": self.confidence,
                "x_opencti_main_observable_type": self._main_observable_type(
                    is_domain, host_value, ip_addresses
                ),
            },
        )
        stix_objects.append(indicator)

        # --- Relationships: indicator → observable ("based-on") ---
        for obs in observable_objects:
            rel = self._make_relationship(
                "based-on",
                indicator.id,
                obs.id,
                start_time=valid_from,
                stop_time=valid_until,
            )
            stix_objects.append(rel)

        # --- Malware SDOs from tags ---
        for tag in tags:
            malware_sdo = self._create_malware_sdo(tag)
            stix_objects.append(malware_sdo)
            # indicator "indicates" malware
            rel = self._make_relationship(
                "indicates",
                indicator.id,
                malware_sdo.id,
                start_time=valid_from,
                stop_time=valid_until,
            )
            stix_objects.append(rel)

        return stix_objects

    def convert_phishing_site(  # pylint: disable=too-many-locals
        self, record: dict[str, Any]
    ) -> list:
        """
        Convert a single phishing-site record to a list of STIX objects.

        Expected record shape (from API):
        {
            "id": 42936,
            "url": "http://yapikredi.world",
            "host": "",
            "is_domain": true,
            "ip_addresses": [],
            "country": "",
            "created": "2015-06-06T08:36:12.950000Z"
        }
        """
        stix_objects: list = []

        url_value = record.get("url", "")
        # is_domain = record.get("is_domain", False)
        ip_addresses = record.get("ip_addresses", [])
        created = self._parse_datetime(record.get("created"))

        if not url_value or url_value.startswith("/"):
            return stix_objects

        # Normalize to a full URL so the observable, pattern, and host extraction
        # are all consistent. Without a scheme, urlparse treats the whole string as
        # a path and yields no hostname.
        normalized_url = url_value if "://" in url_value else f"http://{url_value}"
        host_value = urlparse(normalized_url).hostname or ""

        observable_objects: list = []
        pattern_parts: list[str] = []

        # Create URL observable using the normalized value
        url_obs = self._create_url_observable(normalized_url)
        observable_objects.append(url_obs)
        pattern_parts.append(
            f"[url:value = '{self._escape_stix_value(normalized_url)}']"
        )

        # Create domain observable if applicable
        if host_value and not self._is_ip(host_value):
            domain_obs = self._create_domain_observable(host_value)
            observable_objects.append(domain_obs)

        # Create IP observables
        for ip_addr in ip_addresses:
            if ip_addr and self._is_ip(ip_addr):
                if self._is_ipv6(ip_addr):
                    ip_obs = self._create_ipv6_observable(ip_addr)
                else:
                    ip_obs = self._create_ipv4_observable(ip_addr)
                observable_objects.append(ip_obs)

        stix_objects.extend(observable_objects)

        # --- Build pattern (URL-centric for phishing) ---
        pattern = (
            pattern_parts[0]
            if pattern_parts
            else f"[url:value = '{self._escape_stix_value(normalized_url)}']"
        )

        indicator_name = f"{host_value or normalized_url}"

        indicator = stix2.Indicator(
            id=PyctiIndicator.generate_id(pattern),
            name=indicator_name,
            description="Phishing site identified by USTA threat intelligence.",
            pattern=pattern,
            pattern_type="stix",
            valid_from=created,
            labels=["malicious-activity", "phishing"],
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            confidence=self.confidence,
            custom_properties={
                "x_opencti_score": self.confidence,
                "x_opencti_main_observable_type": "Url",
            },
        )
        stix_objects.append(indicator)

        # Relationships: indicator → observables
        for obs in observable_objects:
            rel = self._make_relationship("based-on", indicator.id, obs.id)
            stix_objects.append(rel)

        return stix_objects

    def convert_malware_hash(  # pylint: disable=too-many-locals
        self, record: dict[str, Any]
    ) -> list:
        """
        Convert a single malware-hash record to a list of STIX objects.

        Expected record shape (from API):
        {
            "id": "uuid",
            "hashes": {
                "md5": "...",
                "sha1": "...",
                "sha256": "..."
            },
            "tags": ["Vidar"],
            "valid_from": "...",
            "valid_until": "...",
            "created": "..."
        }
        """
        stix_objects: list = []

        hashes = record.get("hashes", {})
        md5 = hashes.get("md5")
        sha1 = hashes.get("sha1")
        sha256 = hashes.get("sha256")
        tags = record.get("tags", [])
        valid_from = self._parse_datetime(record.get("valid_from"))
        valid_until = self._parse_datetime(record.get("valid_until"))

        if not (md5 or sha1 or sha256):
            return stix_objects

        # --- File observable ---
        file_obs = self._create_file_observable(md5=md5, sha1=sha1, sha256=sha256)
        stix_objects.append(file_obs)

        # --- STIX pattern ---
        pattern_components: list[str] = []
        if sha256:
            pattern_components.append(f"file:hashes.'SHA-256' = '{sha256}'")
        if sha1:
            pattern_components.append(f"file:hashes.'SHA-1' = '{sha1}'")
        if md5:
            pattern_components.append(f"file:hashes.MD5 = '{md5}'")

        pattern = "[" + " AND ".join(pattern_components) + "]"

        # --- Indicator ---
        display_hash = sha256 or sha1 or md5
        short_hash = (
            display_hash[:16] + "..." if len(display_hash) > 16 else display_hash
        )
        indicator_name = short_hash
        if tags:
            indicator_name = f"{tags[0]} - {short_hash}"

        description_parts = ["Malware hash indicator reported by USTA."]
        if tags:
            description_parts.append(f"Associated malware families: {', '.join(tags)}.")

        indicator = stix2.Indicator(
            id=PyctiIndicator.generate_id(pattern),
            name=indicator_name,
            description=" ".join(description_parts),
            pattern=pattern,
            pattern_type="stix",
            valid_from=valid_from,
            valid_until=valid_until,
            labels=["malicious-activity", "malware-hash"]
            + [t.lower().replace(" ", "-") for t in tags],
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            confidence=self.confidence,
            custom_properties={
                "x_opencti_score": self.confidence,
                "x_opencti_main_observable_type": "StixFile",
            },
        )
        stix_objects.append(indicator)

        # Relationship: indicator → file observable
        rel = self._make_relationship(
            "based-on",
            indicator.id,
            file_obs.id,
            start_time=valid_from,
            stop_time=valid_until,
        )
        stix_objects.append(rel)

        # --- Malware SDOs from tags ---
        for tag in tags:
            malware_sdo = self._create_malware_sdo(tag)
            stix_objects.append(malware_sdo)
            # indicator "indicates" malware
            rel = self._make_relationship(
                "indicates",
                indicator.id,
                malware_sdo.id,
                start_time=valid_from,
                stop_time=valid_until,
            )
            stix_objects.append(rel)

        return stix_objects

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _mask_card_number(card_number: str) -> str:
        """
        Mask a credit card number preserving BIN (first 6) and last 4 digits.
        Example: '4289691967078106' → '428969******8106'
        """
        cleaned = card_number.replace(" ", "").replace("-", "")
        if len(cleaned) < 10:
            return "*" * len(cleaned)
        return cleaned[:6] + "*" * (len(cleaned) - 10) + cleaned[-4:]

    def _create_user_account_observable(
        self,
        account_login: str,
        account_password: str,
        record_id: int | str = "",
        labels: list[str] | None = None,
    ) -> stix2.UserAccount:
        """Create a User-Account SCO with deterministic ID.

        User-Account has no ID-contributing properties in the STIX 2.1 spec,
        so stix2 would generate a random UUID each time. We manually build a
        deterministic UUIDv5 from the USTA API record ID so that the same API
        record always maps to the same STIX object without
        leaking the password into the ID.

        Args:
            account_password: Raw password — only stored in ``credential``
                when ``store_credential_password`` is enabled; never used
                for ID generation.
            record_id: The unique record ID returned by the USTA API.  Used
                as the primary deduplication key.
            labels: Optional list of label strings attached via
                x_opencti_labels (e.g. "corporate", "personal", "malware").
        """
        record_id_str = str(record_id).strip() if record_id is not None else ""
        if record_id_str:
            uuid_name = record_id_str
        else:
            if not account_login:
                raise ValueError(
                    "Cannot generate deterministic UserAccount ID: both record_id "
                    "and account_login are empty."
                )
            uuid_name = f"login:{account_login}"
        deterministic_id = "user-account--" + str(
            uuid.uuid5(
                uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"),
                name=uuid_name,
            )
        )
        custom: dict[str, Any] = {"x_opencti_created_by_ref": self.author.id}
        if labels:
            custom["x_opencti_labels"] = labels
        kwargs: dict[str, Any] = {
            "id": deterministic_id,
            "account_login": account_login,
            "object_marking_refs": [self.tlp_marking.id],
            "custom_properties": custom,
        }
        if self.store_credential_password:
            kwargs["credential"] = account_password
        return stix2.UserAccount(**kwargs)

    # ------------------------------------------------------------------
    # Compromised Credentials conversion
    # ------------------------------------------------------------------

    def convert_compromised_credential(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        self, record: dict[str, Any]
    ) -> list:
        """
        Convert a single compromised-credentials ticket to STIX objects.

        Expected record shape:
        {
            "id": 11185291,
            "status": "open",
            "created": "2026-01-19T09:46:44.942396Z",
            "content_type": "compromised-credentials",
            "company": {"id": 73, "name": "..."},
            "content": {
                "username": "user@example.com",
                "password": "...",
                "password_complexity": {"score": "weak", "length": 7, ...},
                "url": "https://login.example.com",
                "source": "malware" | "phishing_site",
                "is_corporate": true,
                "victim_detail": {  // may be null
                    "victim_uid": "...",
                    "country": "...",
                    "ip": "...",
                    "computer_name": "...",
                    "victim_os": "...",
                    "infection_date": "...",
                    "malware": "StealC",
                    ...
                }
            }
        }

        STIX mapping:
          - UserAccount SCO     (the compromised account)
          - URL SCO             (the targeted login URL)
          - Domain-Name SCO     (extracted from URL)
          - IPv4-Addr SCO       (victim machine IP, if victim_detail present)
          - Malware SDO         (stealer family, if victim_detail.malware present)
          - Incident SDO        (the account-takeover event)
          - Note SDO            (victim telemetry & password complexity — no raw password)
          - Relationships       (incident targets user-account, incident related-to
                                 observables, incident uses malware)

        IMPORTANT: Raw passwords are NOT stored by default.
        They are only placed in the User-Account ``credential`` field when
        ``store_credential_password`` is explicitly enabled.
        Only the password_complexity metadata is preserved otherwise.
        """
        stix_objects: list = []

        content = record.get("content", {})
        username = content.get("username", "")
        _password = content.get("password", "")
        target_url = content.get("url", "")
        source = content.get("source", "unknown")
        is_corporate = content.get("is_corporate", False)
        password_complexity = content.get("password_complexity", {})
        victim_detail = content.get("victim_detail")  # May be None
        created = self._parse_datetime(record.get("created"))
        ticket_id = record.get("id", "unknown")
        company = record.get("company", {})
        company_name = company.get("name", "Unknown Company")

        if not username:
            return stix_objects

        # --- UserAccount SCO ---
        # Labels classify the account type and the credential-theft vector so
        # analysts can filter UserAccount observables in OpenCTI directly.
        ua_labels = ["corporate" if is_corporate else "personal"]
        if source:
            ua_labels.append(source.replace("_", "-"))
        if password_complexity:
            score = password_complexity.get("score", "")
            if score:
                ua_labels.append(f"password-strength-{score}")

        user_account = self._create_user_account_observable(
            username, _password, record_id=ticket_id, labels=ua_labels
        )
        stix_objects.append(user_account)

        # UserAccount is always included in observable_scos so it receives a
        # `related-to` relationship from the Incident.  OpenCTI's schema does
        # not allow `targets` from an Incident to an SCO (only to SDOs such as
        # Identity/Location), so `related-to` is the correct relationship type
        # for all SCO links.
        observable_scos: list = [user_account]

        # --- URL SCO (target login page) ---
        # Skip path-only values — prepending a scheme would produce an invalid URL.
        if target_url and not target_url.startswith("/"):
            # Normalize once: ensures a valid URL SCO value and consistent parsing.
            normalised_target_url = (
                target_url if "://" in target_url else f"http://{target_url}"
            )
            url_obs = self._create_url_observable(normalised_target_url)
            stix_objects.append(url_obs)
            observable_scos.append(url_obs)
            # Direct link: user-account → related-to → url so the target URL
            # is visible on the UserAccount entity in OpenCTI.
            stix_objects.append(
                self._make_relationship("related-to", user_account.id, url_obs.id)
            )

            # Extract domain from the already-normalised URL
            hostname = urlparse(normalised_target_url).hostname or ""
            if hostname and not self._is_ip(hostname):
                domain_obs = self._create_domain_observable(hostname)
                stix_objects.append(domain_obs)
                observable_scos.append(domain_obs)

        # --- Victim IP (if victim_detail present) ---
        malware_name: str | None = None
        if victim_detail:
            victim_ip = victim_detail.get("ip", "")
            if victim_ip and self._is_ip(victim_ip):
                if self._is_ipv6(victim_ip):
                    ip_obs = self._create_ipv6_observable(victim_ip)
                else:
                    ip_obs = self._create_ipv4_observable(victim_ip)
                stix_objects.append(ip_obs)
                observable_scos.append(ip_obs)

            malware_name = victim_detail.get("malware")

        # --- Incident SDO ---
        incident_name = f"Compromised Credential: {username} (Ticket #{ticket_id})"

        description_lines = [
            f"Compromised credential detected by USTA (Ticket #{ticket_id}).",
            "",
            f"- Source: {source}",
            f"- Company: {company_name}",
        ]
        if is_corporate:
            description_lines.append("- Flagged as corporate credential")
        if password_complexity:
            score = password_complexity.get("score", "unknown")
            length = password_complexity.get("length", "?")
            description_lines.append(f"- Password strength: {score} (length: {length})")

        labels = ["compromised-credential", source.replace("_", "-")]
        if is_corporate:
            labels.append("corporate")

        ext_ref = self._make_usta_ext_ref(ticket_id)
        incident = stix2.Incident(
            id=PyctiIncident.generate_id(incident_name, created),
            name=incident_name,
            description="\n".join(description_lines),
            created=created,
            modified=created,
            labels=labels,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            confidence=self.confidence,
            allow_custom=True,
            external_references=[ext_ref] if ext_ref else None,
            custom_properties={
                "incident_type": "account-takeover",
                "source": "usta",
            },
        )
        stix_objects.append(incident)

        # --- Relationships: incident related-to all SCOs (user-account, url, domain, ip) ---
        for obs in observable_scos:
            stix_objects.append(
                self._make_relationship("related-to", incident.id, obs.id)
            )

        # --- Malware SDO from victim_detail ---
        if malware_name:
            malware_sdo = self._create_malware_sdo(malware_name)
            stix_objects.append(malware_sdo)
            stix_objects.append(
                self._make_relationship("uses", incident.id, malware_sdo.id)
            )

        # --- Note SDO: victim telemetry (no raw passwords) ---
        if victim_detail:
            note_content_parts = [
                f"**Compromised Credential Ticket #{ticket_id} — Victim Telemetry**",
                "",
                f"- Victim UID: {victim_detail.get('victim_uid', 'N/A')}",
                f"- OS Username: {victim_detail.get('username', 'N/A')}",
                f"- Country: {victim_detail.get('country', 'N/A')}",
                f"- Victim IP: {victim_detail.get('ip', 'N/A')}",
                f"- Computer Name: {victim_detail.get('computer_name', 'N/A')}",
                f"- OS: {victim_detail.get('victim_os', 'N/A')}",
                f"- CPU: {victim_detail.get('cpu', 'N/A')}",
                f"- Memory: {victim_detail.get('memory', 'N/A')}",
                f"- Infection Date: {victim_detail.get('infection_date', 'N/A')}",
                f"- Stealer Family: {victim_detail.get('malware', 'N/A')}",
            ]
            note_abstract = f"Victim telemetry for compromised credential: {username}"

            note = stix2.Note(
                id=PyctiNote.generate_id(created, note_content_parts[0]),
                abstract=note_abstract,
                content="\n".join(note_content_parts),
                created=created,
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp_marking.id],
                object_refs=[incident.id, user_account.id],
            )
            stix_objects.append(note)

        return stix_objects

    # ------------------------------------------------------------------
    # Credit Card Ticket conversion
    # ------------------------------------------------------------------

    def convert_credit_card_ticket(  # pylint: disable=too-many-locals
        self, record: dict[str, Any]
    ) -> list:
        """
        Convert a single credit card fraud ticket to STIX objects.

        Expected record shape:
        {
            "id": 591197,
            "status": "open",
            "created": "2019-03-08T10:17:46.865262Z",
            "content_type": "credit-card",
            "company": {"id": 73, "name": "API Integration Demo Company"},
            "content": {
                "number": "4289691967078106",
                "expiration_date": "2019-10-01"
            }
        }

        STIX mapping:
          - Incident SDO     (the fraud ticket itself)
          - Identity SDO     (the affected company / card issuer)
          - Note SDO         (masked card details)
          - Relationship     (incident → identity: "targets")

        IMPORTANT: Credit card numbers are masked to BIN (first 6) + last 4
        digits in all STIX objects.  Full PANs are NEVER stored.
        """
        stix_objects: list = []

        content = record.get("content", {})
        card_number_raw = content.get("number", "")
        expiration_date = content.get("expiration_date", "")
        created = self._parse_datetime(record.get("created"))
        ticket_id = record.get("id", "unknown")
        status = record.get("status", "unknown")
        company = record.get("company", {})
        company_name = company.get("name", "Unknown Company")

        if not card_number_raw:
            return stix_objects

        masked_number = self._mask_card_number(card_number_raw)
        # BIN is first 6 digits
        bin_prefix = card_number_raw.replace(" ", "").replace("-", "")[:6]

        # --- Company Identity SDO ---
        company_identity = stix2.Identity(
            id=PyctiIdentity.generate_id(company_name, "organization"),
            name=company_name,
            identity_class="organization",
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
        )
        stix_objects.append(company_identity)

        # --- Incident SDO ---
        usta_ticket_url = f"{self.USTA_TICKET_BASE_URL}{ticket_id}"
        ext_ref = self._make_usta_ext_ref(ticket_id)

        incident_name = f"{masked_number} (USTA Ticket <#{ticket_id}>)"
        incident_description = "\n".join(
            [
                "Credit card fraud ticket reported by USTA.",
                "",
                f"- Ticket ID: {ticket_id}",
                f"- Status: {status}",
                f"- BIN: {bin_prefix}",
                f"- Card (masked): {masked_number}",
                f"- Expiration: {expiration_date}",
                f"- Affected Company: {company_name}",
            ]
        )
        incident = stix2.Incident(
            id=PyctiIncident.generate_id(incident_name, created),
            name=incident_name,
            description=incident_description,
            created=created,
            modified=created,
            labels=["credit-card-fraud", "financial-crime"],
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            confidence=self.confidence,
            allow_custom=True,
            external_references=[ext_ref] if ext_ref else None,
            custom_properties={
                "incident_type": "credit-card-compromise",
                "severity": "high",
                "source": "usta",
            },
        )
        stix_objects.append(incident)

        # --- Relationship: incident targets company ---
        rel_targets = self._make_relationship(
            "targets", incident.id, company_identity.id
        )
        stix_objects.append(rel_targets)

        # --- Note SDO: card details (masked) ---
        note_content_parts = [
            f"**Credit Card Fraud Ticket #{ticket_id}**",
            "",
            f"- Card Number (masked): {masked_number}",
            f"- BIN: {bin_prefix}",
            f"- Expiration Date: {expiration_date}",
            f"- Status: {status}",
            f"- Affected Company: {company_name}",
            f"- USTA Ticket URL: {usta_ticket_url}",
        ]

        note = stix2.Note(
            id=PyctiNote.generate_id(created, note_content_parts[0]),
            abstract=f"Credit card compromise details for ticket #{ticket_id}",
            content="\n".join(note_content_parts),
            created=created,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            object_refs=[incident.id, company_identity.id],
        )
        stix_objects.append(note)

        return stix_objects

    # ------------------------------------------------------------------
    # Deep Sight Ticket conversion
    # ------------------------------------------------------------------

    def convert_deep_sight_ticket(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        self, record: dict[str, Any]
    ) -> list:
        """
        Convert a single Deep Sight intelligence ticket to STIX objects.

        Expected record shape (from API):
        {
            "id": 11309166,
            "status": "open",
            "created": "2026-03-05T07:30:03.581281Z",
            "content_type": "deep-sight",
            "company": {"id": 73, "name": "..."},
            "content": {
                "title": "[REGIONAL] Ransomware Attack...",
                "threat_actors": [
                    {"nickname": "DragonForce", "real_name": "", "country": "my",
                     "motivations": ["ideological"]}
                ],
                "targets": [
                    {"name": "Tenteks", "risk_score": "medium", "analyst_notes": "<p>...</p>"}
                ],
                "detected_platforms": ["sigint"],
                "analyst_notes": "<p>HTML analyst report text</p>",
                "tlp": "amber",
                "labels": ["ransomware"],
                "report": null | "<pre-signed CDN URL>",
                "detected_at": "2026-03-05T07:28:00Z",
                "markers": ["regional"]
            }
        }

        STIX mapping:
          - ThreatActor SDO  per content.threat_actors[] entry
          - Identity SDO     per content.targets[] entry (organization)
          - Relationship     ThreatActor "targets" Identity (per pair)
          - Report SDO       main container → appears in OpenCTI Analyses/Reports
        """
        stix_objects: list = []

        content = record.get("content") or {}
        ticket_id = record.get("id", "unknown")
        title = content.get("title", "")
        if not title:
            title = f"Deep Sight Ticket #{ticket_id}"
        created = self._parse_datetime(record.get("created"))
        status = record.get("status", "unknown")

        # Per-record TLP (overrides connector-level TLP for all objects in this ticket)
        tlp_key = str(content.get("tlp") or self.tlp_level).lower()
        record_tlp = self.TLP_MARKING_MAP.get(tlp_key, self.tlp_marking)

        analyst_notes = self._strip_html(content.get("analyst_notes", ""))
        threat_actors_data = content.get("threat_actors") or []
        targets_data = content.get("targets") or []
        labels_raw = content.get("labels") or []
        markers_raw = content.get("markers") or []

        # --- Threat Actor SDOs ---
        threat_actor_objs: list = []
        for ta in threat_actors_data:
            nickname = (ta.get("nickname") or ta.get("name") or "").strip()
            if not nickname or nickname.upper() == "N/A":
                continue

            motivations_raw = [str(m).lower() for m in (ta.get("motivations") or [])]
            mapped_motivations = [
                self._MOTIVATION_MAP.get(m, m) for m in motivations_raw if m
            ]

            kwargs: dict[str, Any] = {
                "id": PyctiThreatActor.generate_id(
                    name=nickname, opencti_type="Threat-Actor-Individual"
                ),
                "name": nickname,
                "threat_actor_types": ["unknown"],
                "created_by_ref": self.author.id,
                "object_marking_refs": [record_tlp.id],
                "confidence": self.confidence,
                "allow_custom": True,
            }
            if mapped_motivations:
                kwargs["primary_motivation"] = mapped_motivations[0]
            if len(mapped_motivations) > 1:
                kwargs["secondary_motivations"] = mapped_motivations[1:]

            threat_actor_objs.append(stix2.ThreatActor(id=kwargs.pop("id"), **kwargs))

        stix_objects.extend(threat_actor_objs)

        # --- Target Identity SDOs ---
        identity_objs: list = []
        for target in targets_data:
            target_name = (target.get("name") or "").strip()
            if not target_name or target_name.upper() == "N/A":
                continue

            identity = stix2.Identity(
                id=PyctiIdentity.generate_id(target_name, "organization"),
                name=target_name,
                identity_class="organization",
                created_by_ref=self.author.id,
                object_marking_refs=[record_tlp.id],
            )
            identity_objs.append(identity)

        stix_objects.extend(identity_objs)

        # --- Relationships: ThreatActor → Identity ("targets") ---
        rel_objs: list = []
        for ta_sdo in threat_actor_objs:
            for identity in identity_objs:
                rel = self._make_relationship(
                    "targets",
                    ta_sdo.id,
                    identity.id,
                    tlp_marking=record_tlp,
                )
                rel_objs.append(rel)

        stix_objects.extend(rel_objs)

        # --- Report SDO ---
        object_refs = [o.id for o in threat_actor_objs + identity_objs + rel_objs]
        if not object_refs:
            object_refs = [self.author.id]

        labels = [lbl for lbl in (labels_raw + markers_raw) if lbl]
        if status:
            labels.append(status)
        # Tag whether the record ships with a PDF attachment
        labels.append("has-attachment" if content.get("report") else "no-attachment")
        # Deduplicate while preserving order
        seen_labels: set[str] = set()
        unique_labels = []
        for lbl in labels:
            if lbl not in seen_labels:
                seen_labels.add(lbl)
                unique_labels.append(lbl)

        ext_ref = self._make_usta_ext_ref(ticket_id)

        # Embed report PDF directly in the STIX bundle so OpenCTI attaches it
        # to the Report entity atomically — no async timing issues.
        custom_properties: dict[str, Any] = {}
        pdf_data: bytes | None = record.get("_pdf_data")
        pdf_filename: str | None = record.get("_pdf_filename")
        if pdf_data and pdf_filename:
            custom_properties["x_opencti_files"] = [
                {
                    "name": pdf_filename,
                    "data": base64.b64encode(pdf_data).decode("utf-8"),
                    "mime_type": "application/pdf",
                    "no_trigger_import": True,
                    "object_marking_refs": [record_tlp.id],
                }
            ]

        report = stix2.Report(
            id=PyctiReport.generate_id(title, created),
            name=title,
            description=analyst_notes
            or f"Deep Sight intelligence ticket #{ticket_id}. Status: {status}.",
            published=created,
            report_types=["threat-report"],
            object_refs=object_refs,
            labels=unique_labels if unique_labels else ["deep-sight"],
            created=created,
            created_by_ref=self.author.id,
            object_marking_refs=[record_tlp.id],
            confidence=self.confidence,
            allow_custom=True,
            external_references=[ext_ref] if ext_ref else None,
            custom_properties=custom_properties,
        )
        stix_objects.append(report)

        return stix_objects

    @staticmethod
    def _main_observable_type(
        is_domain: bool,
        host_value: str,
        ip_addresses: list[str],
    ) -> str:
        """Determine the x_opencti_main_observable_type for an indicator."""
        if is_domain and host_value and not ConverterToStix._is_ip(host_value):
            return "Domain-Name"
        if ip_addresses:
            for addr_str in ip_addresses:
                try:
                    addr = ipaddress.ip_address(addr_str)
                    return (
                        "IPv6-Addr"
                        if isinstance(addr, ipaddress.IPv6Address)
                        else "IPv4-Addr"
                    )
                except ValueError:
                    continue
        if host_value:
            try:
                addr = ipaddress.ip_address(host_value)
                if isinstance(addr, ipaddress.IPv6Address):
                    return "IPv6-Addr"
                return "IPv4-Addr"
            except ValueError:
                return "Domain-Name"
        return "Url"
