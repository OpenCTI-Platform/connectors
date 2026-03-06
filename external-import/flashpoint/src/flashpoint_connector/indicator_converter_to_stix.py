import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address

import stix2
from connectors_sdk.models import (
    URL,
    AutonomousSystem,
    DomainName,
    EmailAddress,
    ExternalReference,
    File,
    Indicator,
    IPV4Address,
    IPV6Address,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType, TLPLevel
from pycti import OpenCTIConnectorHelper


class IndicatorConverterToStix:
    """Convert Flashpoint indicators into STIX/OpenCTI objects.

    This converter supports both regular indicator payloads and
    `extracted_config` payloads that may contain multiple IoCs.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_definition: str = "TLP:CLEAR",
    ):
        """Initialize converter dependencies and default marking.

        Args:
            helper: OpenCTI connector helper used for logging and object context.
            tlp_definition: TLP definition for generated indicator-related objects.
        """
        self.helper = helper
        self.author = self._create_author()
        tlp_level_mapping = {
            "TLP:CLEAR": TLPLevel.CLEAR,
            "TLP:GREEN": TLPLevel.GREEN,
            "TLP:AMBER": TLPLevel.AMBER,
            "TLP:AMBER+STRICT": TLPLevel.AMBER_STRICT,
            "TLP:RED": TLPLevel.RED,
        }
        self.marking = TLPMarking(level=tlp_level_mapping[tlp_definition])

    def _create_author(self) -> OrganizationAuthor:
        """Build the Flashpoint author object.

        Returns:
            OrganizationAuthor: Author used on generated STIX objects.
        """
        return OrganizationAuthor(
            name="Flashpoint",
            description=(
                "Flashpoint is a data and intelligence company that empowers "
                "customers to take rapid, decisive action to stop threats and reduce risk."
            ),
        )

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        """Parse ISO datetime string to a datetime object.

        Args:
            value: Datetime string, potentially ending with `Z`.

        Returns:
            datetime | None: Parsed datetime or `None` when invalid.
        """
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _extract_ioc_type(indicator: dict) -> str | None:
        """Extract IoC type from indicator payload.

        Args:
            indicator: Indicator payload dictionary.

        Returns:
            str | None: IoC type from `type` or fallback `ioc_type`.
        """
        value = indicator.get("type")
        if isinstance(value, str) and value:
            return value
        fallback_value = indicator.get("ioc_type")
        if isinstance(fallback_value, str) and fallback_value:
            return fallback_value
        return None

    @staticmethod
    def _extract_ioc_value(indicator: dict, ioc_type: str) -> str | None:
        """Extract IoC value from indicator payload.

        Args:
            indicator: Indicator payload dictionary.
            ioc_type: Previously resolved IoC type.

        Returns:
            str | None: IoC value from `value`/`ioc_value`, or hash fallback
            for file indicators.
        """
        raw_value = indicator.get("value")
        if isinstance(raw_value, str) and raw_value:
            return raw_value

        fallback_value = indicator.get("ioc_value")
        if isinstance(fallback_value, str) and fallback_value:
            return fallback_value

        if ioc_type.lower() == "file":
            hashes = indicator.get("hashes")
            if isinstance(hashes, dict):
                for algo in ["sha256", "sha1", "md5"]:
                    hash_value = hashes.get(algo)
                    if isinstance(hash_value, str) and hash_value:
                        return hash_value

        return None

    @staticmethod
    def _extract_file_ioc(indicator: dict) -> tuple[str, str] | None:
        """Resolve file IoC STIX path and value.

        Args:
            indicator: Indicator payload dictionary.

        Returns:
            tuple[str, str] | None: `(stix_path, ioc_value)` for file indicators,
            or `None` if no usable value is found.
        """
        hashes = indicator.get("hashes")
        if isinstance(hashes, dict):
            for algo, stix_path in [
                ("sha256", "hashes.SHA-256"),
                ("sha1", "hashes.SHA-1"),
                ("md5", "hashes.MD5"),
            ]:
                hash_value = hashes.get(algo)
                if isinstance(hash_value, str) and hash_value:
                    return stix_path, hash_value

        raw_ioc_value = indicator.get("value")
        if not isinstance(raw_ioc_value, str) or not raw_ioc_value:
            raw_ioc_value = indicator.get("ioc_value")

        if isinstance(raw_ioc_value, str) and raw_ioc_value:
            normalized_value = raw_ioc_value.strip()
            lowered_value = normalized_value.lower()

            if lowered_value.startswith("md5:"):
                return "hashes.MD5", normalized_value.split(":", maxsplit=1)[1].strip()
            if lowered_value.startswith("sha1:"):
                return (
                    "hashes.SHA-1",
                    normalized_value.split(":", maxsplit=1)[1].strip(),
                )
            if lowered_value.startswith("sha256:"):
                return (
                    "hashes.SHA-256",
                    normalized_value.split(":", maxsplit=1)[1].strip(),
                )

            if re.fullmatch(r"[A-Fa-f0-9]{32}", normalized_value):
                return "hashes.MD5", normalized_value
            if re.fullmatch(r"[A-Fa-f0-9]{40}", normalized_value):
                return "hashes.SHA-1", normalized_value
            if re.fullmatch(r"[A-Fa-f0-9]{64}", normalized_value):
                return "hashes.SHA-256", normalized_value

            return "name", normalized_value

        return None

    @staticmethod
    def _normalize_candidate_token(token: str) -> str:
        """Normalize a token extracted from free-form config.

        Args:
            token: Raw token.

        Returns:
            str: Stripped token without common wrappers.
        """
        return token.strip().strip("'\"[]()")

    @staticmethod
    def _guess_ioc_type_from_token(token: str) -> str | None:
        """Infer IoC type from a token value.

        Args:
            token: Candidate token.

        Returns:
            str | None: One of supported IoC types, otherwise `None`.
        """
        normalized_token = IndicatorConverterToStix._normalize_candidate_token(token)
        if not normalized_token:
            return None

        lowered = normalized_token.lower()
        if lowered in {"null", "none", "true", "false", "nan"}:
            return None

        if lowered.startswith(("http://", "https://", "ftp://")):
            return "url"

        if normalized_token.startswith("/"):
            return None

        host_candidate = normalized_token
        if normalized_token.count(":") == 1:
            host_part, port_part = normalized_token.rsplit(":", maxsplit=1)
            if port_part.isdigit():
                host_candidate = host_part

        try:
            parsed_ip = ip_address(host_candidate)
            return "ipv4-addr" if parsed_ip.version == 4 else "ipv6-addr"
        except ValueError:
            pass

        if (
            "." in host_candidate
            and " " not in host_candidate
            and re.fullmatch(r"[A-Za-z0-9.-]+", host_candidate)
            and not host_candidate.startswith(".")
            and not host_candidate.endswith(".")
            and ".." not in host_candidate
        ):
            return "domain"

        return None

    @staticmethod
    def _normalize_ioc_value_for_type(ioc_type: str, token: str) -> str:
        """Normalize IoC value according to its type.

        Args:
            ioc_type: Resolved IoC type.
            token: Raw token value.

        Returns:
            str: Normalized IoC value.
        """
        normalized_token = IndicatorConverterToStix._normalize_candidate_token(token)
        if ioc_type in {"ipv4-addr", "domain"} and normalized_token.count(":") == 1:
            host_part, port_part = normalized_token.rsplit(":", maxsplit=1)
            if port_part.isdigit():
                return host_part
        return normalized_token

    @staticmethod
    def _iter_extracted_config_values(
        value: str | list | dict, current_key: str | None = None
    ):
        """Yield flattened string values from nested extracted config payload.

        Args:
            value: Nested payload value.
            current_key: Optional key context propagated through recursion.

        Yields:
            tuple[str | None, str]: Key context and extracted string value.
        """
        if isinstance(value, dict):
            for key, nested_value in value.items():
                normalized_key = key.lower() if isinstance(key, str) else current_key
                yield from IndicatorConverterToStix._iter_extracted_config_values(
                    nested_value, normalized_key
                )
            return

        if isinstance(value, list):
            for nested_value in value:
                yield from IndicatorConverterToStix._iter_extracted_config_values(
                    nested_value, current_key
                )
            return

        if isinstance(value, str):
            yield current_key, value

    @staticmethod
    def _extract_iocs_from_extracted_config(indicator: dict) -> list[tuple[str, str]]:
        """Extract normalized IoCs from an `extracted_config` indicator.

        Args:
            indicator: Indicator payload containing extracted config content.

        Returns:
            list[tuple[str, str]]: Deduplicated `(ioc_type, ioc_value)` pairs.
        """
        raw_value = indicator.get("value")

        parsed_value: str | list | dict | None = None
        if isinstance(raw_value, (dict, list)):
            parsed_value = raw_value
        elif isinstance(raw_value, str):
            raw_value = raw_value.strip()
            if not raw_value:
                return []
            try:
                loaded_value = json.loads(raw_value)
                if isinstance(loaded_value, (dict, list, str)):
                    parsed_value = loaded_value
            except json.JSONDecodeError:
                parsed_value = raw_value

        if parsed_value is None:
            return []

        extracted_iocs: list[tuple[str, str]] = []
        seen_iocs: set[tuple[str, str]] = set()
        for _, string_value in IndicatorConverterToStix._iter_extracted_config_values(
            parsed_value
        ):
            for raw_token in re.split(r"[,\s]+", string_value):
                normalized_token = IndicatorConverterToStix._normalize_candidate_token(
                    raw_token
                )
                if not normalized_token:
                    continue

                ioc_type = IndicatorConverterToStix._guess_ioc_type_from_token(
                    normalized_token
                )
                if ioc_type is None:
                    continue

                normalized_ioc_value = (
                    IndicatorConverterToStix._normalize_ioc_value_for_type(
                        ioc_type, normalized_token
                    )
                )
                if not normalized_ioc_value:
                    continue

                ioc = (ioc_type, normalized_ioc_value)
                if ioc in seen_iocs:
                    continue

                seen_iocs.add(ioc)
                extracted_iocs.append(ioc)

        return extracted_iocs

    @staticmethod
    def _deduplicate_stix_objects(stix_objects: list) -> list:
        """Deduplicate STIX objects by object id while preserving order.

        Args:
            stix_objects: Raw STIX object list.

        Returns:
            list: Deduplicated STIX object list.
        """
        deduplicated_stix_objects = []
        seen_ids: set[str] = set()

        for stix_object in stix_objects:
            object_id = getattr(stix_object, "id", None)
            if isinstance(object_id, str):
                if object_id in seen_ids:
                    continue
                seen_ids.add(object_id)

            deduplicated_stix_objects.append(stix_object)

        return deduplicated_stix_objects

    @staticmethod
    def _resolve_score(indicator: dict) -> int:
        """Resolve OpenCTI score from indicator payload.

        Args:
            indicator: Indicator payload dictionary.

        Returns:
            int: Score in range 0-100.
        """
        score_tiers = {
            "informational": 20,
            "suspicious": 50,
            "malicious": 80,
        }

        nested_score = indicator.get("score")
        if isinstance(nested_score, dict):
            value = nested_score.get("value")
            if isinstance(value, str):
                return score_tiers.get(value.lower(), 50)
            if isinstance(value, (int, float)):
                return max(0, min(100, int(value)))

        return 50

    @staticmethod
    def _normalize_labels(raw_tags: list | None) -> list[str]:
        """Normalize and deduplicate indicator labels.

        Args:
            raw_tags: Raw tags payload.

        Returns:
            list[str]: Deduplicated string labels.
        """
        if raw_tags is None:
            return []

        labels = []
        for raw_tag in raw_tags:
            if isinstance(raw_tag, str):
                labels.append(raw_tag)

        return list(dict.fromkeys(labels))

    @staticmethod
    def _resolve_observable_definition(ioc_type: str) -> tuple[str, str, str] | None:
        """Map IoC type to STIX type/path and OpenCTI observable type.

        Args:
            ioc_type: Input IoC type.

        Returns:
            tuple[str, str, str] | None: `(stix_type, stix_path,
            opencti_main_observable_type)` mapping.
        """
        mapping = {
            "ipv4": ("ipv4-addr", "value", "IPv4-Addr"),
            "ipv4-addr": ("ipv4-addr", "value", "IPv4-Addr"),
            "ipv6": ("ipv6-addr", "value", "IPv6-Addr"),
            "ipv6-addr": ("ipv6-addr", "value", "IPv6-Addr"),
            "domain": ("domain-name", "value", "Domain-Name"),
            "domain-name": ("domain-name", "value", "Domain-Name"),
            "hostname": ("domain-name", "value", "Domain-Name"),
            "url": ("url", "value", "Url"),
            "email": ("email-addr", "value", "Email-Addr"),
            "email-addr": ("email-addr", "value", "Email-Addr"),
            "md5": ("file", "hashes.MD5", "StixFile"),
            "sha1": ("file", "hashes.SHA-1", "StixFile"),
            "sha256": ("file", "hashes.SHA-256", "StixFile"),
            "file": ("file", "name", "StixFile"),
            "file-md5": ("file", "hashes.MD5", "StixFile"),
            "file-sha1": ("file", "hashes.SHA-1", "StixFile"),
            "file-sha256": ("file", "hashes.SHA-256", "StixFile"),
            "file-name": ("file", "name", "StixFile"),
            "asn": ("autonomous-system", "number", "Autonomous-System"),
            "autonomous-system": ("autonomous-system", "number", "Autonomous-System"),
        }
        return mapping.get(ioc_type.lower())

    @staticmethod
    def _build_pattern(stix_type: str, stix_path: str, ioc_value: str) -> str | None:
        """Build a STIX pattern for a given observable value.

        Args:
            stix_type: STIX cyber observable type.
            stix_path: STIX object path.
            ioc_value: IoC value.

        Returns:
            str | None: STIX pattern string or `None` if value is invalid.
        """
        object_path = stix_path.split(".")
        value: str | int = ioc_value

        if stix_type == "autonomous-system" and stix_path == "number":
            value = ioc_value.replace("AS", "")
            if value.isdigit():
                value = int(value)
            else:
                return None

        lhs = stix2.ObjectPath(stix_type, object_path)
        return str(
            stix2.ObservationExpression(stix2.EqualityComparisonExpression(lhs, value))
        )

    def _create_observable(
        self,
        stix_type: str,
        stix_path: str,
        ioc_value: str,
        labels: list[str],
        score: int,
    ):
        """Create observable object matching the resolved STIX type/path.

        Args:
            stix_type: STIX observable type.
            stix_path: STIX path used in indicator pattern.
            ioc_value: Observable value.
            labels: Labels to attach to observables when supported.
            score: OpenCTI score.

        Returns:
            Any | None: SDK observable object, else `None`.
        """
        common_properties = {
            "labels": labels,
            "author": self.author,
            "markings": [self.marking],
            "score": score,
        }

        if stix_type == "ipv4-addr":
            return IPV4Address(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "ipv6-addr":
            return IPV6Address(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "domain-name":
            return DomainName(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "url":
            return URL(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "email-addr":
            return EmailAddress(
                value=ioc_value,
                **common_properties,
            )
        if stix_type == "autonomous-system":
            number = ioc_value.replace("AS", "")
            if number.isdigit():
                return AutonomousSystem(
                    number=int(number),
                    **common_properties,
                )
            return None
        if stix_type == "file":
            if stix_path == "name":
                return File(
                    name=ioc_value,
                    **common_properties,
                )
            if stix_path.startswith("hashes."):
                algorithm = stix_path.split(".")[1]
                hash_mapping = {
                    "MD5": HashAlgorithm.MD5,
                    "SHA-1": HashAlgorithm.SHA1,
                    "SHA-256": HashAlgorithm.SHA256,
                }
                hash_algorithm = hash_mapping.get(algorithm)
                if hash_algorithm is None:
                    return None
                return File(hashes={hash_algorithm: ioc_value}, **common_properties)

        return None

    def convert_indicator_to_stix(self, indicator: dict) -> list:
        """Convert a Flashpoint indicator payload into STIX objects.

        Args:
            indicator: Raw Flashpoint indicator payload.

        Returns:
            list: Generated STIX objects. Returns an empty list when conversion
            is not possible.
        """
        ioc_type = self._extract_ioc_type(indicator)
        if ioc_type is None:
            return []

        if ioc_type.lower() == "extracted_config":
            stix_objects = []
            for (
                extracted_ioc_type,
                extracted_ioc_value,
            ) in self._extract_iocs_from_extracted_config(indicator):
                normalized_indicator = dict(indicator)
                normalized_indicator["type"] = extracted_ioc_type
                normalized_indicator["value"] = extracted_ioc_value
                stix_objects.extend(
                    self.convert_indicator_to_stix(normalized_indicator)
                )
            return self._deduplicate_stix_objects(stix_objects)

        forced_file_stix_path = None
        if ioc_type.lower() == "file":
            file_ioc = self._extract_file_ioc(indicator)
            if file_ioc is not None:
                forced_file_stix_path, ioc_value = file_ioc
            else:
                ioc_value = self._extract_ioc_value(indicator, ioc_type)
        else:
            ioc_value = self._extract_ioc_value(indicator, ioc_type)

        if ioc_value is None:
            return []

        observable_definition = self._resolve_observable_definition(ioc_type)
        if observable_definition is None:
            return []

        stix_type, stix_path, opencti_main_observable_type = observable_definition
        if stix_type == "file" and isinstance(forced_file_stix_path, str):
            stix_path = forced_file_stix_path
        pattern = self._build_pattern(stix_type, stix_path, ioc_value)
        if pattern is None:
            return []

        created = self._parse_datetime(indicator.get("created_at"))
        modified = self._parse_datetime(indicator.get("modified_at"))
        first_seen = self._parse_datetime(indicator.get("first_seen_at"))
        last_seen = self._parse_datetime(indicator.get("last_seen_at"))

        valid_from = (
            first_seen or created or modified or last_seen or datetime.now(timezone.utc)
        )
        description = indicator.get("description") or ""

        labels = self._normalize_labels(indicator.get("tags"))
        score = self._resolve_score(indicator)

        external_references = []
        reference_url = indicator.get("href")
        if isinstance(reference_url, str) and reference_url:
            external_references.append(
                ExternalReference(source_name="Flashpoint", url=reference_url)
            )

        flashpoint_indicator_id = indicator.get("id")
        if flashpoint_indicator_id is not None and str(flashpoint_indicator_id):
            external_references.append(
                ExternalReference(
                    source_name="Flashpoint",
                    external_id=str(flashpoint_indicator_id),
                )
            )

        stix_indicator = Indicator(
            name=ioc_value,
            description=description,
            pattern_type="stix",
            pattern=pattern,
            valid_from=valid_from,
            author=self.author,
            markings=[self.marking],
            external_references=external_references,
            main_observable_type=opencti_main_observable_type,
            score=score,
        )

        stix_objects = [
            self.marking.to_stix2_object(),
            self.author.to_stix2_object(),
            stix_indicator.to_stix2_object(),
        ]

        stix_observable = self._create_observable(
            stix_type=stix_type,
            stix_path=stix_path,
            ioc_value=ioc_value,
            labels=labels,
            score=score,
        )
        if stix_observable is not None:
            stix_objects.append(stix_observable.to_stix2_object())
            stix_relationship = Relationship(
                type=RelationshipType.BASED_ON,
                source=stix_indicator,
                target=stix_observable,
                author=self.author,
                markings=[self.marking],
            )
            stix_objects.append(stix_relationship.to_stix2_object())

        return stix_objects
