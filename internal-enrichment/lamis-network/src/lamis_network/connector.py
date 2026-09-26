# -*- coding: utf-8 -*-
"""Lamis Network OpenCTI internal-enrichment connector."""

import ipaddress
from typing import Any, Dict, List, Optional

from lamis_network.builder import (
    _MARKING_ID_TO_TLP,
    _TLP_MAP,
    LamisNetworkBuilder,
)
from lamis_network.client import LamisNetworkClient
from lamis_network.settings import ConnectorSettings
from pycti import Identity as PyctiIdentity
from pycti import OpenCTIConnectorHelper
from pydantic import SecretStr
from stix2 import Identity


def _normalize_tlp(value: Optional[str], fallback: str = "TLP:CLEAR") -> str:
    """Normalize TLP string to canonical TLP:LEVEL format."""
    if not value or not isinstance(value, str):
        return fallback
    normalized = value.strip().upper()
    if not normalized:
        return fallback
    if not normalized.startswith("TLP:"):
        normalized = f"TLP:{normalized}"
    return normalized


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in ("true", "1", "yes", "on"):
            return True
        if value.strip().lower() in ("false", "0", "no", "off"):
            return False
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise ValueError(f"Invalid boolean value: {value!r}")


def _validated_response(response: Any, ip_value: str) -> Optional[Dict[str, Any]]:
    """Reject incomplete or contradictory API data before any OpenCTI write."""
    if not isinstance(response, dict):
        return None
    score = response.get("fraud_score")
    if isinstance(score, bool) or not isinstance(score, int):
        return None
    if not 0 <= score <= 100:
        return None
    try:
        if response.get("ip") is not None and ipaddress.ip_address(
            response["ip"]
        ) != ipaddress.ip_address(ip_value):
            return None
    except (ValueError, TypeError):
        return None

    for field in ("country_code", "country", "city", "country_name"):
        val = response.get(field)
        if val is not None and not isinstance(val, str):
            return None

    geo = response.get("geo")
    if geo is not None:
        if not isinstance(geo, dict):
            return None
        for field in ("country_code", "country", "city", "country_name"):
            val = geo.get(field)
            if val is not None and not isinstance(val, str):
                return None

    asn = response.get("asn")
    if asn is not None:
        if not isinstance(asn, dict):
            return None
        for field in ("name", "org", "rir", "type"):
            val = asn.get(field)
            if val is not None and not isinstance(val, str):
                return None
        asn_num = asn.get("asn") or asn.get("number")
        if asn_num is not None:
            if isinstance(asn_num, bool):
                return None
            try:
                if isinstance(asn_num, str) and asn_num.upper().startswith("AS"):
                    num_val = int(asn_num[2:])
                else:
                    num_val = int(asn_num)
                if not 0 <= num_val <= 4294967295:
                    return None
            except (ValueError, TypeError):
                return None

    normalized = dict(response)
    normalized["fraud_score"] = int(score)
    for name in (
        "is_datacenter",
        "datacenter",
        "is_vpn",
        "vpn",
        "is_tor",
        "tor",
        "is_proxy",
        "proxy",
    ):
        if name in normalized and normalized[name] is not None:
            try:
                normalized[name] = _parse_bool(normalized[name])
            except ValueError:
                return None
    return normalized


_TLP_RANK = {
    "TLP:CLEAR": 0,
    "TLP:WHITE": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}


class LamisNetworkConnector:
    """Lamis Network internal-enrichment connector for OpenCTI."""

    def __init__(
        self,
        config: Optional[ConnectorSettings] = None,
        helper: Optional[OpenCTIConnectorHelper] = None,
    ) -> None:
        """Initialize connector configuration and client."""
        self.config = config or ConnectorSettings()
        self.helper = helper or OpenCTIConnectorHelper(
            config=self.config.to_helper_config(),
            playbook_compatible=True,
        )

        api_key_val = self.config.lamis_network.api_key
        self.api_key = (
            api_key_val.get_secret_value()
            if isinstance(api_key_val, SecretStr)
            else str(api_key_val or "")
        )
        self.api_url = str(self.config.lamis_network.api_url).rstrip("/")
        self.timeout = self.config.lamis_network.timeout
        self.suspicious_threshold = self.config.lamis_network.suspicious_threshold
        self.create_indicator = self.config.lamis_network.create_indicator
        self.add_relationships = self.config.lamis_network.add_relationships

        self.default_tlp = _normalize_tlp(self.config.lamis_network.default_tlp)
        self.max_tlp = _normalize_tlp(self.config.lamis_network.max_tlp)
        if self.default_tlp not in _TLP_MAP or self.max_tlp not in _TLP_MAP:
            raise ValueError(
                "LAMIS_NETWORK_DEFAULT_TLP and MAX_TLP must be known TLP levels"
            )
        if _TLP_RANK[self.default_tlp] > _TLP_RANK[self.max_tlp]:
            raise ValueError("LAMIS_NETWORK_DEFAULT_TLP exceeds MAX_TLP")

        self.author = Identity(
            id=PyctiIdentity.generate_id("Lamis Network", "organization"),
            name="Lamis Network",
            identity_class="organization",
            description="Lamis Network IP Intelligence & Fraud Scoring (Austria, EU)",
        )

        self.default_marking_refs = []
        if self.default_tlp in _TLP_MAP:
            self.default_marking_refs.append(_TLP_MAP[self.default_tlp].id)

        self.client = LamisNetworkClient(
            api_key=self.api_key,
            base_url=self.api_url,
            timeout=self.timeout,
        )

    def _resolve_marking_level(
        self,
        ref: str,
        object_marking_id_to_tlp: Dict[str, str],
        known_non_tlp_refs: set,
    ) -> Optional[str]:
        if ref in known_non_tlp_refs:
            return "NON_TLP"
        level = object_marking_id_to_tlp.get(ref) or _MARKING_ID_TO_TLP.get(ref)
        if level is not None:
            return level
        # Check platform marking definition if available
        if (
            hasattr(self.helper, "api")
            and self.helper.api
            and hasattr(self.helper.api, "marking_definition")
        ):
            try:
                m_data = self.helper.api.marking_definition.read(id=ref)
                if isinstance(m_data, dict):
                    m_type = str(m_data.get("definition_type", "")).upper()
                    if m_type == "TLP":
                        level = _normalize_tlp(
                            m_data.get("definition"), fallback="INVALID"
                        )
                        if level in _TLP_MAP:
                            object_marking_id_to_tlp[ref] = level
                            return level
                        return None
                    else:
                        known_non_tlp_refs.add(ref)
                        return "NON_TLP"
            except Exception:
                pass
        return None

    def _check_max_tlp(
        self,
        observable: Dict[str, Any],
        raise_on_invalid: bool = False,
        extra_stix_refs: Optional[List[str]] = None,
    ) -> bool:
        """Check if observable TLP is within configured max_tlp.

        :param extra_stix_refs: Additional ``object_marking_refs`` from the
            accompanying ``stix_entity``.  When ``enrichment_entity`` carries no
            markings, the default TLP is used as fallback — but the STIX
            representation of the same object can have more restrictive markings
            (e.g. TLP:RED) that should block the external API call.  Pass those
            refs here so they are always evaluated even when
            ``enrichment_entity`` is unmarked.
        """
        levels: List[str] = []
        raw_object_marking = observable.get("objectMarking")
        raw_marking_refs = observable.get("object_marking_refs")
        if raw_object_marking is not None and not isinstance(raw_object_marking, list):
            return False
        if raw_marking_refs is not None and not isinstance(raw_marking_refs, list):
            return False
        object_marking_id_to_tlp: Dict[str, str] = {}
        if isinstance(raw_object_marking, list):
            for marking in raw_object_marking:
                if not isinstance(marking, dict):
                    return False
                if str(marking.get("definition_type", "")).upper() == "TLP":
                    level = _normalize_tlp(
                        marking.get("definition"), fallback="INVALID"
                    )
                    if level not in _TLP_MAP:
                        return False
                    if not marking.get("standard_id"):
                        return False
                    object_marking_id_to_tlp[marking["standard_id"]] = level
                    levels.append(level)

        known_non_tlp_refs = {
            marking.get("standard_id")
            for marking in (raw_object_marking or [])
            if isinstance(marking, dict)
            and str(marking.get("definition_type", "")).upper() != "TLP"
        }

        if isinstance(raw_marking_refs, list):
            for ref in raw_marking_refs:
                if not isinstance(ref, str):
                    return False
                res = self._resolve_marking_level(
                    ref, object_marking_id_to_tlp, known_non_tlp_refs
                )
                if res is None:
                    return False
                if res != "NON_TLP":
                    levels.append(res)

        # Also evaluate markings carried on stix_entity even when
        # enrichment_entity has none, to prevent the fallback to default_tlp
        # from silently allowing a TLP:RED STIX object through.
        # An unrecognized marking ID is treated as a failed TLP check — we
        # cannot evaluate it, so the safe course is to block the API call.
        # Known non-TLP markings (e.g. PAP in objectMarking) are recognized and skipped.
        if extra_stix_refs and isinstance(extra_stix_refs, list):
            seen_in_levels = set(levels)
            for ref in extra_stix_refs:
                if not isinstance(ref, str):
                    return False
                res = self._resolve_marking_level(
                    ref, object_marking_id_to_tlp, known_non_tlp_refs
                )
                if res is None:
                    # Unknown marking — cannot evaluate; block external API call
                    return False
                if res != "NON_TLP" and res not in seen_in_levels:
                    levels.append(res)
                    seen_in_levels.add(res)

        valid = all(
            OpenCTIConnectorHelper.check_max_tlp(level, self.max_tlp)
            for level in (levels or [self.default_tlp])
        )
        if not valid and raise_on_invalid:
            raise ValueError(
                f"[Lamis Network] Observable TLP exceeds maximum allowed ({self.max_tlp})"
            )
        return valid

    def _extract_ip_value(self, observable: Dict[str, Any]) -> Optional[str]:
        """Extract IP address value from observable."""
        return observable.get("value") or observable.get("observable_value")

    def _format_description(
        self, ip: str, data: Dict[str, Any], fraud_score: int
    ) -> str:
        """Build Markdown summary of Lamis Network intelligence."""
        lines = [
            f"### Lamis Network IP Intelligence: `{ip}`",
            f"- **Fraud Risk Score:** `{fraud_score}/100`",
        ]

        asn_info = data.get("asn") or {}
        raw_asn = asn_info.get("asn") or data.get("asn_number")
        asn_name = asn_info.get("name") or data.get("asn_name") or data.get("asn_org")
        if raw_asn is not None and not isinstance(raw_asn, (bool, float)):
            try:
                if isinstance(raw_asn, str) and raw_asn.upper().startswith("AS"):
                    clean_asn = int(raw_asn[2:])
                else:
                    clean_asn = int(raw_asn)
                lines.append(
                    f"- **Autonomous System:** `AS{clean_asn}` ({asn_name or 'N/A'})"
                )
            except (ValueError, TypeError):
                display_asn = str(raw_asn)
                if not display_asn.upper().startswith("AS"):
                    display_asn = f"AS{display_asn}"
                lines.append(
                    f"- **Autonomous System:** `{display_asn}` ({asn_name or 'N/A'})"
                )

        geo = data.get("geo") or {}
        country = geo.get("country") or data.get("country") or geo.get("country_code")
        city = geo.get("city") or data.get("city")
        if country or city:
            loc_str = f"{city}, {country}" if city and country else (country or city)
            lines.append(f"- **Location:** {loc_str}")

        flags = []
        if data.get("is_datacenter") or data.get("datacenter"):
            flags.append("Datacenter / Hosting")
        if data.get("is_vpn") or data.get("vpn"):
            flags.append("VPN")
        if data.get("is_tor") or data.get("tor"):
            flags.append("Tor Exit Node")
        if data.get("is_proxy") or data.get("proxy"):
            flags.append("Public Proxy")

        if flags:
            lines.append(f"- **Infrastructure:** {', '.join(flags)}")

        return "\n".join(lines)

    def _send_passthrough_bundle(self, stix_objects: List[Any]) -> None:
        """Forward unmodified incoming stix_objects preserving existing markings and references."""
        if not stix_objects:
            return
        # Do not use cleanup_inconsistent_bundle=True on pass-through bundles:
        # the connector did not modify these objects, and cleanup would strip
        # object_marking_refs pointing to platform-persisted marking definitions.
        self.helper.send_stix2_bundle(
            self.helper.stix2_create_bundle(stix_objects),
            cleanup_inconsistent_bundle=False,
        )

    def _process_message(self, data: Dict[str, Any]) -> str:
        """Process incoming OpenCTI enrichment event."""
        observable = data.get("enrichment_entity")
        if not observable:
            raise ValueError("Observable not found in enrichment event data.")

        stix_objects = data["stix_objects"] if "stix_objects" in data else []

        entity_type = observable.get("entity_type")
        if entity_type not in ("IPv4-Addr", "IPv6-Addr"):
            if not data.get("event_type"):
                self._send_passthrough_bundle(stix_objects)
                return f"Unsupported entity type {entity_type}; passed through original bundle."
            raise ValueError(f"Unsupported observable entity type: {entity_type}")

        ip_value = self._extract_ip_value(observable)
        if not ip_value:
            raise ValueError("Missing IP address value on observable.")
        try:
            parsed_ip = ipaddress.ip_address(ip_value)
        except ValueError as exc:
            raise ValueError("Invalid IP address on observable") from exc
        if (parsed_ip.version == 4) != (entity_type == "IPv4-Addr"):
            raise ValueError("IP address family does not match observable type")

        # Ensure observable has standard_id normalized from id if absent
        if not observable.get("standard_id") and observable.get("id"):
            observable["standard_id"] = observable["id"]

        obs_standard_id = observable.get("standard_id")
        if not obs_standard_id:
            raise ValueError("Missing identifier (standard_id/id) on observable.")

        # TLP Check before calling external API.
        # Also pass stix_entity's object_marking_refs: enrichment_entity may
        # carry no markings while its STIX representation has TLP:RED.
        stix_entity = data.get("stix_entity")
        stix_entity_refs: List[str] = []
        if isinstance(stix_entity, dict):
            raw_refs = stix_entity.get("object_marking_refs")
            if raw_refs is not None:
                if not isinstance(raw_refs, list) or not all(
                    isinstance(r, str) for r in raw_refs
                ):
                    raise ValueError(
                        "Malformed object_marking_refs on stix_entity; "
                        "expected list of marking reference strings."
                    )
                stix_entity_refs = raw_refs
        if not self._check_max_tlp(observable, extra_stix_refs=stix_entity_refs):
            self.helper.connector_logger.info(
                f"[Lamis Network] Skipping {ip_value}: TLP exceeds "
                f"configured maximum ({self.max_tlp})"
            )
            self._send_passthrough_bundle(stix_objects)
            return f"Observable {ip_value} skipped due to TLP restrictions."

        # Validate the STIX entity before querying the external API so that
        # malformed events neither disclose an IP unnecessarily nor attach
        # intelligence to the wrong observable.
        if not isinstance(stix_entity, dict):
            raise ValueError(
                "Missing stix_entity in enrichment event; "
                "cannot enrich without a valid STIX observable."
            )
        stix_id = stix_entity.get("id")
        if not stix_id:
            raise ValueError("Missing 'id' on stix_entity in enrichment event.")
        if stix_id != obs_standard_id:
            raise ValueError(
                f"STIX entity ID {stix_id!r} does not match "
                f"observable standard_id {obs_standard_id!r}"
            )
        stix_value = stix_entity.get("value")
        if not stix_value or not isinstance(stix_value, str):
            raise ValueError(
                "Missing or invalid 'value' on stix_entity in enrichment event."
            )
        try:
            parsed_stix_ip = ipaddress.ip_address(stix_value.strip())
        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address value {stix_value!r} on stix_entity"
            ) from exc

        if parsed_stix_ip != parsed_ip:
            raise ValueError(
                f"STIX entity IP {stix_value!r} ({parsed_stix_ip}) does not match "
                f"observable IP {ip_value!r} ({parsed_ip})"
            )

        expected_stix_type = "ipv4-addr" if entity_type == "IPv4-Addr" else "ipv6-addr"
        stix_type = stix_entity.get("type")
        if not stix_type or stix_type != expected_stix_type:
            raise ValueError(
                f"STIX entity type {stix_type!r} does not match "
                f"expected type {expected_stix_type!r} for {entity_type}"
            )

        self.helper.connector_logger.info(
            f"[Lamis Network] Querying IP intelligence for {ip_value}"
        )
        response = self.client.get_ip_reputation(ip_value)

        response = _validated_response(response, ip_value)
        if response is None:
            self.helper.connector_logger.warning(
                f"[Lamis Network] No valid data returned for {ip_value}; "
                "existing knowledge preserved."
            )
            self._send_passthrough_bundle(stix_objects)
            return f"Lamis Network: no intelligence available for {ip_value}."

        fraud_score = response["fraud_score"]

        # Infrastructure flags: distinguish explicitly True, explicitly False,
        # and omitted (None) to ensure partial responses (e.g. /v1/score fallback)
        # do not erase previously recorded classifications.
        evaluated_flags: Dict[str, Optional[bool]] = {}

        def _get_flag(primary: str, fallback: str) -> Optional[bool]:
            if primary in response and response[primary] is not None:
                return bool(response[primary])
            if fallback in response and response[fallback] is not None:
                return bool(response[fallback])
            return None

        evaluated_flags["datacenter"] = _get_flag("is_datacenter", "datacenter")
        evaluated_flags["vpn"] = _get_flag("is_vpn", "vpn")
        evaluated_flags["tor-exit-node"] = _get_flag("is_tor", "tor")
        evaluated_flags["public-proxy"] = _get_flag("is_proxy", "proxy")
        evaluated_flags["suspicious"] = fraud_score >= self.suspicious_threshold

        labels: List[str] = [lbl for lbl, val in evaluated_flags.items() if val is True]

        builder = LamisNetworkBuilder(
            helper=self.helper,
            author=self.author,
            observable=observable,
            default_marking_refs=self.default_marking_refs,
            stix_objects=stix_objects,
            stix_entity_marking_refs=stix_entity_refs,
        )

        # Put the observable update in the same STIX bundle as the new entities.
        builder.enrich_observable(
            stix_entity,
            fraud_score,
            labels,
            evaluated_flags=evaluated_flags,
        )

        # 2. Add ASN entity and belongs-to relationship
        if self.add_relationships:
            # Merge nested and top-level ASN fields so partial data is preserved.
            asn_data = dict(response.get("asn") or {})
            if response.get("asn_number"):
                asn_data.setdefault("asn", response["asn_number"])
            asn_name = response.get("asn_name") or response.get("asn_org")
            if asn_name:
                asn_data.setdefault("name", asn_name)
            if asn_data:
                builder.add_asn(asn_data)

            # 3. Merge nested and top-level geo fields.
            geo_data = dict(response.get("geo") or {})
            if response.get("country"):
                geo_data.setdefault("country", response["country"])
            if response.get("country_code"):
                geo_data.setdefault("country_code", response["country_code"])
            if response.get("city"):
                geo_data.setdefault("city", response["city"])
            if geo_data:
                builder.add_geolocation(geo_data)

        # 4. Create Indicator with based-on relationship (high-risk only), or retire existing
        if self.create_indicator:
            if fraud_score >= self.suspicious_threshold:
                description = self._format_description(ip_value, response, fraud_score)
                builder.create_indicator(
                    ip_value=ip_value,
                    entity_type=entity_type,
                    fraud_score=fraud_score,
                    labels=labels,
                    description=description,
                    evaluated_flags=evaluated_flags,
                )
            else:
                builder.revoke_indicator(ip_value=ip_value, entity_type=entity_type)

        # Serialize and dispatch only after all objects have been built.
        result = builder.send_bundle()
        self.helper.connector_logger.info(
            f"[Lamis Network] Completed enrichment for {ip_value}: {result}"
        )
        return result

    def start(self) -> None:
        """Start listening for enrichment events."""
        self.helper.listen(message_callback=self._process_message)

    def run(self) -> None:
        """Start listening for enrichment events (alias for start)."""
        self.start()
