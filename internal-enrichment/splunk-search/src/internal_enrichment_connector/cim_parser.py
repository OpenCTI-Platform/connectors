from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

from .services.sourcetype_resolver import SourcetypeResolver

CIM_TO_STIX_MAP = {
    "src_ip": ("IPv4-Addr", "value"),
    "src_ipv6": ("IPv6-Addr", "value"),
    "dest_ip": ("IPv4-Addr", "value"),
    "dest_ipv6": ("IPv6-Addr", "value"),
    "src_dns": ("Domain-Name", "value"),
    "dest_dns": ("Domain-Name", "value"),
    "src_host": ("Hostname", "value"),
    "dest_host": ("Hostname", "value"),
    "src": ("Polymorphic", "value"),
    "dest": ("Polymorphic", "value"),
    "host": ("Polymorphic", "value"),
    "url": ("Url", "value"),
    "uri_path": ("Url", "value"),
    "uri_query": ("Url", "value"),
    "http_user_agent": ("User-Agent", "value"),
    "user": ("User-Account", "account_login"),
    "src_user": ("User-Account", "account_login"),
    "dest_user": ("User-Account", "account_login"),
    "email_src": ("Email-Addr", "value"),
    "email_dst": ("Email-Addr", "value"),
    "src_email": ("Email-Addr", "value"),
    "dest_email": ("Email-Addr", "value"),
    "app": ("Software", "name"),
    "process_name": ("Process", "name"),
    "process_path": ("Process", "command_line"),
    "process": ("Process", "command_line"),
    "process_id": ("Process", "pid"),
    "file_name": ("StixFile", "object"),
    "file_path": ("StixFile", "object"),
    "file_hash": ("StixFile", "object"),
    "md5": ("StixFile", "object"),
    "sha1": ("StixFile", "object"),
    "sha256": ("StixFile", "object"),
    "sha512": ("StixFile", "object"),
    "src_mac": ("Mac-Addr", "value"),
    "dest_mac": ("Mac-Addr", "value"),
    "email": ("Email-Addr", "value"),
    "src_port": None,
    "dest_port": None,
    "protocol": None,
    "action": None,
    "vendor_product": None,
    "sourcetype": None,
}

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")

_INVALID_VALUES = {"-", "unknown", "n/a", "null", "none"}

_HASH_FIELD_TO_ALGO = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
}

_NETWORK_DEVICE_TYPES = {
    "network",
    "network-device",
    "firewall",
    "ids",
    "proxy",
    "load-balancer",
    "waf",
    "cloud-service",
    "cloud-security",
    "dns-security",
    "email-security",
    "identity-provider",
    "siem",
    "ndr",
    "soar",
    "casb",
    "dlp",
    "vulnerability-scanner",
}

_ENDPOINT_TYPES = {"endpoint", "endpoint-security", "edr"}


@dataclass(frozen=True)
class ParsedObservable:
    """A single observable parsed from a Splunk result row."""

    stix_type: str
    stix_property: str
    value: Any
    source_field: str


class CIMParser:
    """Parses Splunk CIM rows into STIX observables."""

    def __init__(
        self,
        field_map: dict | None = None,
        skip_private_ips: bool = False,
        sourcetype_resolver: SourcetypeResolver | None = None,
    ):
        self._field_map = field_map or CIM_TO_STIX_MAP
        self._skip_private_ips = skip_private_ips
        self._sourcetype_resolver = sourcetype_resolver or SourcetypeResolver()

    @staticmethod
    def _normalize_value(raw: Any) -> str | None:
        if raw is None:
            return None
        value = str(raw).strip()
        if not value:
            return None
        if value.lower() in _INVALID_VALUES:
            return None
        return value

    @staticmethod
    def _resolve_polymorphic_type(value: str) -> str:
        """Determine observable type from value format."""
        if _IPV4_RE.match(value):
            try:
                ipaddress.IPv4Address(value)
                return "IPv4-Addr"
            except ValueError:
                pass

        if _IPV6_RE.match(value) and ":" in value:
            try:
                ipaddress.IPv6Address(value)
                return "IPv6-Addr"
            except ValueError:
                pass

        if "." in value and not value.replace(".", "").isdigit():
            return "Domain-Name"
        return "Hostname"

    def _is_private_ip(self, value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_private
        except ValueError:
            return False

    @staticmethod
    def _infer_file_hash_algo(value: str) -> str:
        length = len(value)
        if length == 32:
            return "MD5"
        if length == 40:
            return "SHA-1"
        if length == 64:
            return "SHA-256"
        if length == 128:
            return "SHA-512"
        return "SHA-256"

    def _collect_file_object(self, row: dict[str, Any]) -> dict[str, Any] | None:
        file_name = self._normalize_value(row.get("file_name"))
        file_path = self._normalize_value(row.get("file_path"))

        hashes: dict[str, str] = {}
        for field, algo in _HASH_FIELD_TO_ALGO.items():
            value = self._normalize_value(row.get(field))
            if value:
                hashes[algo] = value

        generic_hash = self._normalize_value(row.get("file_hash"))
        if generic_hash:
            hashes[self._infer_file_hash_algo(generic_hash)] = generic_hash

        if not file_name and not file_path and not hashes:
            return None

        file_obj: dict[str, Any] = {}
        if file_name:
            file_obj["name"] = file_name
        if file_path:
            file_obj["path"] = file_path
        if hashes:
            file_obj["hashes"] = hashes
        return file_obj

    def _is_mapped_sourcetype(self, sourcetype: str) -> bool:
        return bool(sourcetype) and self._sourcetype_resolver.is_mapped(sourcetype)

    def _is_network_device_sourcetype(self, sourcetype: str) -> bool:
        if not self._is_mapped_sourcetype(sourcetype):
            return False

        entry = self._sourcetype_resolver.resolve(sourcetype)
        if entry.get("entity_type") != "Infrastructure":
            return False

        infra_types = {
            str(infra_type).strip().lower()
            for infra_type in entry.get("infrastructure_types") or []
            if str(infra_type).strip()
        }
        return bool(infra_types.intersection(_NETWORK_DEVICE_TYPES))

    def _is_endpoint_sourcetype(self, sourcetype: str) -> bool:
        if not self._is_mapped_sourcetype(sourcetype):
            return False

        entry = self._sourcetype_resolver.resolve(sourcetype)
        if entry.get("entity_type") != "Infrastructure":
            return False

        infra_types = {
            str(infra_type).strip().lower()
            for infra_type in entry.get("infrastructure_types") or []
            if str(infra_type).strip()
        }
        return bool(infra_types.intersection(_ENDPOINT_TYPES))

    @staticmethod
    def _dedup_key(observable: ParsedObservable) -> tuple[str, str, str]:
        if isinstance(observable.value, dict):
            normalized_value = json.dumps(observable.value, sort_keys=True)
        else:
            normalized_value = str(observable.value)
        return (observable.stix_type, observable.stix_property, normalized_value)

    def parse_row(self, row: dict[str, Any]) -> list[ParsedObservable]:
        """Parse one result row and return parsed observables."""
        observables: list[ParsedObservable] = []
        seen_row: set[tuple[str, str, str]] = set()

        file_object = self._collect_file_object(row)
        if file_object is not None:
            file_obs = ParsedObservable(
                stix_type="StixFile",
                stix_property="object",
                value=file_object,
                source_field="file",
            )
            key = self._dedup_key(file_obs)
            if key not in seen_row:
                seen_row.add(key)
                observables.append(file_obs)

        sourcetype = self._normalize_value(row.get("sourcetype")) or ""
        for field, value in row.items():
            if field not in self._field_map:
                continue

            mapped = self._field_map[field]
            if mapped is None:
                continue

            if field in {
                "file_name",
                "file_path",
                "file_hash",
                "md5",
                "sha1",
                "sha256",
                "sha512",
            }:
                continue

            normalized_value = self._normalize_value(value)
            if normalized_value is None:
                continue

            stix_type, stix_property = mapped

            if field in {"src", "dest", "host"}:
                if field == "host":
                    if self._is_network_device_sourcetype(sourcetype):
                        continue
                    if self._is_endpoint_sourcetype(sourcetype):
                        stix_type = "Hostname"
                    else:
                        stix_type = self._resolve_polymorphic_type(normalized_value)
                else:
                    stix_type = self._resolve_polymorphic_type(normalized_value)

            if self._skip_private_ips and stix_type in {"IPv4-Addr", "IPv6-Addr"}:
                if self._is_private_ip(normalized_value):
                    continue

            observable = ParsedObservable(
                stix_type=stix_type,
                stix_property=stix_property,
                value=normalized_value,
                source_field=field,
            )
            key = self._dedup_key(observable)
            if key in seen_row:
                continue
            seen_row.add(key)
            observables.append(observable)
        return observables

    def parse_results(self, results: list[dict[str, Any]]) -> list[ParsedObservable]:
        """Parse multiple rows and deduplicate by (stix_type, value)."""
        dedup: dict[tuple[str, str, str], ParsedObservable] = {}
        for row in results:
            for observable in self.parse_row(row):
                key = self._dedup_key(observable)
                if key not in dedup:
                    dedup[key] = observable
        return list(dedup.values())
