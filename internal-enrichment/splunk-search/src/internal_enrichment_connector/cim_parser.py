from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CIM_TO_STIX_MAP = {
    "src_ip": ("IPv4-Addr", "value"),
    "src_ipv6": ("IPv6-Addr", "value"),
    "dest_ip": ("IPv4-Addr", "value"),
    "dest_ipv6": ("IPv6-Addr", "value"),
    "src_dns": ("Domain-Name", "value"),
    "dest_dns": ("Domain-Name", "value"),
    "src_host": ("Domain-Name", "value"),
    "dest_host": ("Domain-Name", "value"),
    "url": ("Url", "value"),
    "http_user_agent": ("User-Agent", "value"),
    "user": ("User-Account", "account_login"),
    "src_user": ("User-Account", "account_login"),
    "dest_user": ("User-Account", "account_login"),
    "app": ("Software", "name"),
    "process_name": ("Process", "name"),
    "process_id": ("Process", "pid"),
    "file_name": ("StixFile", "name"),
    "file_hash": ("StixFile", "hashes"),
    "file_path": ("Directory", "path"),
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


@dataclass(frozen=True)
class ParsedObservable:
    """A single observable parsed from a Splunk result row."""

    stix_type: str
    stix_property: str
    value: Any
    source_field: str


class CIMParser:
    """Parses Splunk CIM rows into STIX observables."""

    def __init__(self, field_map: dict | None = None):
        self._field_map = field_map or CIM_TO_STIX_MAP

    def parse_row(self, row: dict[str, str]) -> list[ParsedObservable]:
        """Parse one result row and return parsed observables."""
        observables: list[ParsedObservable] = []
        for field, value in row.items():
            if field not in self._field_map:
                continue

            mapped = self._field_map[field]
            if mapped is None:
                continue

            if value is None:
                continue

            if isinstance(value, str) and value.strip() == "":
                continue

            stix_type, stix_property = mapped
            observables.append(
                ParsedObservable(
                    stix_type=stix_type,
                    stix_property=stix_property,
                    value=value,
                    source_field=field,
                )
            )
        return observables

    def parse_results(self, results: list[dict[str, str]]) -> list[ParsedObservable]:
        """Parse multiple rows and deduplicate by (stix_type, value)."""
        dedup: dict[tuple[str, str], ParsedObservable] = {}
        for row in results:
            for observable in self.parse_row(row):
                key = (observable.stix_type, str(observable.value))
                if key not in dedup:
                    dedup[key] = observable
        return list(dedup.values())
