"""Convert Threat Library API objects into STIX 2.1 SDOs.

Threat Library objects have upstream ``standard_id`` values.
STIX objects are built with ``stix2`` directly so those IDs are preserved. The
connectors-sdk SDO models regenerate IDs from names.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import stix2
from connector.utils import ENTITY_TYPE_TO_STIX, PATH_TO_STIX_TYPE, with_sync_labels
from connectors_sdk.models import TLPMarking
from pycti import OpenCTIConnectorHelper

_STIX_IDENTITY_CLASSES = frozenset(
    {
        "individual",
        "group",
        "system",
        "organization",
        "class",
        "unspecified",
    }
)

# OpenCTI stores an unset first/last seen as these range sentinels.
_UNSET_DATE_PREFIXES = (
    "1970-01-01T00:00:00",
    "5138-11-16T09:46:40",
)


def present_date(value: Any) -> Any:
    """Return a real timestamp, or None when the API left the date unset."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.startswith(_UNSET_DATE_PREFIXES):
        return None
    return value


def copy_aliases(item: Dict[str, Any], kwargs: Dict[str, Any]) -> None:
    if item.get("aliases"):
        kwargs["aliases"] = list(item["aliases"])


def copy_seen_dates(item: Dict[str, Any], kwargs: Dict[str, Any]) -> None:
    for field in ("first_seen", "last_seen"):
        seen = present_date(item.get(field))
        if seen is not None:
            kwargs[field] = seen


class ConverterToStix:
    """Build STIX 2.1 objects from Threat Library API payloads."""

    def __init__(self, helper: OpenCTIConnectorHelper, *, tlp_level: str = "clear"):
        self.helper = helper
        self.tlp_marking = TLPMarking(level=tlp_level).to_stix2_object()

    def item_to_sdo(
        self,
        item: Dict[str, Any],
        obj_type_path: str,
        sync_labels: List[str],
    ) -> Optional[Any]:
        entity_type = item.get("entity_type")
        stix_type = ENTITY_TYPE_TO_STIX.get(entity_type) or PATH_TO_STIX_TYPE.get(
            obj_type_path
        )
        builders = {
            "intrusion-set": self.build_intrusion_set,
            "malware": self.build_malware,
            "tool": self.build_tool,
            "campaign": self.build_campaign,
        }
        if not stix_type or stix_type not in builders:
            self.helper.connector_logger.warning(
                "Skipping object with unsupported entity_type",
                {
                    "entity_type": entity_type,
                    "path": obj_type_path,
                },
            )
            return None
        if not item.get("standard_id") or not item.get("name"):
            self.helper.connector_logger.warning(
                "Skipping object missing standard_id or name",
                {"standard_id": item.get("standard_id")},
            )
            return None
        try:
            merged = with_sync_labels(dict(item), sync_labels)
            return builders[stix_type](merged)
        except Exception as exc:
            self.helper.connector_logger.error(
                "Failed to convert object to STIX",
                {
                    "stix_type": stix_type,
                    "standard_id": item.get("standard_id"),
                    "error": str(exc),
                },
            )
            return None

    @staticmethod
    def build_external_references(refs: List[Dict[str, Any]]) -> List[Any]:
        out: List[Any] = []
        for ref in refs or []:
            source_name = ref.get("source_name")
            if not source_name:
                continue
            kwargs: Dict[str, Any] = {"source_name": source_name}
            if ref.get("url"):
                kwargs["url"] = ref["url"]
            if ref.get("external_id"):
                kwargs["external_id"] = ref["external_id"]
            if ref.get("description"):
                kwargs["description"] = ref["description"]
            out.append(stix2.v21.ExternalReference(**kwargs))
        return out

    def _base_sdo_kwargs(self, item: Dict[str, Any]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "id": item["standard_id"],
            "name": item.get("name") or item["standard_id"],
        }
        for field in ("created", "modified", "description", "revoked"):
            if item.get(field) not in (None, ""):
                kwargs[field] = item[field]
        if item.get("confidence") is not None:
            try:
                kwargs["confidence"] = int(item["confidence"])
            except (TypeError, ValueError):
                pass
        if item.get("objectLabel"):
            kwargs["labels"] = list(item["objectLabel"])

        ext = self.build_external_references(item.get("externalReferences") or [])
        if ext:
            kwargs["external_references"] = ext

        created_by = item.get("createdBy") or {}
        identity = self.build_identity(created_by)
        if identity is not None:
            kwargs["created_by_ref"] = identity.id

        kwargs["object_marking_refs"] = [self.tlp_marking.id]
        return kwargs

    def build_identity(self, created_by: Dict[str, Any]) -> Optional[Any]:
        sid = created_by.get("standard_id")
        if not sid:
            return None
        name = created_by.get("name") or sid
        identity_class = (
            str(created_by.get("identity_class") or "organization").strip().lower()
        )
        if identity_class not in _STIX_IDENTITY_CLASSES:
            self.helper.connector_logger.warning(
                "Skipping invalid createdBy identity",
                {
                    "standard_id": sid,
                    "identity_class": identity_class,
                    "error": f"unsupported identity_class '{identity_class}'",
                },
            )
            return None
        try:
            return stix2.v21.Identity(
                id=sid,
                name=name,
                identity_class=identity_class,
                object_marking_refs=[self.tlp_marking.id],
            )
        except Exception as exc:
            self.helper.connector_logger.warning(
                "Skipping invalid createdBy identity",
                {
                    "standard_id": sid,
                    "identity_class": identity_class,
                    "error": str(exc),
                },
            )
            return None

    def build_intrusion_set(self, item: Dict[str, Any]) -> Any:
        kwargs = self._base_sdo_kwargs(item)
        copy_seen_dates(item, kwargs)
        for field in ("primary_motivation", "resource_level"):
            if item.get(field) not in (None, ""):
                kwargs[field] = item[field]
        copy_aliases(item, kwargs)
        if item.get("goals"):
            kwargs["goals"] = list(item["goals"])
        if item.get("secondary_motivations"):
            kwargs["secondary_motivations"] = list(item["secondary_motivations"])
        stix_id = kwargs.pop("id")
        return stix2.v21.IntrusionSet(id=stix_id, **kwargs)

    def build_malware(self, item: Dict[str, Any]) -> Any:
        kwargs = self._base_sdo_kwargs(item)
        copy_seen_dates(item, kwargs)
        for field in (
            "malware_types",
            "capabilities",
            "architecture_execution_envs",
            "implementation_languages",
        ):
            if item.get(field):
                kwargs[field] = list(item[field])
        copy_aliases(item, kwargs)
        if item.get("is_family") is not None:
            kwargs["is_family"] = bool(item["is_family"])
        stix_id = kwargs.pop("id")
        return stix2.v21.Malware(id=stix_id, **kwargs)

    def build_tool(self, item: Dict[str, Any]) -> Any:
        kwargs = self._base_sdo_kwargs(item)
        if item.get("tool_types"):
            kwargs["tool_types"] = list(item["tool_types"])
        if item.get("tool_version"):
            kwargs["tool_version"] = item["tool_version"]
        copy_aliases(item, kwargs)
        stix_id = kwargs.pop("id")
        return stix2.v21.Tool(id=stix_id, **kwargs)

    def build_campaign(self, item: Dict[str, Any]) -> Any:
        kwargs = self._base_sdo_kwargs(item)
        copy_seen_dates(item, kwargs)
        if item.get("objective") not in (None, ""):
            kwargs["objective"] = item["objective"]
        copy_aliases(item, kwargs)
        stix_id = kwargs.pop("id")
        return stix2.v21.Campaign(id=stix_id, **kwargs)
