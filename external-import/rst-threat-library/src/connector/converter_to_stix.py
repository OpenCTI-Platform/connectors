"""Convert Threat Library API objects into STIX 2.1 SDOs.

Threat Library objects have upstream ``standard_id`` values.
STIX objects are built with ``stix2`` directly so those IDs are preserved. The
connectors-sdk SDO models regenerate IDs from names.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import stix2
from pycti import OpenCTIConnectorHelper

from connector.utils import ENTITY_TYPE_TO_STIX, PATH_TO_STIX_TYPE


class ConverterToStix:
    """Build STIX 2.1 objects from Threat Library API payloads."""

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper

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
            from connector.utils import with_sync_labels

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
        if created_by.get("standard_id"):
            kwargs["created_by_ref"] = created_by["standard_id"]

        marking_refs = [
            marking["standard_id"]
            for marking in (item.get("objectMarking") or [])
            if marking.get("standard_id")
        ]
        if marking_refs:
            kwargs["object_marking_refs"] = marking_refs

        return kwargs

    def build_identity(self, created_by: Dict[str, Any]) -> Optional[Any]:
        sid = created_by.get("standard_id")
        if not sid:
            return None
        name = created_by.get("name") or sid
        identity_class = str(created_by.get("identity_class") or "organization")
        return stix2.v21.Identity(id=sid, name=name, identity_class=identity_class)

    def build_intrusion_set(self, item: Dict[str, Any]) -> Any:
        kwargs = self._base_sdo_kwargs(item)
        for field in (
            "first_seen",
            "last_seen",
            "primary_motivation",
            "resource_level",
        ):
            if item.get(field) not in (None, ""):
                kwargs[field] = item[field]
        if item.get("aliases"):
            kwargs["aliases"] = list(item["aliases"])
        if item.get("goals"):
            kwargs["goals"] = list(item["goals"])
        if item.get("secondary_motivations"):
            kwargs["secondary_motivations"] = list(item["secondary_motivations"])
        return stix2.v21.IntrusionSet(**kwargs)

    def build_malware(self, item: Dict[str, Any]) -> Any:
        kwargs = self._base_sdo_kwargs(item)
        for field in (
            "malware_types",
            "capabilities",
            "architecture_execution_envs",
            "implementation_languages",
        ):
            if item.get(field):
                kwargs[field] = list(item[field])
        if item.get("aliases"):
            kwargs["aliases"] = list(item["aliases"])
        if item.get("is_family") is not None:
            kwargs["is_family"] = bool(item["is_family"])
        return stix2.v21.Malware(**kwargs)

    def build_tool(self, item: Dict[str, Any]) -> Any:
        kwargs = self._base_sdo_kwargs(item)
        if item.get("tool_types"):
            kwargs["tool_types"] = list(item["tool_types"])
        if item.get("tool_version"):
            kwargs["tool_version"] = item["tool_version"]
        return stix2.v21.Tool(**kwargs)

    def build_campaign(self, item: Dict[str, Any]) -> Any:
        kwargs = self._base_sdo_kwargs(item)
        for field in ("first_seen", "last_seen", "objective"):
            if item.get(field) not in (None, ""):
                kwargs[field] = item[field]
        return stix2.v21.Campaign(**kwargs)
