"""OpenCTI ``export-file-ods`` connector worker.

Receives an export request from OpenCTI, fetches the requested entities
through the platform API and renders them as an ODS spreadsheet using
``unogenerator`` (which talks to a headless LibreOffice instance).
"""

import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from unogenerator import ODS_Standard
from unogenerator.commons import ColorsNamed

from lib.internal_export import InternalExportConnector
from lib.sanitization import sanitize_cell

_UNSUPPORTED_ENTITY_TYPES = {
    "stix-sighting-relationship",
    "stix-core-relationship",
    "Opinion",
}

# Headers use dot notation (``hashes.MD5``); the row generator strips the
# ``hashes.`` prefix to look up the matching algorithm in ``entity["hashes"]``.
_HASH_HEADER_PREFIX = "hashes."
_HASH_ALGORITHMS: Tuple[str, ...] = ("MD5", "SHA-1", "SHA-256", "SHA-512", "SSDEEP")
_HASH_HEADERS: Tuple[str, ...] = tuple(
    f"{_HASH_HEADER_PREFIX}{algo}" for algo in _HASH_ALGORITHMS
)


class ExportFileODSConnector(InternalExportConnector):
    """Internal-export connector rendering OpenCTI entities to an ODS file."""

    def __init__(self) -> None:
        super().__init__()
        self.export_type: str = "simple"
        self.main_filter: Optional[Dict[str, Any]] = None
        self.access_filter: Optional[Dict[str, Any]] = None
        self.file_name: str = ""

    def _get_export_list(
        self, entities_list: List[Dict[str, Any]]
    ) -> List[Tuple[Dict[str, Any], int]]:
        """Return ``[(entity, level), ...]`` with neighbours when ``full``.

        Level 1 entities are the selected entries already filtered by the
        platform through ``api_impersonate`` and the request's
        ``access_filter``. Level 2 entities are first neighbours reached
        through STIX core relationships. Neighbour candidates are fetched
        in a single batch via the unified
        ``opencti_stix_object_or_stix_relationship.list`` endpoint with the
        request's ``access_filter`` applied, so an exported neighbour can
        never bypass the marking / access restrictions configured for the
        export.

        The result is de-duplicated by entity id (level 1 always wins) so
        the same neighbour reached from several selected entities or from
        both directions does not produce duplicate rows in the spreadsheet.
        """
        export_list: List[Tuple[Dict[str, Any], int]] = []
        seen_ids: set[str] = set()
        self.helper.log_debug(f"Export Type: {self.export_type}")

        for entity in entities_list:
            entity_id = entity.get("id")
            if entity_id and entity_id in seen_ids:
                continue
            if entity_id:
                seen_ids.add(entity_id)
            self.helper.log_debug(f"Selected entity (level 1): {entity_id}")
            export_list.append((entity, 1))

        if self.export_type != "full":
            return export_list

        candidate_neighbor_ids: set[str] = set()
        for entity_id in [eid for eid in seen_ids if eid]:
            for direction, ref_key in (("fromId", "to"), ("toId", "from")):
                # ``main_filter`` is intentionally **not** forwarded here.
                # For a ``selection`` export it is the selected object ids
                # filter, which would filter the *relationship* rows by
                # those ids (which they do not carry) and effectively
                # turn a ``full`` export into a ``simple`` one. For a
                # ``query`` export it is the user-defined entity filter
                # which generally does not apply to relationship rows.
                # We only need the endpoint direction
                # (``fromId`` / ``toId``) to discover the neighbour ids;
                # the marking / access restrictions are enforced when
                # we fetch the actual neighbour objects below, by
                # AND-ing ``access_filter`` into the unified entity
                # endpoint lookup.
                rels = self.helper.api_impersonate.stix_core_relationship.list(
                    **{direction: entity_id},
                    getAll=True,
                )
                self.helper.log_debug(
                    f"Relationships {direction}={entity_id}: {len(rels)} found"
                )
                for relationship in rels:
                    neighbor_id = relationship[ref_key]["id"]
                    if neighbor_id in seen_ids:
                        continue
                    candidate_neighbor_ids.add(neighbor_id)

        if not candidate_neighbor_ids:
            return export_list

        neighbor_filter = self._build_neighbor_filter(
            sorted(candidate_neighbor_ids), self.access_filter
        )
        neighbors = (
            self.helper.api_impersonate.opencti_stix_object_or_stix_relationship.list(
                filters=neighbor_filter, getAll=True
            )
        )
        for neighbor in neighbors:
            neighbor_id = neighbor.get("id")
            if not neighbor_id or neighbor_id in seen_ids:
                continue
            seen_ids.add(neighbor_id)
            self.helper.log_debug(f"Related entity (level 2): {neighbor_id}")
            export_list.append((neighbor, 2))
        return export_list

    @staticmethod
    def _build_neighbor_filter(
        neighbor_ids: List[str],
        access_filter: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build a filter selecting ``neighbor_ids`` and applying ``access_filter``.

        The neighbour ids are passed as a positive ``ids`` filter; the
        request's ``access_filter`` (when present and non-empty) is ANDed
        with it so the unified entity endpoint enforces the same marking
        restrictions the platform applied to the selected entities.
        """
        ids_filter_group: Dict[str, Any] = {
            "mode": "and",
            "filterGroups": [],
            "filters": [
                {
                    "key": "ids",
                    "values": neighbor_ids,
                    "operator": "eq",
                    "mode": "or",
                }
            ],
        }
        access_filter_content = (access_filter or {}).get("filters") or []
        access_filter_groups = (access_filter or {}).get("filterGroups") or []
        if access_filter and (access_filter_content or access_filter_groups):
            return {
                "mode": "and",
                "filterGroups": [ids_filter_group, access_filter],
                "filters": [],
            }
        return ids_filter_group

    @staticmethod
    def _row_for(entity: Dict[str, Any], header: str) -> str:
        """Render the cell content for ``header`` on ``entity``."""
        if header.startswith(_HASH_HEADER_PREFIX):
            algo = header[len(_HASH_HEADER_PREFIX) :]
            for hashed in entity.get("hashes") or []:
                if hashed.get("algorithm") == algo:
                    return sanitize_cell(hashed.get("hash"))
            return ""

        value = entity.get(header)
        if value is None:
            return ""
        if isinstance(value, str):
            return sanitize_cell(value)
        if isinstance(value, (int, float, bool)):
            return sanitize_cell(str(value))
        if isinstance(value, list):
            if not value:
                return ""
            if isinstance(value[0], str):
                return sanitize_cell(",".join(value))
            if isinstance(value[0], dict):
                parts: List[str] = []
                for item in value:
                    for key in ("name", "definition", "value", "observable_value"):
                        if key in item:
                            parts.append(sanitize_cell(item[key]))
                            break
                return sanitize_cell(",".join(parts))
            return ""
        if isinstance(value, dict):
            for key in ("name", "value", "observable_value"):
                if key in value:
                    return sanitize_cell(value[key])
            return ""
        return ""

    def _build_headers(self, entities_list: List[Dict[str, Any]]) -> List[str]:
        """Return the alphabetically-sorted header list for the spreadsheet.

        The raw ``hashes`` column is replaced by the per-algorithm
        ``hashes.<ALGO>`` columns (``_HASH_HEADERS``) since ``_row_for``
        only knows how to render values from the ``hashes.<ALGO>`` form.
        """
        headers: List[str] = sorted(set().union(*(e.keys() for e in entities_list)))
        if "hashes" in headers:
            headers.remove("hashes")
            headers = headers + [h for h in _HASH_HEADERS if h not in headers]
        return headers

    def _get_content(self, export_list: List[Tuple[Dict[str, Any], int]]) -> bytes:
        """Render ``export_list`` as an ODS document and return its bytes."""
        entities_list = [entry[0] for entry in export_list]
        headers = self._build_headers(entities_list)

        tmp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")
        os.makedirs(tmp_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(suffix=".ods", dir=tmp_dir)
        os.close(fd)
        self.helper.log_debug(f"Rendering ODS spreadsheet at: {tmp_path}")

        try:
            with ODS_Standard() as sheet:
                sheet.addRowWithStyle("A1", headers, colors=ColorsNamed.Blue)
                for row_index, (entity, level) in enumerate(export_list, start=2):
                    row = [self._row_for(entity, header) for header in headers]
                    color = (
                        ColorsNamed.GrayDark if level == 1 else ColorsNamed.GrayLight
                    )
                    sheet.addRowWithStyle(f"A{row_index}", row, colors=color)
                sheet.save(tmp_path)
            with open(tmp_path, "rb") as ods:
                return ods.read()
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                self.helper.log_warning(f"Could not remove temporary file: {tmp_path}")

    def _list_selection_entities(
        self, main_filter: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Fetch every entity matching a ``selection`` export request.

        Uses the unified ``opencti_stix_object_or_stix_relationship.list``
        endpoint with ``getAll=True`` so the spreadsheet is not truncated
        to a single page and covers every STIX object / relationship type
        in a single call.
        """
        return (
            self.helper.api_impersonate.opencti_stix_object_or_stix_relationship.list(
                filters=main_filter, getAll=True
            )
        )

    @staticmethod
    def _build_query_filter(
        list_params_filters: Optional[Dict[str, Any]],
        access_filter: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Combine the user filter and the access (marking) filter.

        Either side may be missing or empty: when ``access_filter`` has no
        ``filters`` and no ``filterGroups`` it is treated as absent and the
        user filter is returned as-is (and vice versa).
        """
        access_has_content = bool(
            (access_filter or {}).get("filters")
            or (access_filter or {}).get("filterGroups")
        )
        if access_has_content and list_params_filters is not None:
            return {
                "mode": "and",
                "filterGroups": [list_params_filters, access_filter],
                "filters": [],
            }
        if not access_has_content:
            return list_params_filters
        return access_filter

    def _sanitize_file_name(self, raw_file_name: str) -> str:
        """Return a safe ``<name>.ods`` filename from the request payload.

        Strips directory components (``os.path.basename``) to defend against
        path traversal and removes the literal ``.unknown`` suffix (not via
        ``str.rstrip`` which would mangle filenames such as ``file.unk``).
        """
        base = os.path.basename(raw_file_name or "")
        if base.endswith(".unknown"):
            base = base[: -len(".unknown")]
        if not base:
            base = "export"
        return f"{base}.ods"

    def _push_export(
        self,
        entity_type: str,
        entity_id: Optional[str],
        file_markings: List[str],
        list_filters: str,
        content: bytes,
    ) -> None:
        """Push the rendered ODS content back to OpenCTI."""
        self.helper.log_info(f"Uploading file as '{self.file_name}'...")
        kwargs = (
            entity_id,
            entity_type,
            self.file_name,
            file_markings,
            content,
            list_filters,
        )
        if entity_type == "Stix-Cyber-Observable":
            self.helper.api.stix_cyber_observable.push_list_export(*kwargs)
        elif entity_type == "Stix-Core-Object":
            self.helper.api.stix_core_object.push_list_export(*kwargs)
        else:
            self.helper.api.stix_domain_object.push_list_export(*kwargs)

    def _process_message(self, data: Dict[str, Any]) -> str:
        """Process an export request."""
        self.helper.log_debug(f"Export request payload: {data}")
        self.file_name = self._sanitize_file_name(data.get("file_name", ""))
        file_markings = data.get("file_markings") or []
        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]
        export_scope = data["export_scope"]
        self.export_type = data.get("export_type", "simple")
        self.main_filter = data.get("main_filter")
        self.access_filter = data.get("access_filter")
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the export..."
        )

        if export_scope == "single":
            raise ValueError("This connector only supports list exports")

        if entity_type in _UNSUPPORTED_ENTITY_TYPES:
            raise ValueError("ODS export is not available for this entity type.")

        if export_scope == "selection":
            list_filters = "selected_ids"
            entities_list = self._list_selection_entities(self.main_filter)
        else:  # export_scope == "query"
            list_params = data["list_params"]
            list_params_filters = list_params.get("filters")
            export_query_filter = self._build_query_filter(
                list_params_filters, self.access_filter
            )
            entities_list = self.helper.api_impersonate.stix2.export_entities_list(
                entity_type=entity_type,
                search=list_params.get("search"),
                filters=export_query_filter,
                orderBy=list_params.get("orderBy"),
                orderMode=list_params.get("orderMode"),
                getAll=True,
            )
            self.helper.log_info(f"Uploading: {entity_type} to {self.file_name}")
            list_filters = json.dumps(list_params)

        if not entities_list:
            raise ValueError("An error occurred, the list is empty")

        export_list = self._get_export_list(entities_list)

        if entity_type == "Malware-Analysis":
            for entity in entities_list:
                if "result_name" in entity:
                    entity["name"] = entity["result_name"]

        self._push_export(
            entity_type=entity_type,
            entity_id=entity_id,
            file_markings=file_markings,
            list_filters=list_filters,
            content=self._get_content(export_list),
        )
        self.helper.log_info(f"Export done: {entity_type} to {self.file_name}")
        return "Export done"


if __name__ == "__main__":
    try:
        connector = ExportFileODSConnector()
        connector.start()
    except Exception as exc:  # noqa: BLE001 - we want to log any startup error
        print(exc)
        time.sleep(10)
        sys.exit(1)
