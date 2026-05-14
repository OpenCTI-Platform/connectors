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

from lib.internal_export import InternalExportConnector
from unogenerator import ODS_Standard
from unogenerator.commons import ColorsNamed

# Entity types that are not supported by the ODS export.
_UNSUPPORTED_ENTITY_TYPES = {
    "stix-sighting-relationship",
    "stix-core-relationship",
    "Opinion",
}

# Hash column convention: header is rendered with dot notation (``hashes.MD5``)
# while the row generator looks for a known prefix to pick the proper hash.
# Both lists must stay in sync — the prefix is stored explicitly to avoid the
# old "hashes." vs "hashes_" inconsistency that produced missing columns.
_HASH_HEADER_PREFIX = "hashes."
_HASH_ALGORITHMS: Tuple[str, ...] = ("MD5", "SHA-1", "SHA-256", "SHA-512", "SSDEEP")
_HASH_HEADERS: Tuple[str, ...] = tuple(
    f"{_HASH_HEADER_PREFIX}{algo}" for algo in _HASH_ALGORITHMS
)

# Control characters that should never appear at the start of a spreadsheet
# cell. They are stripped to mitigate CSV / spreadsheet injection that abuses
# tab / carriage-return separators.
_SANITIZE_LEADING_CONTROL_CHARS = ("\t", "\r", "\n")

# Characters that, when used as the first character of a cell, are interpreted
# as a formula by LibreOffice and most other spreadsheet apps. Prefixing them
# with ``[<char>]`` neutralises the formula without losing the original value.
_SANITIZE_FORMULA_TRIGGERS = ("=", "+", "-", "@")


def sanitize_cell(value: Any) -> str:
    """Return ``value`` rendered as a spreadsheet-safe string.

    The function defensively handles ``None`` and non-string inputs (numbers,
    booleans, ...) and prevents two classes of issue:

    * formula injection — leading ``=``/``+``/``-``/``@`` are wrapped in
      square brackets so spreadsheet apps stop interpreting the cell as a
      formula;
    * control-character injection — leading tab, carriage-return or newline
      characters are stripped (the previous implementation tried to match the
      literal strings ``"0x09"``/``"0x0D"`` which never occurred in practice).
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    while text and text[0] in _SANITIZE_LEADING_CONTROL_CHARS:
        text = text[1:]
    if text and text[0] in _SANITIZE_FORMULA_TRIGGERS:
        text = "[" + text[0] + "]" + text[1:]
    return text


class ExportFileODSConnector(InternalExportConnector):
    """Internal-export connector rendering OpenCTI entities to an ODS file."""

    def __init__(self) -> None:
        super().__init__()
        self.export_type: str = "simple"
        self.main_filter: Optional[Dict[str, Any]] = None
        self.access_filter: Optional[Dict[str, Any]] = None
        self.content_markings: List[str] = []
        self.file_name: str = ""

    @staticmethod
    def _check_markings(entity: Dict[str, Any], forbidden: List[str]) -> bool:
        """Return ``True`` when ``entity`` has no forbidden object marking."""
        for marking in entity.get("objectMarking") or []:
            if marking.get("id") in forbidden:
                return False
        return True

    @staticmethod
    def _get_content_markings(data: Dict[str, Any]) -> List[str]:
        """Extract the list of forbidden object-marking ids from the request."""
        main_filter = data.get("main_filter") or {}
        for f in main_filter.get("filters") or []:
            if f.get("key") == "objectMarking":
                return list(f.get("values") or [])
        return []

    def _get_export_list(
        self, entities_list: List[Dict[str, Any]]
    ) -> List[Tuple[Dict[str, Any], int]]:
        """Return ``[(entity, level), ...]`` with neighbours when ``full``.

        Level 1 entities are the selected entries. Level 2 entities are first
        neighbours reached through STIX core relationships. The result is
        de-duplicated by entity id (level 1 always wins) so the same
        neighbour reached from several selected entities or from both
        directions does not produce duplicate rows in the spreadsheet.
        """
        export_list: List[Tuple[Dict[str, Any], int]] = []
        seen_ids: set[str] = set()
        for entity in entities_list:
            if not self._check_markings(entity, self.content_markings):
                continue
            entity_id = entity.get("id")
            if entity_id and entity_id in seen_ids:
                continue
            if entity_id:
                seen_ids.add(entity_id)
            export_list.append((entity, 1))
            self.helper.log_debug(f"Export Type: {self.export_type}")

            if self.export_type != "full":
                continue

            self.helper.log_debug(f"Entity ID: {entity_id}")
            for direction, ref_key in (("fromId", "to"), ("toId", "from")):
                rels = self.helper.api_impersonate.stix_core_relationship.list(
                    **{direction: entity_id},
                    filters=self.main_filter,
                    getAll=True,
                )
                self.helper.log_debug(f"Relationships {direction}: {rels!r}")
                for relationship in rels:
                    neighbor_id = relationship[ref_key]["id"]
                    if neighbor_id in seen_ids:
                        continue
                    neighbor = self._read_neighbor(neighbor_id)
                    if neighbor is None:
                        continue
                    if not self._check_markings(neighbor, self.content_markings):
                        continue
                    seen_ids.add(neighbor_id)
                    export_list.append((neighbor, 2))
        return export_list

    def _read_neighbor(self, neighbor_id: str) -> Optional[Dict[str, Any]]:
        """Return the SDO or SCO matching ``neighbor_id`` if any."""
        neighbor = self.helper.api_impersonate.stix_domain_object.read(id=neighbor_id)
        if neighbor is not None:
            return neighbor
        return self.helper.api_impersonate.stix_cyber_observable.read(id=neighbor_id)

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
        ``hashes.<ALGO>`` columns (``_HASH_HEADERS``). Keeping the raw
        ``hashes`` header would render as an empty cell because ``_row_for``
        only understands the ``hashes.<ALGO>`` form for hash lookups.
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

        # Render to a temporary file we own, then read it back. Using
        # ``tempfile`` keeps the cleanup deterministic even if reading the
        # file raises.
        tmp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")
        os.makedirs(tmp_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(suffix=".ods", dir=tmp_dir)
        os.close(fd)

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
        """Fetch every entity matching the ``selection`` request.

        Uses the unified ``opencti_stix_object_or_stix_relationship.list``
        endpoint (with ``getAll=True``) like every other internal-export
        connector (``export-file-stix``, ``export-file-csv``,
        ``export-file-yara``, ``export-report-pdf``). It covers all STIX
        object / relationship types in a single call, so we no longer need
        to keep the four hand-written lookups in sync with the platform.
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

        ``access_filter`` may be missing or ``None`` for backwards
        compatibility, in which case the user filter is returned as-is.
        """
        access_filter_content = (access_filter or {}).get("filters") or []
        if access_filter_content and list_params_filters is not None:
            return {
                "mode": "and",
                "filterGroups": [list_params_filters, access_filter],
                "filters": [],
            }
        if not access_filter_content:
            return list_params_filters
        return access_filter

    def _sanitize_file_name(self, raw_file_name: str) -> str:
        """Return a safe ``<name>.ods`` filename from the request payload.

        ``str.rstrip`` trims any trailing characters from the ``".unknown"``
        set, which can mangle the filename (e.g. ``"file.unk"`` would become
        ``"file."``). We instead remove the exact suffix and strip any
        directory components to defend against path-traversal attempts.
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
        self.helper.log_debug(f"Data: {data}")
        self.file_name = self._sanitize_file_name(data.get("file_name", ""))
        file_markings = data.get("file_markings") or []
        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]
        export_scope = data["export_scope"]
        self.export_type = data.get("export_type", "simple")
        self.main_filter = data.get("main_filter")
        self.access_filter = data.get("access_filter")
        self.content_markings = self._get_content_markings(data)
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
