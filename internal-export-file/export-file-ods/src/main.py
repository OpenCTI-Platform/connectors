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
from typing import Any, Dict, Iterable, List, Optional, Tuple

from lib.filenames import sanitize_file_name
from lib.filters import (
    access_filter_has_content,
    build_neighbor_filter,
    build_query_filter,
)
from lib.headers import HASH_HEADER_PREFIX, build_headers
from lib.internal_export import InternalExportConnector
from lib.rendering import render_dict_item, render_dict_list
from lib.sanitization import sanitize_cell
from unogenerator import ODS_Standard
from unogenerator.commons import ColorsNamed

_UNSUPPORTED_ENTITY_TYPES = {
    "stix-sighting-relationship",
    "stix-core-relationship",
    "Opinion",
}

# Headers use dot notation (``hashes.MD5``); the row generator strips the
# ``hashes.`` prefix to look up the matching algorithm in ``entity["hashes"]``.
# The canonical algorithm list keeps a stable header order for the
# common algorithms; ``lib.headers.build_headers`` adds any extra
# algorithms found on the actual ``entity["hashes"]`` payloads on top so
# non-canonical algorithms (anything STIX/OpenCTI may carry beyond
# MD5/SHA-1/SHA-256/SHA-512/SSDEEP) are not silently dropped.
_HASH_ALGORITHMS: Tuple[str, ...] = ("MD5", "SHA-1", "SHA-256", "SHA-512", "SSDEEP")


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
        through STIX core relationships. Relationship discovery uses a
        single ``stix_core_relationship.list`` call per selected entity
        (``fromOrToId``) instead of one per direction, halving the API
        load on the platform. Neighbour candidates are then fetched in a
        single batch via the unified
        ``opencti_stix_object_or_stix_relationship.list`` endpoint with
        the request's ``access_filter`` applied, so an exported
        neighbour can never bypass the marking / access restrictions
        configured for the export.

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

        candidate_neighbor_ids = self._collect_neighbor_candidate_ids(seen_ids)
        if not candidate_neighbor_ids:
            return export_list

        neighbor_filter = build_neighbor_filter(
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

    def _collect_neighbor_candidate_ids(self, seen_ids: Iterable[str]) -> set[str]:
        """Return the unique neighbour ids reachable from ``seen_ids``.

        Uses ``fromOrToId`` so a single paginated relationship list call
        returns the relationships in both directions for a given entity
        (rather than the previous ``fromId`` + ``toId`` pair, which
        doubled the API load on ``full`` exports). ``main_filter`` is
        intentionally **not** forwarded: for a ``selection`` export it is
        the selected-object-ids filter (which has no meaning on
        relationship rows and would silently turn every ``full`` export
        into a ``simple`` one); for a ``query`` export it is the
        user-defined entity filter (which generally does not apply to
        relationship rows either).

        ``access_filter`` **is** forwarded as a relationship-list filter
        when present so marking-restricted graph topology cannot leak
        through the discovery step. Without that filter a low-marked
        neighbour could still surface in the export — even though the
        later neighbour-object fetch removes it — simply because the
        very existence of a relationship to it would have been
        observable through this list call. Applying ``access_filter``
        at both stages keeps the relationship-discovery and the
        neighbour-object stages consistent.
        """
        candidate_neighbor_ids: set[str] = set()
        access_filter = self._access_filter_for_relationships()
        for entity_id in [eid for eid in seen_ids if eid]:
            list_kwargs: Dict[str, Any] = {
                "fromOrToId": entity_id,
                "getAll": True,
            }
            if access_filter is not None:
                list_kwargs["filters"] = access_filter
            rels = self.helper.api_impersonate.stix_core_relationship.list(
                **list_kwargs
            )
            self.helper.log_debug(
                f"Relationships fromOrToId={entity_id}: {len(rels)} found"
            )
            for relationship in rels:
                from_id = (relationship.get("from") or {}).get("id")
                to_id = (relationship.get("to") or {}).get("id")
                neighbor_id = to_id if from_id == entity_id else from_id
                if not neighbor_id or neighbor_id in seen_ids:
                    continue
                candidate_neighbor_ids.add(neighbor_id)
        return candidate_neighbor_ids

    def _access_filter_for_relationships(self) -> Optional[Dict[str, Any]]:
        """Return ``access_filter`` if it has any usable content, else ``None``.

        ``access_filter`` is treated as optional: an empty / missing
        ``filters`` and ``filterGroups`` payload is normalised to
        ``None`` so callers do not pass a no-op filter container to
        the platform.

        The "has usable content" check is delegated to
        :func:`lib.filters.access_filter_has_content` — the same helper
        that :func:`lib.filters.build_neighbor_filter` and
        :func:`lib.filters.build_query_filter` use to decide whether to
        AND the access filter in. Sharing that helper keeps the
        relationship-discovery step (this method) and the
        neighbour-object fetch (``build_neighbor_filter``) from ever
        diverging on what counts as an "empty" access filter, which is
        a marking-enforcement invariant the connector must preserve.
        """
        return (
            self.access_filter
            if access_filter_has_content(self.access_filter)
            else None
        )

    @staticmethod
    def _row_for(entity: Dict[str, Any], header: str) -> str:
        """Render the cell content for ``header`` on ``entity``."""
        if header.startswith(HASH_HEADER_PREFIX):
            algo = header[len(HASH_HEADER_PREFIX) :]
            for hashed in entity.get("hashes") or []:
                # Defensively coerce ``None`` / non-dict items to an empty
                # dict, matching ``lib.headers.build_headers`` — a single
                # malformed entry in ``entity["hashes"]`` should not abort
                # the entire export with ``AttributeError``.
                hashed_dict = hashed if isinstance(hashed, dict) else {}
                if hashed_dict.get("algorithm") == algo:
                    return sanitize_cell(hashed_dict.get("hash"))
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
                return render_dict_list(value)
            return ""
        if isinstance(value, dict):
            return render_dict_item(value)
        return ""

    def _get_content(self, export_list: List[Tuple[Dict[str, Any], int]]) -> bytes:
        """Render ``export_list`` as an ODS document and return its bytes."""
        entities_list = [entry[0] for entry in export_list]
        # ``lib.headers.build_headers`` is dependency-free so the header
        # logic can be unit-tested without LibreOffice; it also builds
        # the union of entity keys iteratively (``set.update`` per
        # entity) rather than via ``set().union(*generator)`` so memory
        # stays linear in the number of entities and we don't hit
        # CPython's positional-argument unpacking limit on large exports.
        headers = build_headers(entities_list, _HASH_ALGORITHMS)

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
        self.file_name = sanitize_file_name(data.get("file_name", ""))
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
            export_query_filter = build_query_filter(
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
