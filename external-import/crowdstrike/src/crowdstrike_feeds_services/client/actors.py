from typing import List, Optional

from .base_api import BaseCrowdstrikeClient


class ActorsAPI(BaseCrowdstrikeClient):
    def __init__(self, helper):
        super().__init__(helper)

    def get_combined_actor_entities(
        self, limit: int, offset: int, sort: str, fql_filter: str, fields: list
    ):
        """
        Get info about actors that match provided FQL filters.
        :param limit: Maximum number of records to return (Max: 5000) in integer
        :param offset: Starting index of overall result set from which to return ids in integer
        :param sort: The property to sort by. (Ex: created_date|desc) in str
        :param fql_filter: FQL query expression that should be used to limit the results in str
        :param fields: The fields to return, or a predefined set of fields in the form of the collection name
        surrounded by two underscores like: __<collection>__. Ex: slug __full__. Defaults to __basic__.
        :return: Dict object containing API response
        """

        response = self.cs_intel.query_actor_entities(
            limit=limit, offset=offset, sort=sort, filter=fql_filter, fields=fields
        )

        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting combined actor entities...")

        return response["body"]

    def query_mitre_attacks(self, actor_id: int):
        """
        Query MITRE ATT&CK techniques associated with a specific threat actor.
        :param actor_id: The ID for the threat actor
        :return: Dict object containing API response with TTP data in format:
                 {'errors': [], 'meta': {...}, 'resources': ['actor_TA0001_T1190', ...]}
        """
        response = self.cs_intel.query_mitre_attacks(id=str(actor_id))

        self.handle_api_error(response)
        self.helper.connector_logger.info(
            f"Getting MITRE attacks for actor ID: {actor_id}..."
        )

        return response["body"]

    def get_actor_entities(self, ids: list, fields: list):
        """Retrieve specific actors using their actor IDs."""
        response = self.cs_intel.get_actor_entities(ids=ids, fields=fields)
        self.handle_api_error(response)
        self.helper.connector_logger.info("Getting actor entities...")
        return response["body"]

    def get_actors_by_slugs(
        self,
        slugs: List,
        fields: Optional[List[str]] = None,
    ):
        """Resolve one or more threat actors from mixed tokens.

        Inputs may be:
        - dict stubs (common in Reports): {"id": ..., "name": ..., "slug": ...}
        - strings (common in Indicators): actor names (Pascal/Title Case / uppercase) or slugs

        We resolve in 3 passes and merge results:
        1) ids-only (most reliable)
        2) slugs-only
        3) names-only

        This avoids building overly-large FQL filters that can exceed service limits.
        """

        if fields is None:
            fields = ["__full__"]

        ids: List[int] = []
        slugs_list: List[str] = []
        names: List[str] = []

        for item in slugs or []:
            if not item:
                continue

            if isinstance(item, dict):
                if item.get("id") is not None:
                    try:
                        ids.append(int(item.get("id")))
                        continue
                    except Exception:
                        pass

                slug_val = (item.get("slug") or "").strip()
                if slug_val:
                    slugs_list.append(slug_val)
                    continue
                name_val = (item.get("name") or "").strip()
                if name_val:
                    names.append(name_val)

                continue

            token = str(item).strip()
            if not token:
                continue

            # Heuristic: kebab-case with no spaces is most likely a slug.
            if "-" in token and " " not in token:
                slugs_list.append(token)
            else:
                names.append(token)

        # De-dupe preserving order
        def _dedupe(seq):
            seen = set()
            out = []
            for x in seq:
                if x in seen:
                    continue
                seen.add(x)
                out.append(x)
            return out

        ids = _dedupe(ids)
        slugs_list = _dedupe(slugs_list)
        names = _dedupe(names)

        if not ids and not slugs_list and not names:
            return {"errors": [], "meta": {}, "resources": []}

        def _chunk(seq, size=18):
            return [seq[i : i + size] for i in range(0, len(seq), size)]

        def _escape(value: str) -> str:
            return value.replace("'", "\\'")

        resources_all: List[dict] = []

        # Pass 1: resolve by IDs using entities endpoint (no FQL)
        if ids:
            for ids_c in _chunk(ids, 500):
                self.helper.connector_logger.debug(
                    "ActorsAPI.resolve_actors by ids",
                    {"ids": ids_c, "fields": fields},
                )
                resp = self.get_actor_entities(ids=ids_c, fields=fields)
                resources_all.extend(resp.get("resources", []))

        # Pass 2: resolve by slugs (FQL OR)
        if slugs_list:
            for slugs_c in _chunk(slugs_list, 18):
                fql_filter = (
                    "(" + ",".join([f"slug:'{_escape(s)}'" for s in slugs_c]) + ")"
                )
                self.helper.connector_logger.debug(
                    "ActorsAPI.resolve_actors by slugs FQL",
                    {"slugs": slugs_c, "filter": fql_filter, "fields": fields},
                )
                resp = self.get_combined_actor_entities(
                    limit=5000,
                    offset=0,
                    sort="name|desc",
                    fql_filter=fql_filter,
                    fields=fields,
                )
                resources_all.extend(resp.get("resources", []))

        # Pass 3: resolve by names (FQL OR)
        if names:
            for names_c in _chunk(names, 18):
                fql_filter = (
                    "(" + ",".join([f"name:'{_escape(n)}'" for n in names_c]) + ")"
                )
                self.helper.connector_logger.debug(
                    "ActorsAPI.resolve_actors by names FQL",
                    {"names": names_c, "filter": fql_filter, "fields": fields},
                )
                resp = self.get_combined_actor_entities(
                    limit=5000,
                    offset=0,
                    sort="name|desc",
                    fql_filter=fql_filter,
                    fields=fields,
                )
                resources_all.extend(resp.get("resources", []))

        # De-dupe results by actor id
        deduped_by_id = {}
        for a in resources_all:
            if isinstance(a, dict) and a.get("id") is not None:
                deduped_by_id[a.get("id")] = a

        resources_final = (
            list(deduped_by_id.values()) if deduped_by_id else resources_all
        )

        self.helper.connector_logger.debug(
            f"Resolved {len(resources_final)} actors from tokens.",
            {
                "requested_ids": ids,
                "requested_slugs": slugs_list,
                "requested_names": names,
            },
        )

        return {"errors": [], "meta": {}, "resources": resources_final}

    @staticmethod
    def build_slug_filter(slugs: List[str]) -> str:
        """
        Build an FQL filter to match threat actors by slug.
        Uses OR semantics between slugs so that any matching slug is returned.
        Example output: "(slug:'bounty-jackal',slug:'stardust-chollima')"
        """
        cleaned_slugs = [str(s).strip() for s in slugs if s and str(s).strip()]
        if not cleaned_slugs:
            return ""

        def _escape(value: str) -> str:
            # Minimal escaping for single quotes in FQL string literals
            return value.replace("'", "\\'")

        # IMPORTANT: filter on `slug`, not `name`
        conditions = [f"slug:'{_escape(slug)}'" for slug in cleaned_slugs]
        return "(" + ",".join(conditions) + ")"
