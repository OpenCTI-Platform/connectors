"""BaseDataProcessor implementation for Censys Collections ingestion."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from censys_platform import Collection
from connectors_sdk import (
    BaseConnectorSettings,
    BaseDataProcessor,
    ExternalImportConnectorState,
)
from connectors_sdk.models import BaseObject
from pycti import OpenCTIConnectorHelper

from censys_collections.client import Client
from censys_collections.converter import Converter
from censys_collections.settings import ConfigLoader


class CollectionsProcessor(BaseDataProcessor):
    """Fetch every collection asset and stream it into OpenCTI as observables."""

    work_name = "Censys Collections"

    def __init__(self, client: Client, converter: Converter) -> None:
        self.client = client
        self.converter = converter

    # ------------------------------------------------------------------
    # BaseDataProcessor interface
    # ------------------------------------------------------------------

    def inject_dependencies(
        self,
        settings: BaseConnectorSettings,
        helper: OpenCTIConnectorHelper,
        state: ExternalImportConnectorState,
    ) -> None:
        """Inject dependencies, keeping a direct helper reference for grouping maintenance."""
        super().inject_dependencies(settings, helper, state)
        self._helper = helper

    def collect(self) -> list[Collection]:
        """Return all collections that should be ingested this run.

        ``collection_ids`` (an allow-list) takes precedence over
        ``excluded_collection_ids`` (a deny-list) if both are configured.
        """
        settings: ConfigLoader = self.settings  # type: ignore[assignment]
        all_collections = list(self.client.list_collections())

        included_ids: list[str] | None = settings.censys_collections.collection_ids
        excluded_ids: list[str] | None = (
            settings.censys_collections.excluded_collection_ids
        )

        if included_ids:
            if excluded_ids:
                self.logger.warning(
                    "Censys Collections: both 'collection_ids' and "
                    "'excluded_collection_ids' are set; 'excluded_collection_ids' "
                    "will be ignored."
                )
            all_collections = [c for c in all_collections if c.id in included_ids]
        elif excluded_ids:
            excluded_id_set = set(excluded_ids)
            all_collections = [
                c for c in all_collections if c.id not in excluded_id_set
            ]

        self.logger.info(
            f"Censys Collections: {len(all_collections)} collection(s) to ingest."
        )
        return all_collections

    def transform(
        self, data: list[Collection]
    ) -> Generator[list[BaseObject], None, None]:
        """Yield one bundle of OpenCTI objects per collection.

        A failure while fetching one collection's assets (e.g. a persistent
        network timeout) is logged and skipped rather than aborting the
        remaining collections in this run.
        """
        for collection in data:
            self.work_name = f"Censys Collections — {collection.name}"
            self.logger.info(
                f"Censys Collections: processing '{collection.name}' "
                f"(id={collection.id}, assets={collection.total_assets})."
            )
            objects: list[Any] = []
            try:
                for hit in self.client.fetch_collection_hits(collection.id):
                    objects.extend(self.converter.from_hit(hit, collection))
            except Exception as error:
                self.logger.error(
                    f"Censys Collections: failed to fetch assets for "
                    f"collection '{collection.name}' (id={collection.id}): "
                    f"{error}. Skipping this collection for this run."
                )
                continue

            if objects:
                object_refs = [obj.id for obj in objects if hasattr(obj, "id")]
                grouping = self.converter.build_grouping(collection, objects)
                if grouping is not None:
                    self._prune_stale_grouping_members(grouping.id, object_refs)

                bundle = self.converter.bootstrap_objects() + objects
                if grouping is not None:
                    bundle.append(grouping)
                self.logger.info(
                    f"Censys Collections: yielding {len(bundle)} object(s) "
                    f"for collection '{collection.name}'."
                )
                yield bundle
            else:
                self.logger.info(
                    f"Censys Collections: no objects generated for "
                    f"collection '{collection.name}' — skipping."
                )

    # ------------------------------------------------------------------
    # Grouping maintenance
    # ------------------------------------------------------------------

    def _prune_stale_grouping_members(
        self, grouping_stix_id: str, current_refs: list[str]
    ) -> None:
        """Unlink any Grouping member that's no longer part of the collection.

        STIX bundle ingestion only ever *adds* to a Grouping's membership, so
        Censys assets removed from a collection between runs would otherwise
        stay attached forever. This diffs the existing Grouping's current
        members (fetched via the OpenCTI API) against *current_refs* and
        explicitly removes any that are no longer present.
        """
        try:
            existing = self._helper.api.grouping.read(id=grouping_stix_id)
        except Exception as error:
            self.logger.error(
                f"Censys Collections: failed to read existing grouping "
                f"{grouping_stix_id} for pruning: {error}"
            )
            return

        if not existing:
            return  # First run for this collection - nothing to prune yet.

        current_ref_set = set(current_refs)
        stale_ids = [
            member["standard_id"]
            for member in existing.get("objects") or []
            if member.get("standard_id")
            and member["standard_id"] not in current_ref_set
        ]
        if not stale_ids:
            return

        self.logger.info(
            f"Censys Collections: pruning {len(stale_ids)} stale member(s) "
            f"from grouping '{existing.get('name')}'."
        )
        for stale_id in stale_ids:
            try:
                self._helper.api.grouping.remove_stix_object_or_stix_relationship(
                    id=existing["id"],
                    stixObjectOrStixRelationshipId=stale_id,
                )
            except Exception as error:
                self.logger.error(
                    f"Censys Collections: failed to remove stale member "
                    f"{stale_id} from grouping: {error}"
                )
