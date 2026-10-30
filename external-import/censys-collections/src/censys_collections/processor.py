"""BaseDataProcessor implementation for Censys Collections ingestion."""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

from censys_collections.client import Client
from censys_collections.converter import Converter
from censys_collections.settings import ConfigLoader
from censys_collections.state import CensysCollectionsState
from censys_platform import Collection
from connectors_sdk import (
    BaseDataProcessor,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import BaseObject


class CollectionsProcessor(BaseDataProcessor):
    """Fetch every collection asset and stream it into OpenCTI as observables."""

    work_name = "Censys Collections"

    def __init__(self, client: Client, converter: Converter) -> None:
        self.client = client
        self.converter = converter

    # ------------------------------------------------------------------
    # BaseDataProcessor interface
    # ------------------------------------------------------------------

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

        A collection already ingested is skipped when ``skip_unchanged_collections``
        is enabled and Censys reports no asset additions since its checkpoint.

        A failure while fetching one collection's assets (e.g. a persistent
        network timeout) is logged and skipped rather than aborting the
        remaining collections in this run. If *every* fetched collection fails
        (e.g. an invalid API token), a ``DataRetrievalError`` is raised so the
        run is reported as failed and the connector state is not advanced.
        """
        attempted_collections = 0
        failed_collections = 0
        for collection in data:
            self.work_name = f"Censys Collections — {collection.name}"
            if self._is_unchanged(collection):
                self.logger.info(
                    f"Censys Collections: no assets added to '{collection.name}' "
                    f"(id={collection.id}) since its last ingestion — skipping."
                )
                continue

            self.logger.info(
                f"Censys Collections: processing '{collection.name}' "
                f"(id={collection.id}, assets={collection.total_assets})."
            )
            attempted_collections += 1
            fetch_started_at = datetime.now(tz=timezone.utc)
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
                failed_collections += 1
                continue

            if objects:
                grouping = self.converter.build_grouping(collection, objects)
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

            self._set_checkpoint(collection.id, fetch_started_at)

        if attempted_collections and failed_collections == attempted_collections:
            raise DataRetrievalError(
                f"Censys Collections: failed to fetch assets for all "
                f"{failed_collections} collection(s); marking this run as failed."
            )

    # ------------------------------------------------------------------
    # Incremental ingestion
    # ------------------------------------------------------------------

    def _checkpoints(self) -> dict[str, datetime]:
        state: CensysCollectionsState = self.state  # type: ignore[assignment]
        return dict(getattr(state, "collection_checkpoints", None) or {})

    def _set_checkpoint(self, collection_id: str, fetched_at: datetime) -> None:
        """Record *fetched_at* as *collection_id*'s checkpoint.

        Called once the collection's bundle has been sent. The checkpoint is
        the time the fetch started, so assets added while it was running are
        picked up on the next run. It is persisted with the rest of the state
        only when the whole run succeeds.
        """
        checkpoints = self._checkpoints()
        checkpoints[collection_id] = fetched_at
        self.state.collection_checkpoints = checkpoints  # type: ignore[attr-defined]

    def _is_unchanged(self, collection: Collection) -> bool:
        """Return whether *collection* can be skipped for this run.

        A collection is never skipped on its first ingestion, when
        ``skip_unchanged_collections`` is disabled, or when the events lookup
        fails (the collection is then fully re-ingested).
        """
        settings: ConfigLoader = self.settings  # type: ignore[assignment]
        if not settings.censys_collections.skip_unchanged_collections:
            return False

        checkpoint = self._checkpoints().get(collection.id)
        if checkpoint is None:
            return False

        try:
            return not self.client.has_added_assets_since(collection.id, checkpoint)
        except Exception as error:
            self.logger.warning(
                f"Censys Collections: failed to read events for collection "
                f"'{collection.name}' (id={collection.id}): {error}. "
                f"Ingesting it in full."
            )
            return False
