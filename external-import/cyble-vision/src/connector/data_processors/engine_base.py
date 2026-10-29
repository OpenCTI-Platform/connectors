"""Shared setup for Cyble engine document processors."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

from connectors_sdk import ApiClientError, BaseDataProcessor
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from cyble_client import CybleEngineClient
from cyble_client.engine_dates import parse_engine_datetime

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state import ConnectorState


class EngineDocumentsProcessor(BaseDataProcessor):
    """Common author, marking, client, and date window for engine APIs."""

    settings: ConnectorSettings
    state: ConnectorState
    work_name: str

    def post_init(self) -> None:
        cfg = self.settings.cyble_vision
        self.client = CybleEngineClient(
            base_url=str(cfg.engine_api_base_url),
            api_token=cfg.api_token.get_secret_value(),
            page_size=cfg.engine_page_size,
            logger=self.logger,
        )
        self.author = OrganizationAuthor(
            name="Cyble",
            description="Cyble Vision threat intelligence and digital risk protection.",
        )
        self.default_marking = TLPMarking(level=cfg.tlp_level)

    def window(self, checkpoint: str | None) -> tuple[datetime, datetime]:
        until = datetime.now(timezone.utc)
        since = None
        if checkpoint:
            since = parse_engine_datetime(checkpoint)
        if since is None:
            if self.state.last_run:
                since = self.state.last_run
            else:
                since = self.settings.cyble_vision.import_since
        return since, until

    def collect_pages(self, iterator: Callable, checkpoint: str | None, product: str):
        since, until = self.window(checkpoint)
        self.logger.info(
            "Collecting Cyble engine documents",
            {
                "product": product,
                "since": since.isoformat(),
                "until": until.isoformat(),
            },
        )
        try:
            yield from iterator(since=since, until=until)
        except ApiClientError as err:
            self.logger.warning(
                "Skipping Cyble engine product after API error",
                {"product": product, "error": str(err)},
            )
