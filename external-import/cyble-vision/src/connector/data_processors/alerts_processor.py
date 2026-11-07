"""Import Cyble Vision alerts into OpenCTI."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Generator

from connector.mappers import AlertConversionError, map_alert
from connector.mappers.common import parse_datetime
from connectors_sdk import ApiClientError, BaseDataProcessor
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from cyble_client import CybleVisionClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state import ConnectorState
    from connectors_sdk.models import BaseIdentifiedObject


class AlertsProcessor(BaseDataProcessor):
    """Fetch Vision alerts and convert them to STIX.

    One API request per service (required by the Alerts API). Pages are
    yielded so a large tenant never sits entirely in memory.
    """

    settings: ConnectorSettings
    state: ConnectorState

    work_name = "Cyble Vision alerts import"

    def post_init(self) -> None:
        cfg = self.settings.cyble_vision
        self.client = CybleVisionClient(
            base_url=str(cfg.api_base_url),
            api_token=cfg.api_token.get_secret_value(),
            page_size=cfg.page_size,
            logger=self.logger,
        )
        self.author = OrganizationAuthor(
            name="Cyble",
            description="Cyble Vision threat intelligence and digital risk protection.",
        )
        self.tlp_marking = TLPMarking(level=cfg.tlp_level)

    def collect(self) -> Generator[tuple[str, list[dict]], None, None]:
        """Yield ``(service, page)`` tuples of raw alerts."""
        until = datetime.now(timezone.utc)
        services = self._services()

        for service in services:
            since = self._since_for(service)
            self.logger.info(
                "Collecting Cyble Vision alerts",
                {
                    "service": service,
                    "since": since.isoformat(),
                    "until": until.isoformat(),
                },
            )
            try:
                for page in self.client.iter_alerts(
                    service=service,
                    since=since,
                    until=until,
                    exclude_statuses=self.settings.cyble_vision.exclude_statuses,
                ):
                    yield service, page
            except ApiClientError as err:
                # One unentitled or failing service must not stop the whole run.
                self.logger.warning(
                    "Skipping Cyble Vision service after API error",
                    {"service": service, "error": str(err)},
                )

    def transform(
        self, pages: Generator[tuple[str, list[dict]], None, None]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        """Convert each page and advance that service's high-water mark."""
        cfg = self.settings.cyble_vision

        for service, page in pages:
            stix_objects: list[BaseIdentifiedObject] = []
            last_created = None

            for alert in page:
                try:
                    stix_objects.extend(
                        map_alert(
                            alert,
                            author=self.author,
                            marking=self.tlp_marking,
                            portal_url_template=cfg.portal_url_template,
                        )
                    )
                    last_created = alert.get("created_at") or last_created
                except AlertConversionError as err:
                    self.logger.warning(
                        "Failed to convert alert, skipping it",
                        {
                            "alert_id": alert.get("id"),
                            "service": service,
                            "error": str(err),
                        },
                    )

            if last_created:
                parsed = parse_datetime(last_created)
                if parsed:
                    self.state.last_alert_created_at = {
                        **(self.state.last_alert_created_at or {}),
                        service: parsed.isoformat(),
                    }

            if stix_objects:
                self.work_name = f"Cyble Vision alerts import - {service}"
                yield [self.author, self.tlp_marking] + stix_objects

    def _services(self) -> list[str]:
        entitled = self.client.list_services()
        allow = self.settings.cyble_vision.alert_services
        if not allow:
            selected = list(entitled)
        else:
            selected = [name for name in entitled if name in allow]
        missing = sorted(set(allow) - set(entitled))
        if missing:
            self.logger.warning(
                "Configured services are not entitled for this token",
                {"missing": missing},
            )
        skip = set()
        cfg = self.settings.cyble_vision
        if cfg.enable_advisories:
            skip.add("advisory")
        if cfg.enable_newsflash:
            skip.add("flash_report")
        if cfg.enable_newsfeed:
            skip.add("news_feed")
        if skip:
            dropped = [name for name in selected if name in skip]
            selected = [name for name in selected if name not in skip]
            if dropped:
                self.logger.info(
                    "Skipping document alert services; engine APIs own those Reports",
                    {"skipped": dropped},
                )
        return selected

    def _since_for(self, service: str) -> datetime:
        raw = (self.state.last_alert_created_at or {}).get(service)
        if raw:
            parsed = parse_datetime(raw)
            if parsed:
                return parsed
        if self.state.last_run:
            return self.state.last_run
        return self.settings.cyble_vision.import_since
