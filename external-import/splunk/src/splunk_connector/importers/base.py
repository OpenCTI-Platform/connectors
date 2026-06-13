"""Base importer contract."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from splunk_connector.client import SplunkClient
from splunk_connector.converter_to_stix import ConverterToStix
from splunk_connector.settings import ConnectorSettings


class BaseImporter:
    """Common importer behavior for independently scheduled datasets."""

    state_key: str
    name: str

    def __init__(
        self,
        config: ConnectorSettings,
        client: SplunkClient,
        converter: ConverterToStix,
    ) -> None:
        self.config = config
        self.client = client
        self.converter = converter

    @property
    def interval(self) -> timedelta:
        raise NotImplementedError

    def collect(
        self, state: dict[str, Any]
    ) -> tuple[list[Any], dict[str, Any]]:
        raise NotImplementedError

    def should_run(self, state: dict[str, Any], now: datetime) -> bool:
        dataset_state = state.get(self.state_key, {})
        last_success = self._parse_state_datetime(dataset_state.get("last_success"))
        if last_success is None:
            return True
        return now - last_success >= self.interval

    def success_state(self, objects_count: int, records_count: int) -> dict[str, Any]:
        return {
            "last_success": datetime.now(UTC).isoformat(),
            "objects_count": objects_count,
            "records_count": records_count,
        }

    @staticmethod
    def _parse_state_datetime(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    @staticmethod
    def _cap_records(records: list[dict[str, Any]], max_records: int) -> list[dict[str, Any]]:
        if max_records <= 0:
            return records
        return records[:max_records]
