from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(slots=True)
class ConnectorState:
    last_seen_updated_at: str

    @classmethod
    def empty(cls, initial_lookback_days: int, now_iso: str) -> "ConnectorState":
        bootstrap = _parse_iso_datetime(now_iso) - timedelta(days=initial_lookback_days)
        return cls(last_seen_updated_at=_format_utc(bootstrap))


def next_checkpoint(
    current: ConnectorState, seen_timestamps: list[str]
) -> ConnectorState:
    latest = _parse_iso_datetime(current.last_seen_updated_at)
    for timestamp in seen_timestamps:
        candidate = _parse_iso_datetime(timestamp)
        if candidate > latest:
            latest = candidate
    return ConnectorState(last_seen_updated_at=_format_utc(latest))


def _parse_iso_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
