from __future__ import annotations

"""Connector configuration.

This connector is configured primarily through environment variables.
`load_config()` converts an `os.environ`-like mapping into a typed `Config`.

Required variables:
- `OPENCTI_URL`, `OPENCTI_TOKEN`
- `CONNECTOR_ID`, `CONNECTOR_TYPE`, `CONNECTOR_NAME`, `CONNECTOR_SCOPE`, `CONNECTOR_LOG_LEVEL`
- `PRAVDA_DATASET_PATH`

Optional variables:
- `PRAVDA_INTERVAL_MINUTES`, `PRAVDA_BATCH_SIZE`, `PRAVDA_RUN_MODE`
- resource guards: `PRAVDA_MAX_FILE_BYTES`, `PRAVDA_MAX_ROW_BYTES`, `PRAVDA_MAX_ROWS_PER_FILE`
"""

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Config:
    """Runtime configuration for the connector."""

    opencti_url: str
    opencti_token: str
    connector_id: str
    connector_type: str
    connector_name: str
    connector_scope: str
    connector_log_level: str

    dataset_path: str
    interval_minutes: int = 60
    batch_size: int = 1000

    # Operation mode
    run_mode: str = "loop"  # "loop" (default) or "once"

    # Resource guards (optional)
    max_file_bytes: int | None = None
    max_row_bytes: int | None = None
    max_rows_per_file: int | None = None


class ConfigError(ValueError):
    """Raised when config is missing or malformed."""

    pass


def _require_str(environ: Mapping[str, str], key: str) -> str:
    """Read a required string env var and reject empty/whitespace."""
    value = (environ.get(key) or "").strip()
    if not value:
        raise ConfigError(f"Missing required environment variable: {key}")
    return value


def _optional_int(environ: Mapping[str, str], key: str) -> int | None:
    """Read an optional positive integer env var.

    Returns None if unset/empty.
    """
    raw = environ.get(key)
    if raw is None or str(raw).strip() == "":
        return None
    try:
        parsed = int(str(raw).strip())
    except ValueError as exc:
        raise ConfigError(f"Invalid integer for {key}: {raw!r}") from exc
    if parsed <= 0:
        raise ConfigError(f"{key} must be > 0")
    return parsed


def load_config(environ: Mapping[str, str]) -> Config:
    """Load connector configuration from an environment mapping."""
    interval_minutes = _optional_int(environ, "PRAVDA_INTERVAL_MINUTES") or 60
    batch_size = _optional_int(environ, "PRAVDA_BATCH_SIZE") or 1000

    run_mode = (environ.get("PRAVDA_RUN_MODE") or "loop").strip().lower()
    if run_mode not in {"loop", "once"}:
        raise ConfigError("PRAVDA_RUN_MODE must be 'loop' or 'once'")

    return Config(
        opencti_url=_require_str(environ, "OPENCTI_URL"),
        opencti_token=_require_str(environ, "OPENCTI_TOKEN"),
        connector_id=_require_str(environ, "CONNECTOR_ID"),
        connector_type=_require_str(environ, "CONNECTOR_TYPE"),
        connector_name=_require_str(environ, "CONNECTOR_NAME"),
        connector_scope=_require_str(environ, "CONNECTOR_SCOPE"),
        connector_log_level=_require_str(environ, "CONNECTOR_LOG_LEVEL"),
        dataset_path=_require_str(environ, "PRAVDA_DATASET_PATH"),
        interval_minutes=interval_minutes,
        batch_size=batch_size,
        run_mode=run_mode,
        max_file_bytes=_optional_int(environ, "PRAVDA_MAX_FILE_BYTES"),
        max_row_bytes=_optional_int(environ, "PRAVDA_MAX_ROW_BYTES"),
        max_rows_per_file=_optional_int(environ, "PRAVDA_MAX_ROWS_PER_FILE"),
    )
