from datetime import timedelta
from typing import Any

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr, ValidationInfo, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="04e5ba20-0e6f-4265-a723-4803502fd6db",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Checkfirst Import Connector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["checkfirst"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(weeks=1),
    )


class CheckfirstImportConnectorConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CheckfirstImportConnector`.
    """

    api_url: HttpUrl = Field(
        description="Base URL for the API endpoint (e.g., https://api.example.com)."
    )
    api_endpoint: str = Field(
        description="API endpoint path (e.g., /v1/articles).",
        default="/v1/articles",
    )
    api_key: SecretStr = Field(
        description="API key for authentication (sent in Api-Key header)."
    )
    since: DatetimeFromIsoString = Field(
        description=(
            "Only ingest articles published on or after this date. "
            "Accepts ISO 8601 absolute dates (e.g., 2024-01-01T00:00:00Z) "
            "or durations relative to now (e.g., P365D, P1Y, P6M, P4W). "
            "Defaults to 1 year ago."
        ),
        default="P1Y",
    )
    force_reprocess: bool = Field(
        description=(
            "If true, ignore any saved connector cursor and restart from the "
            "beginning of the filtered result set. Useful for debugging or "
            "re-importing all data."
        ),
        default=False,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking level applied to created STIX entities.",
        default=TLPLevel.CLEAR,
    )
    max_row_bytes: int | None = Field(
        description="Skip any API row larger than this approximate number of bytes.",
        default=None,
    )
    convert_workers: int = Field(
        description=(
            "Number of processes used for Row → STIX conversion. "
            "1 keeps conversion in the main process (default). "
            "Values > 1 use a process pool; HTTP fetch and watermark stay serial."
        ),
        default=1,
        ge=1,
    )
    convert_batch_size: int = Field(
        description=(
            "How many articles to convert together when convert_workers > 1. "
            "Larger batches improve process-pool efficiency; keep modest to limit memory."
        ),
        default=32,
        ge=1,
    )
    bundle_size: int = Field(
        description=(
            "Max unique OpenCTI/STIX objects accumulated before prepare+send. "
            "Smaller values send more often (shorter stalls, more OpenCTI work items); "
            "larger values batch more aggressively. Does not change entity IDs or "
            "final data, only how work is chunked."
        ),
        default=10_000,
        ge=1,
    )
    log_file: str | None = Field(
        description=(
            "If set, also write connector logs to this file path (JSON lines). "
            "Mount the parent directory as a Docker volume to keep them on the host."
        ),
        default=None,
    )

    @field_validator(
        "convert_workers",
        "convert_batch_size",
        "bundle_size",
        "max_row_bytes",
        mode="before",
    )
    @classmethod
    def _coerce_optional_int(cls, value: Any, info: ValidationInfo) -> Any:
        """Env/compose always provide strings; coerce to int (empty → field default)."""
        if value is None or (isinstance(value, str) and not value.strip()):
            return cls.model_fields[info.field_name].default
        if isinstance(value, bool):
            raise ValueError("boolean is not a valid integer")
        if isinstance(value, int):
            return value
        return int(str(value).strip())


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `CheckfirstImportConnectorConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    checkfirst: CheckfirstImportConnectorConfig = Field(
        default_factory=CheckfirstImportConnectorConfig
    )
