import json
import warnings
from datetime import timedelta
from typing import Any

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr, field_validator, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        description="The name of the connector.",
        default="SOCRadar",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'socradar'.",
        default=["socradar"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=10),
    )


class FeedList(BaseConfigModel):
    """Represent a single SOCRadar feed list to fetch."""

    name: str = Field(description="The name of SOCRadar feed list to fetch.")
    id: str = Field(description="The ID of SOCRadar feed list to fetch.")


class RadarConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the SOCRadar connector.
    """

    base_feed_url: str = Field(description="SOCRadar Feed API base URL.")
    socradar_key: SecretStr = Field(
        description="The API key to connect to SOCRadar.",
    )
    feed_lists: list[FeedList] = Field(
        description="The SOCRadar feed lists to fetch.",
    )
    run_interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(seconds=int(x)),
    )

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_collections_uuid(cls, data: Any) -> Any:
        """
        Env var `RADAR_COLLECTIONS_UUID` is deprecated.
        This is a workaround to keep the old config working while migrating to `RADAR_FEED_LISTS`.
        """
        if not isinstance(data, dict):
            return data

        # Legacy: key will differ whether data comes from env vars or from config.yml
        collections: dict | str | None = data.pop("collections_uuid", None) or data.pop(
            "radar_collections_uuid", None
        )
        if collections:
            warnings.warn(
                "Env var 'RADAR_COLLECTIONS_UUID' is deprecated. Use 'RADAR_FEED_LISTS' instead."
            )

            # If data comes from env vars, collections is serialized JSON
            if isinstance(collections, str):
                collections = json.loads(collections)

            feed_lists = data.get("feed_lists") or {}
            for collection_data in collections.values():
                name = collection_data.get("name")
                id = collection_data.get("id")
                if name and id:  # /!\ name and id are lists, not strings
                    feed_lists[name[0]] = id[0]

            data["feed_lists"] = feed_lists

        return data

    @field_validator("feed_lists", mode="before")
    @classmethod
    def convert_feed_lists(cls, value: Any) -> Any:
        """
        Config/env vars must be as flat as possible.
        This is a util method to format feed lists, making them easier to use in the rest of the codebase.
        """
        if isinstance(value, str):
            value = json.loads(value)
        if isinstance(value, dict):
            return [{"name": name, "id": id} for (name, id) in value.items()]
        return value


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `RadarConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    radar: RadarConfig = Field(default_factory=RadarConfig)
