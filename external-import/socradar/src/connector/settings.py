import json
from datetime import timedelta
from typing import Any

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, Json, SecretStr


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


def collections_uuid_to_feed_lists(value: Any) -> str:
    """
    Convert a deprecated `collections_uuid` mapping into a `feed_lists` mapping.
    Used to migrate `RADAR_COLLECTIONS_UUID` to `RADAR_FEED_LISTS`.
    Returns a JSON string, as `feed_lists` is typed as `Json[dict[str, str]]`.
    """
    # If data comes from env vars, collections is serialized JSON
    if isinstance(value, str):
        value = json.loads(value)

    feed_lists: dict[str, str] = {}
    for collection_data in value.values():
        name = collection_data.get("name")
        id = collection_data.get("id")
        if name and id:  # /!\ name and id are lists, not strings
            feed_lists[name[0]] = id[0]
    return json.dumps(feed_lists)


class RadarConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the SOCRadar connector.
    """

    base_feed_url: str = Field(description="SOCRadar Feed API base URL.")
    socradar_key: SecretStr = Field(
        description="The API key to connect to SOCRadar.",
    )
    feed_lists: Json[dict[str, str]] = Field(
        description="The SOCRadar feed lists to fetch, as a JSON object mapping "
        'each feed list name to its ID. Example: \'{"feed_list_1": "ID_1", "feed_list_2": "ID_2"}\'',
    )
    run_interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(seconds=int(x)),
    )
    collections_uuid: dict | None = DeprecatedField(
        default=None,
        deprecated="Use 'RADAR_FEED_LISTS' instead.",
        new_namespaced_var="feed_lists",
        new_value_factory=collections_uuid_to_feed_lists,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `RadarConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    radar: RadarConfig = Field(default_factory=RadarConfig)
