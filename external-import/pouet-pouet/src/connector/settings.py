from datetime import timedelta
from typing import Annotated, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
)
from pydantic import Field, HttpUrl
from connectors_sdk.settings.deprecations import Deprecate


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="PouetPouetConnector",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class PouetPouetConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `PouetPouetConnector`.
    """

    api_base_url: HttpUrl = Field(description="API base URL.")
    api_key: str = Field(description="API key for authentication.")
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )
    new: str = Field(
        description="A new configuration parameter.",
        default="default_value",
    )
    test: str = DeprecatedField(
        new_namespaced_var="new",
        new_value_factory=lambda v: f"{v} (migrated from test)",
    )
    annotated_new: str = Field(
        description="A new configuration parameter with an annotation.",
        default="default_value",
    )
    annotated_test: Annotated[
        str,
        Field(
            description="A deprecated configuration parameter with an annotation.",
        ),
        Deprecate(
            new_namespaced_var="annotated_new",
            new_value_factory=lambda v: f"{v} (migrated from annotated_test)",
        ),
    ]


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `PouetPouetConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    pouet_pouet: PouetPouetConfig = Field(default_factory=PouetPouetConfig)
