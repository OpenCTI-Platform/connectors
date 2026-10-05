import json
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr

_TAXONOMY_FILE_PATH = Path(__file__).parent / "resources" / "taxonomy.json"


@lru_cache(maxsize=1)
def _load_taxonomy_mapping() -> dict[str, Any]:
    """Load the taxonomy mapping shipped with the connector's resources.

    :return: The taxonomy mapping, or an empty dict if the resource file is missing.
    """
    if _TAXONOMY_FILE_PATH.is_file():
        with open(_TAXONOMY_FILE_PATH, "r", encoding="utf-8") as file:
            return dict(json.load(file))
    return {}


class AccentureActiConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="358f9d75-bcca-4be9-867c-6692552d3f74",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Accenture ACTI",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["accenture"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class AccentureActiConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ConnectorAccenture`.
    """

    username: str = Field(
        description="The username of the Accenture ACTI account used to authenticate.",
    )
    password: SecretStr = Field(
        description="The password of the Accenture ACTI account used to authenticate.",
    )
    user_pool_id: str = Field(
        description="The AWS Cognito user pool ID provided by Accenture ACTI.",
    )
    client_id: str = Field(
        description="The AWS Cognito client ID provided by Accenture ACTI.",
    )
    s3_bucket_name: str = Field(
        description="The name of the Accenture ACTI S3 bucket to collect data from.",
    )
    s3_bucket_region: str = Field(
        description="The AWS region of the Accenture ACTI S3 bucket.",
    )
    s3_bucket_access_key: SecretStr = Field(
        description="The AWS access key used to read the Accenture ACTI S3 bucket.",
    )
    s3_bucket_secret_key: SecretStr = Field(
        description="The AWS secret key used to read the Accenture ACTI S3 bucket.",
    )
    client_tlp_level: Literal[
        "clear", "white", "green", "amber", "amber+strict", "red"
    ] = DeprecatedField(
        deprecated="Use 'ACCENTURE_ACTI_TLP_LEVEL' instead.",
        new_namespaced_var="tlp_level",
        removal_date="2027-06-30",
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="The TLP marking applied to the imported data.",
            default="amber+strict",
        )
    )
    relative_import_start_date: timedelta = Field(
        description="The relative period of time to look back for the first import.",
        default=timedelta(days=30),
    )
    threat_actor_as_intrusion_set: bool = Field(
        description="Whether to convert imported threat actors into intrusion sets.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `AccentureActiConnectorConfig` and `AccentureActiConfig`.
    """

    connector: AccentureActiConnectorConfig = Field(
        default_factory=AccentureActiConnectorConfig
    )
    accenture_acti: AccentureActiConfig = Field(default_factory=AccentureActiConfig)

    @property
    def mapping(self) -> dict[str, Any]:
        """The taxonomy mapping used to convert Accenture ACTI labels into STIX entities."""
        return _load_taxonomy_mapping()
