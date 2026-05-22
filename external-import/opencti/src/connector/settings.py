from datetime import timedelta
from typing import Annotated

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import BeforeValidator, Field


def _coerce_false(v):
    """Coerce the literal string ``"false"`` (case-insensitive) to the bool ``False``.

    The dataset URL fields document a "set to ``false`` to disable" toggle, but
    Pydantic / Docker / YAML / env-var configuration delivers booleans as strings
    in many setups (`CONFIG_SECTORS_FILE_URL=false` lands as the string
    ``"false"``). Without this coercion the typed ``str`` field happily stores
    the literal string ``"false"``, the downstream filter
    ``url is not False`` never matches, and the connector then tries to fetch
    the URL ``"false"`` and logs an error. Coerce up-front so the disable
    contract works as documented.
    """
    if isinstance(v, str) and v.strip().lower() == "false":
        return False
    return v


# Either a URL string (the active dataset endpoint) or the bool ``False``
# (dataset disabled). The connector filters out ``False`` entries at the
# url-list construction step so the disable-via-config-false UX advertised
# in the README and ``config.yml.sample`` keeps working end-to-end.
FalsableUrl = Annotated[str | bool, BeforeValidator(_coerce_false)]


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="OpenCTI Datasets",
    )
    # Default scope mirrors ``src/config.yml.sample`` / ``docker-compose.yml`` so
    # the bundle's ``entities_types`` is non-empty out of the box; the dataset
    # bundles ship marking-definitions, identities (sectors / companies), and
    # locations (countries / regions).
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["marking-definition", "identity", "location"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class OpenctiConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `OpenctiConnector`.
    """

    sectors_file_url: FalsableUrl = Field(
        description="URL to sectors dataset (set to `false` to disable).",
        default="https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json",
    )
    geography_file_url: FalsableUrl = Field(
        description="URL to geography dataset (set to `false` to disable).",
        default="https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json",
    )
    companies_file_url: FalsableUrl = Field(
        description="URL to companies dataset (set to `false` to disable).",
        default="https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/companies.json",
    )
    remove_creator: bool = Field(
        description="Remove creator identity from imported objects.",
        default=False,
    )
    interval: int = Field(
        description="Interval in days between connector runs.",
        default=7,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `OpenctiConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    config: OpenctiConfig = Field(default_factory=OpenctiConfig)
