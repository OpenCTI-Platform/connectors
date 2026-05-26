from datetime import timedelta
from typing import Annotated

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import BeforeValidator, Field


def _normalize_dataset_url(v):
    """Normalise the documented "set to ``false`` to disable" UX onto a plain ``str``.

    The dataset URL fields are documented to accept the literal value
    ``false`` (real YAML boolean or env-var string ``"false"``, case-
    insensitive, surrounding whitespace tolerated) as a sentinel that
    disables the dataset. Previously the field was typed
    ``str | Literal[False]`` to model that contract directly, but the
    resulting JSON Schema (``anyOf: [{"type": "string"}, {"const": false,
    "type": "boolean"}]``) is rejected by the OpenCTI Manager / XTM
    Composer UI - every URL field rendered as
    "CONFIG_SECTORS_FILE_URL - Unsupported" and could not be edited.

    Normalise both shapes to an empty string ``""``; the downstream
    consumer (`OpenCTI.__init__`) then filters disabled URLs out with a
    plain truthy check (``if url``). This preserves backwards
    compatibility for every documented input - real YAML ``false``,
    env-var ``"false"`` / ``"FALSE"`` / ``"  false  "`` - while exposing
    a clean ``{"type": "string"}`` to the schema generator.
    """
    if v is False:
        return ""
    if isinstance(v, str) and v.strip().lower() == "false":
        return ""
    return v


# Plain ``str`` field that accepts the documented "false to disable"
# sentinels (real bool ``False`` and the case-insensitive string
# ``"false"``) and normalises them to ``""``. Anything else passes
# through to Pydantic's standard ``str`` validation, which rejects real
# booleans (``True`` is not a string) - so a bogus ``True`` still fails
# fast at startup instead of crashing inside ``urllib.request.urlopen``
# on the first scheduled run.
DatasetUrl = Annotated[str, BeforeValidator(_normalize_dataset_url)]


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

    sectors_file_url: DatasetUrl = Field(
        description="URL to sectors dataset (set to `false` or leave empty to disable).",
        default="https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json",
    )
    geography_file_url: DatasetUrl = Field(
        description="URL to geography dataset (set to `false` or leave empty to disable).",
        default="https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json",
    )
    companies_file_url: DatasetUrl = Field(
        description="URL to companies dataset (set to `false` or leave empty to disable).",
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
