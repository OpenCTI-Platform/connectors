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
    """Normalise every documented "disable this dataset" sentinel onto a plain ``str``.

    The dataset URL fields are documented (README + ``config.yml.sample``)
    to accept several equivalent ways of disabling a dataset:

    - real YAML boolean ``false`` (``sectors_file_url: false``),
    - env-var / Docker string ``"false"`` (case-insensitive, surrounding
      whitespace tolerated),
    - an explicit YAML null value (key present with no value -
      ``sectors_file_url:`` or ``sectors_file_url: null`` - both of
      which PyYAML surfaces as Python ``None``). The ``None`` -> ``""``
      branch below covers this case. (When the key is omitted
      entirely, Pydantic substitutes the field's default URL; that
      default still flows through this validator because
      ``BaseConfigModel`` sets ``validate_default=True``, but the
      default is a real URL string that simply passes through
      unchanged - it is not a disable sentinel and the dataset
      stays enabled.)
    - the operator-friendly empty / whitespace-only string (UI input
      or env var trimmed to nothing).

    Previously the field was typed ``str | Literal[False]`` to model the
    ``false`` contract directly, but the resulting JSON Schema
    (``anyOf: [{"type": "string"}, {"const": false, "type": "boolean"}]``)
    is rejected by the OpenCTI Manager / XTM Composer UI - every URL
    field rendered as "CONFIG_SECTORS_FILE_URL - Unsupported" and could
    not be edited. Normalise every disable shape to the empty string
    ``""``; the downstream consumer (`OpenCTI.__init__`) then filters
    disabled URLs out with a plain truthy check (``if url``). This
    preserves backwards compatibility for every documented input while
    exposing a clean ``{"type": "string"}`` to the schema generator.

    Anything that is not a recognised disable sentinel falls through to
    Pydantic's standard ``str`` validation - in particular real ``True``
    is still rejected (``True`` is not a string and this validator does
    not coerce it) so a bogus ``True`` fails fast at startup instead of
    crashing inside ``urllib.request.urlopen`` on the first scheduled
    run. Real URL strings are passed through unchanged (no stripping)
    so an operator-supplied URL keeps its exact value.
    """
    if v is None or v is False:
        return ""
    if isinstance(v, str):
        stripped = v.strip()
        if not stripped or stripped.lower() == "false":
            return ""
    return v


# Plain ``str`` field that accepts the documented "false to disable"
# sentinels (real bool ``False`` and the case-insensitive string
# ``"false"``) and normalises them to ``""``. The two booleans are
# handled asymmetrically on purpose:
#
# * ``False`` is the documented disable sentinel. The
#   ``BeforeValidator`` above catches it and rewrites it to ``""``
#   before Pydantic's standard ``str`` check runs, so the value
#   reaches the typed field as a valid string and the downstream
#   ``if url`` filter drops it.
# * ``True`` has no semantic meaning on a URL field ("enable the
#   URL" is not a thing - either set a real URL or leave the
#   default). ``_normalize_dataset_url`` deliberately does NOT catch
#   it, so it flows through to Pydantic's ``str`` check and is
#   rejected at validation time (``True`` is not a string). An
#   operator who sets ``CONFIG_SECTORS_FILE_URL=True`` therefore
#   gets a clear ``ConfigValidationError`` at startup instead of a
#   confusing ``TypeError`` from inside
#   ``urllib.request.urlopen(True)`` on the first scheduled run.
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
