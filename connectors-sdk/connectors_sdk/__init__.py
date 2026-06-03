"""Offer a package to develop OpenCTI Connectors."""

__version__ = "0.1.0"

from connectors_sdk.client import (
    ApiClientError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
    BaseClientApi,
)
from connectors_sdk.http_client.base_http_client import BaseHttpClient
from connectors_sdk.http_client.http_adapter import RateLimit, RateLimitHTTPAdapter
from connectors_sdk.http_client.exceptions import (
    HttpClientRateLimitError,
    HttpClientException,
    HttpRequestError,
    HttpRequestClientError,
    HttpRequestServerError,
)
from connectors_sdk.connectors.external_import.base_data_processor import (
    BaseDataProcessor,
)
from connectors_sdk.connectors.external_import.external_import_connector import (
    ExternalImportConnector,
)
from connectors_sdk.connectors.external_import.logger import ConnectorLogger
from connectors_sdk.settings.annotated_types import (
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.settings.base_settings import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalExportFileConnectorConfig,
    BaseInternalImportFileConnectorConfig,
    BaseStreamConnectorConfig,
)
from connectors_sdk.settings.deprecations import (
    Deprecate,
    DeprecatedField,
)
from connectors_sdk.settings.exceptions import (
    ConfigError,
    ConfigValidationError,
)
from connectors_sdk.states.states import ExternalImportConnectorState

__all__ = [
    # HTTP Client
    "BaseClientApi",
    "ApiClientError",
    "ApiNotFoundError",
    "ApiRateLimitError",
    "ApiServerError",
    "ApiUnauthorizedError",
    # http_client
    "BaseHttpClient",
    "HttpClientException",
    "HttpClientRateLimitError",
    "HttpRequestError",
    "HttpRequestClientError",
    "HttpRequestServerError",
    "RateLimit",
    "RateLimitHTTPAdapter",
    # connectors
    "ExternalImportConnector",
    "ConnectorLogger",
    "BaseDataProcessor",
    # settings
    "BaseConfigModel",
    "BaseConnectorSettings",
    "BaseExternalImportConnectorConfig",
    "BaseInternalEnrichmentConnectorConfig",
    "BaseInternalExportFileConnectorConfig",
    "BaseInternalImportFileConnectorConfig",
    "BaseStreamConnectorConfig",
    "ConfigError",
    "ConfigValidationError",
    "DatetimeFromIsoString",
    "Deprecate",
    "DeprecatedField",
    "ListFromString",
    # states
    "ExternalImportConnectorState",
]
