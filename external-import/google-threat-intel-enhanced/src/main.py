"""Config Loader for the OCTI composer catalog."""

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.octi.configs.connector_settings import _ConnectorFrameworkConfig
from connectors_sdk.settings.base_settings import _OpenCTIConfig
from pydantic import BaseModel


class ConfigLoader(BaseModel):
    """Aggregator of all the pydantic models used in the GTI configuration for the OCTI composer catalog."""

    connector: _ConnectorFrameworkConfig
    opencti: _OpenCTIConfig
    gti: GTIConfig
