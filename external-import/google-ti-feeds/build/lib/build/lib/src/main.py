"""Config Loader for the OCTI composer catalog."""

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.octi.configs.connector_config import ConnectorConfig
from connector.src.octi.configs.octi_config import OctiConfig
from pydantic import BaseModel


class ConfigLoader(BaseModel):
    """Aggregator of all the pydantic models used in the GTI configuration for the OCTI composer catalog."""

    connector: ConnectorConfig
    opencti: OctiConfig
    gti: GTIConfig
