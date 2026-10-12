"""OpenCTI -> Cloudflare Rules List stream connector (v2).

Pushes IPv4 threat-intelligence indicators from OpenCTI into a Cloudflare
Rules List, built on the modern OpenCTI ``connectors-sdk`` + Pydantic-settings
architecture (OpenCTI 7.x / pycti 7.x).
"""

from cloudflare_rules_list.connector import Connector
from cloudflare_rules_list.settings import ConnectorSettings

__all__ = ["Connector", "ConnectorSettings"]
