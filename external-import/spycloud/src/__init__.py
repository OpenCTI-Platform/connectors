"""Expose `ConnectorSettings` to the OpenCTI connector config schema generator.

The generator imports the connector settings with `from src import ConnectorSettings`.
This connector ships its code as the `spycloud_connector` package instead of a
`src` package, hence this thin re-export module.
"""

from spycloud_connector.settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
