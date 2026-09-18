"""Expose `ConnectorSettings` to the OpenCTI connector config schema generator.

The generator imports the connector settings with `from src import ConnectorSettings`.
This connector ships its code as the `tenable_security_center` package instead of a
`src` package, hence this thin re-export module.
"""

from tenable_security_center.settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
