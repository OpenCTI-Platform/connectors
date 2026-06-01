"""
Single import point for polyswarm-api with connector-branded user agent.

Import PolyswarmAPI from here instead of polyswarm_api.api directly.
The UA patch runs once at import time before any session is created.
"""

import platform

import polyswarm_api
from polyswarm_api import settings

settings.DEFAULT_USER_AGENT = (
    f"opencti-polyswarm-connector/{polyswarm_api.__version__}"
    f" ({platform.machine()}-{platform.system()}"
    f"-{platform.python_implementation()}-{platform.python_version()})"
)

from polyswarm_api.api import PolyswarmAPI  # noqa: E402

__all__ = ["PolyswarmAPI"]
