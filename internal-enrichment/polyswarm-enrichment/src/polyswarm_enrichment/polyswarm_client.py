"""
Single-source PolySwarm API import with project-wide user-agent patch.

All project code should import PolyswarmAPI and polyswarm exceptions
from this module rather than from polyswarm_api directly.
"""

import polyswarm_api.settings

# Patch user-agent to identify this connector to the PolySwarm API.
polyswarm_api.settings.DEFAULT_USER_AGENT = (
    polyswarm_api.settings.DEFAULT_USER_AGENT.replace(
        "polyswarm_api/", "opencti_polyswarm_api/"
    )
)

from polyswarm_api.api import PolyswarmAPI  # noqa: E402
from polyswarm_api import exceptions as polyswarm_exceptions  # noqa: E402

__all__ = ["PolyswarmAPI", "polyswarm_exceptions"]
