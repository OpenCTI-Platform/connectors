"""
Single-source PolySwarm API import with the connector's User-Agent.

All project code should import PolyswarmAPI and polyswarm exceptions
from this module rather than from polyswarm_api directly, and every raw
HTTP call to PolySwarm should send ``polyswarm_headers()``.
"""

import pycti
from polyswarm_api import exceptions as polyswarm_exceptions
from polyswarm_api.api import PolyswarmAPI as _SdkPolyswarmAPI

# One stable User-Agent for every request this connector makes to PolySwarm.
# The version follows the OpenCTI release the connector is built for.
USER_AGENT = f"PolySwarm-OpenCTI-Enrichment/{pycti.__version__} (OpenCTI)"


class PolyswarmAPI(_SdkPolyswarmAPI):
    """PolySwarm SDK client that identifies itself with USER_AGENT.

    The SDK binds its default User-Agent when its session class is defined,
    so patching ``polyswarm_api.settings`` has no effect. The header is set
    on the session of every instance instead.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.set_user_agent(USER_AGENT)


def polyswarm_headers(extra: dict | None = None) -> dict:
    """Headers for a raw HTTP call to PolySwarm: USER_AGENT plus ``extra``."""
    headers = dict(extra or {})
    headers["User-Agent"] = USER_AGENT
    return headers


__all__ = ["USER_AGENT", "PolyswarmAPI", "polyswarm_exceptions", "polyswarm_headers"]
