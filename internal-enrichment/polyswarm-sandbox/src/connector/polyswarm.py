"""
Single import point for polyswarm-api and the connector's User-Agent.

Import PolyswarmAPI and USER_AGENT from here instead of polyswarm_api directly.

The SDK binds its default User-Agent as a default argument of
``PolyswarmSession.__init__`` when ``polyswarm_api`` is imported, so patching
``polyswarm_api.settings.DEFAULT_USER_AGENT`` afterwards has no effect. Set the
header on each session instead with ``apply_user_agent``.
"""

import pycti
from polyswarm_api.api import PolyswarmAPI

USER_AGENT = f"PolySwarm-OpenCTI-Sandbox/{pycti.__version__} (OpenCTI)"


def apply_user_agent(session) -> None:
    """Set the connector User-Agent on a requests.Session (or PolyswarmSession)."""
    session.headers["User-Agent"] = USER_AGENT


__all__ = ["PolyswarmAPI", "USER_AGENT", "apply_user_agent"]
