"""The User-Agent sent on every request this connector makes to PolySwarm.

One stable value per connector, versioned with the OpenCTI release it ships
in (the pycti version), so PolySwarm can tell this connector's traffic apart
from other clients and from the ``python-requests`` default.
"""

from pycti import __version__ as _pycti_version

USER_AGENT = f"PolySwarm-OpenCTI-Feed/{_pycti_version} (OpenCTI)"


def with_user_agent(headers: dict[str, str]) -> dict[str, str]:
    """Return ``headers`` with the connector's User-Agent added."""
    return {**headers, "User-Agent": USER_AGENT}
