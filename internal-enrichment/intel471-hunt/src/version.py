"""Connector version and the User-Agent derived from it.

Intel 471 integrations identify themselves to the Intel 471 APIs as
``Intel471-<Integration>/<version>`` so first-party traffic stays attributable
and version-traceable. The version is single-sourced from the installed package
metadata rather than hand-typed.
"""

from importlib.metadata import PackageNotFoundError, version

INTEGRATION_NAME = "Intel471-OpenCTI-Hunter"

try:
    __version__ = version("intel471-hunt-connector")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0.dev0"

USER_AGENT = f"{INTEGRATION_NAME}/{__version__}"
