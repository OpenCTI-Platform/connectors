"""OpenCTI AlienVault connector module."""

from alienvault.core import AlienVault

__all__ = ["AlienVault"]

connector = AlienVault()
connector.run()
