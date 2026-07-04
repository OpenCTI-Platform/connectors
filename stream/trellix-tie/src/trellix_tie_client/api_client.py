"""OpenDXL client for setting Trellix TIE file reputations."""

from __future__ import annotations

import re
from typing import Optional

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel

# Map STIX hash algorithm names (as they appear in a STIX pattern) to TIE HashType.
_ALGO_MAP = {
    "MD5": HashType.MD5,
    "SHA-1": HashType.SHA1,
    "SHA1": HashType.SHA1,
    "SHA-256": HashType.SHA256,
    "SHA256": HashType.SHA256,
}

# Matches `file:hashes.'SHA-256' = '<hex>'` (quotes around the algo are optional).
_HASH_RE = re.compile(
    r"hashes\.['\"]?(?P<algo>[A-Za-z0-9\-]+)['\"]?\s*=\s*'(?P<value>[0-9A-Fa-f]+)'"
)


def extract_hashes(pattern: str) -> dict:
    """
    Extract a TIE-ready hash dict from a STIX file pattern.

    Returns a mapping of ``HashType`` -> hex digest for the MD5 / SHA-1 / SHA-256
    hashes found in the pattern (empty if none).
    """
    hashes: dict = {}
    for match in _HASH_RE.finditer(pattern or ""):
        hash_type = _ALGO_MAP.get(match.group("algo").upper())
        if hash_type is not None:
            hashes[hash_type] = match.group("value").lower()
    return hashes


class TrellixTieAPIError(Exception):
    """Custom exception for Trellix TIE / OpenDXL errors."""


class TrellixTieClient:
    """Thin client that publishes file reputations to Trellix TIE over OpenDXL."""

    def __init__(self, helper, dxl_config_path: str) -> None:
        """
        Store the OpenDXL configuration. The config file is loaded and the DXL
        connection established lazily on first use.

        :param helper: The OpenCTI connector helper (used for logging).
        :param dxl_config_path: Path to the ePO-provisioned dxlclient.config file.
        """
        self.helper = helper
        self.dxl_config_path = dxl_config_path
        self._client = None
        self._tie: Optional[TieClient] = None

    def _ensure_connected(self) -> None:
        if self._client is None:
            try:
                config = DxlClientConfig.create_dxl_config_from_file(
                    self.dxl_config_path
                )
            except Exception as err:
                raise TrellixTieAPIError(
                    f"Failed to load OpenDXL config from {self.dxl_config_path}: {err}"
                ) from err
            self._client = DxlClient(config)
        if not self._client.connected:
            try:
                self._client.connect()
            except Exception as err:
                raise TrellixTieAPIError(
                    f"Failed to connect to the DXL fabric: {err}"
                ) from err
        if self._tie is None:
            self._tie = TieClient(self._client)

    @staticmethod
    def _trust_level(name: str) -> int:
        return getattr(TrustLevel, name, TrustLevel.KNOWN_MALICIOUS)

    def set_file_reputation(
        self,
        trust_level_name: str,
        hashes: dict,
        filename: str = "",
        comment: str = "",
    ) -> None:
        """Set the TIE enterprise reputation for the given hashes."""
        if not hashes:
            return
        self._ensure_connected()
        try:
            self._tie.set_file_reputation(
                self._trust_level(trust_level_name),
                hashes,
                filename=filename,
                comment=comment,
            )
        except Exception as err:
            raise TrellixTieAPIError(
                f"Failed to set TIE file reputation: {err}"
            ) from err

    def close(self) -> None:
        """Disconnect from the DXL fabric."""
        try:
            if self._client is not None and self._client.connected:
                self._client.disconnect()
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass
