"""Persisted connector state for RST Threat Library.

Uses the connectors-sdk ``ExternalImportConnectorState`` contract so OpenCTI
stores checkpoints (cursors, managed IDs, fingerprints, split failures) between
runs. Extra keys (e.g. ``cursor_intrusion-sets``) are allowed for backward
compatibility with existing deployments.
"""

from __future__ import annotations

from typing import Any

from connectors_sdk import ExternalImportConnectorState
from pydantic import Field


class ConnectorState(ExternalImportConnectorState):
    """Checkpoints used to resume Threat Library imports and merge/split."""

    fingerprints: dict[str, Any] = Field(default_factory=dict)
    managed_ids: dict[str, Any] = Field(default_factory=dict)
    split_failures: dict[str, Any] = Field(default_factory=dict)

    def to_mutable_dict(self) -> dict[str, Any]:
        """JSON-serializable dict for legacy engine helpers that mutate state."""
        return self.to_json()

    def apply_mutable_dict(self, data: dict[str, Any]) -> None:
        """Copy mutated dict fields back onto this state instance."""
        for key, value in data.items():
            if key.startswith("_"):
                continue
            setattr(self, key, value)
