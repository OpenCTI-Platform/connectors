import os
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Dict

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from alienvault.models import Pulse


@pytest.fixture
def pulse_data() -> Dict[str, Any]:
    """OTX pulse payload with empty lists and no adversary."""
    return {
        "id": "pulse-1",
        "name": "Test pulse",
        "description": "A test pulse",
        "author_name": "AlienVault",
        "public": True,
        "revision": 1,
        "malware_families": [],
        "industries": [],
        "attack_ids": [],
        "tlp": "white",
        "tags": [],
        "created": datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "modified": datetime(2024, 1, 3, 3, 4, 5, tzinfo=timezone.utc),
        "references": [],
        "targeted_countries": [],
        "indicators": [],
    }


@pytest.fixture
def make_pulse(pulse_data: Dict[str, Any]) -> Callable[..., Pulse]:
    """Build a Pulse from the shared payload, with per-test overrides."""

    def _make_pulse(**overrides: Any) -> Pulse:
        return Pulse(**{**pulse_data, **overrides})

    return _make_pulse
