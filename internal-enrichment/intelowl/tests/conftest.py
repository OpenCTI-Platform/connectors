import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

import copy  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402

# A finished IntelOwl job for an IP, shaped like IntelOwl's JobSerializer output
# (api_app/serializers/job.py): an aggregated `data_model` and one report per analyzer.
INTELOWL_JOB: dict[str, Any] = {
    "id": 42,
    "status": "reported_with_fails",
    "tlp": "AMBER",
    "observable_name": "198.51.100.7",
    "observable_classification": "ip",
    "playbook_requested": "FREE_TO_USE_ANALYZERS",
    "playbook_to_execute": "FREE_TO_USE_ANALYZERS",
    "data_model": {
        "evaluation": "malicious",
        "reliability": 8,
        "tags": ["tor_exit_node", "scanner"],
        "malware_family": "mirai",
        "kill_chain_phase": "c2",
        "external_references": [],
        "related_threats": [],
    },
    "analyzer_reports": [
        {
            "name": "TorProject",
            "status": "SUCCESS",
            "report": {"found": True},
            "errors": [],
            "data_model": {"evaluation": "malicious", "reliability": 7},
        },
        {
            "name": "FeodoTracker",
            "status": "SUCCESS",
            "report": {"found": False},
            "errors": [],
            "data_model": None,
        },
        {
            "name": "GreyNoiseCommunity",
            "status": "FAILED",
            "report": {},
            "errors": ["429 Too Many Requests"],
        },
    ],
    "warnings": [],
    "errors": [],
}


@pytest.fixture
def intelowl_job() -> dict[str, Any]:
    return copy.deepcopy(INTELOWL_JOB)


@pytest.fixture
def ipv4_stix_entity() -> dict[str, Any]:
    return {
        "type": "ipv4-addr",
        "id": "ipv4-addr--a9ad6e1f-6b6b-5b54-9c6f-6a1f8d1a1c2e",
        "spec_version": "2.1",
        "value": "198.51.100.7",
        "extensions": {},
    }
