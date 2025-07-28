import os
from copy import deepcopy
from typing import Any, Generator
from unittest.mock import Mock, patch

import pytest


@pytest.fixture(name="config_dict")
def fixture_config_dict() -> dict[str, dict[str, Any]]:
    """Fixture to provide the expected configuration dictionary for OpenCTIConnectorHelper."""

    return {
        "opencti": {
            "json_logging": True,
            "ssl_verify": False,
            "token": "opencti-token",
            "url": "http://localhost:4242/",  # trailing slash in necessary for tests to pass
        },
        "connector": {
            "auto": False,
            "expose_metrics": False,
            "id": "connector-uuid",
            "log_level": "error",
            "metrics_port": 9095,
            "name": "Test connector",
            "only_contextual": False,
            "queue_protocol": "amqp",
            "queue_threshold": 500,
            "scope": "domain-name,url",
            "send_to_directory": False,
            "send_to_directory_path": None,
            "send_to_directory_retention": 7,
            "send_to_queue": True,
            "type": "INTERNAL_ENRICHMENT",
            "validate_before_import": False,
        },
        "recorded_future": {
            "token": "recorded-future-token",
            "create_indicator_threshold": 0,
            "info_max_tlp": "TLP:CLEAR",
            "vulnerability_enrichment_optional_fields": "",  # empty comma-separated list
        },
    }


@pytest.fixture(name="mocked_environ")
def fixture_mocked_environ(
    config_dict: dict[str, dict[str, Any]],
) -> Generator[Mock, None, None]:
    """Fixture to mock os.environ with necessary env vars. Cleaned between each test."""

    environ = deepcopy(os.environ)
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    with patch("os.environ", environ) as mocked_environ:
        yield mocked_environ  # yielding resets os.environ between each test
