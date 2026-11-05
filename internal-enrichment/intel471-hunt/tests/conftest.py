import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def response_payload() -> dict:
    with (FIXTURES / "response.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def first_hunt(response_payload) -> dict:
    return response_payload["results"][0]
