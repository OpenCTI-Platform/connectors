import json
from datetime import date

import pytest


def get_manifest() -> dict:
    with open("./manifest.json", "r", encoding="utf-8") as file:
        return json.load(file)


def test_manifest_should_be_valid():
    # Given a manifest
    manifest = get_manifest()

    # When checking fields
    # Then manifest should be valid
    assert isinstance(manifest["id"], str)
    assert isinstance(manifest["name"], str)
    assert isinstance(manifest["description"], str)
    assert isinstance(manifest["version"], str)
    assert isinstance(manifest["contracts"], list) and (
        all([isinstance(contract, dict) for contract in manifest["contracts"]])
    )


@pytest.mark.parametrize("contract", get_manifest()["contracts"])
def test_manifest_contracts_should_be_valid(contract: dict):
    # Given a manifest's contract
    # When checking the contract
    # Then it should be valid

    # Title is a str
    assert isinstance(contract["title"], str)
    # Slug is a str
    assert isinstance(contract["slug"], str)
    # Description is a str
    assert isinstance(contract["description"], str)
    # Short Description is a str
    assert isinstance(contract["short_description"], str)
    # Logo is a str (base64 encoded image)
    assert isinstance(contract["logo"], str) and contract["logo"].startswith(
        "data:image/"
    )
    # Use Cases is a list of str
    assert isinstance(contract["use_cases"], list) and all(
        isinstance(use_case, str) for use_case in contract["use_cases"]
    )
    # Verified is a bool
    assert isinstance(contract["verified"], bool)
    # Last Verified Date is an optional ISO date string
    assert (
        isinstance(contract["last_verified_date"], str)
        and date.fromisoformat(contract["last_verified_date"])
    ) or contract["last_verified_date"] is None
    # Playbook Supported is a bool
    assert isinstance(contract["playbook_supported"], bool)
    # Max Confidence Level is between 0 and 100
    assert isinstance(contract["max_confidence_level"], int) and (
        contract["max_confidence_level"] >= 0
        and contract["max_confidence_level"] <= 100
    )
    # Support Version is a str
    assert isinstance(contract["support_version"], str)
    # Subscription Link is an optional str
    assert (
        isinstance(contract["subscription_link"], str)
        or contract["subscription_link"] is None
    )
    # Source Code is a str
    assert isinstance(contract["source_code"], str) and (
        contract["source_code"].startswith(
            "https://github.com/OpenCTI-Platform/connectors/"
        )
    )
    # Manager Supported is a bool
    assert isinstance(contract["manager_supported"], bool)
    # Container Version is a str
    assert isinstance(contract["container_version"], str)
    # Container Image is a str
    assert isinstance(contract["container_image"], str) and contract[
        "container_image"
    ].startswith("opencti/connector-")
    # Container Type is a literal
    assert contract["container_type"] in [
        "EXTERNAL_IMPORT",
        "INTERNAL_ENRICHMENT",
        "INTERNAL_EXPORT_FILE",
        "INTERNAL_IMPORT_FILE",
        "STREAM",
    ]
    # Config schema is a dict
    assert (
        "config_schema" in contract
        and isinstance(contract["config_schema"], dict)
        or "config_schema" not in contract
    )
