import json

import pytest

from tests._manifest_validators import (
    is_boolean,
    is_valid_container_image,
    is_valid_container_type,
    is_valid_date_str,
    is_valid_license_type,
    is_valid_max_confidence_level,
    is_valid_solution_categories,
    is_valid_source_code,
    is_valid_str,
    is_valid_use_cases,
)


def get_manifest() -> dict:
    with open("./manifest.json", "r", encoding="utf-8") as file:
        return json.load(file)


def test_manifest_is_valid():
    # Given a global manifest
    manifest = get_manifest()

    # When checking root fields
    # Then values should be valid
    assert isinstance(manifest["id"], str)
    assert isinstance(manifest["name"], str)
    assert isinstance(manifest["description"], str)
    assert isinstance(manifest["version"], str)
    assert isinstance(manifest["contracts"], list) and (
        all([isinstance(contract, dict) for contract in manifest["contracts"]])
    )


@pytest.mark.parametrize("contract", get_manifest()["contracts"])
def test_manifest_contracts_are_valid(contract: dict):
    """Assert each contract in the global manifest satisfies validity rules.

    Important: All fields are required in each contract object, except `config_schema`
    (not implemented in every connector yet). Some fields are nullable, which means
    the key is still required but the value may be `None`.

    Field validation rules:
    - title: string (required)
    - slug: string (required)
    - description: string (required)
    - short_description: string (required)
    - logo: string (base64-encoded image) (required)
    - use_cases: 1-3 items from allowed use cases (required)
    - solution_categories: 1-3 items from allowed solution categories (required)
    - contact: string or None (required key, nullable value)
    - license_type: one of allowed license types (required key, nullable value)
    - verified: bool (required)
    - last_verified_date: ISO-8601 string or None (required key, nullable value)
    - playbook_supported: bool (required)
    - max_confidence_level: integer between 0 and 100 (required)
    - subscription_link: string or None (required key, nullable value)
    - source_code: Github URL (required)
    - manager_supported: bool (required)
    - container_version: string (required)
    - container_image: string with correct prefix (required)
    - container_type: correct type of connector (required)
    - config_schema: optional key; if present, value must be a dict
    """

    # Given a manifest's contract
    # When checking the contract
    # Then it should be valid

    # Validate contract fields coming from connector_manifest.json files
    assert is_valid_str(contract["title"])
    assert is_valid_str(contract["slug"])
    assert is_valid_str(contract["description"])
    assert is_valid_str(contract["short_description"])
    assert is_valid_str(contract["logo"]) and contract["logo"].startswith("data:image/")
    assert is_valid_use_cases(contract["use_cases"])
    assert is_valid_solution_categories(contract["solution_categories"])
    assert is_valid_str(contract["contact"]) or contract["contact"] is None
    assert (
        is_valid_license_type(contract["license_type"])
        or contract["license_type"] is None
    )
    assert is_boolean(contract["verified"])
    assert (
        is_valid_date_str(contract["last_verified_date"])
        or contract["last_verified_date"] is None
    )
    assert is_boolean(contract["playbook_supported"])
    assert is_valid_max_confidence_level(contract["max_confidence_level"])
    assert is_valid_str(contract["support_version"])
    assert (
        is_valid_str(contract["subscription_link"])
        or contract["subscription_link"] is None
    )
    assert is_valid_source_code(contract["source_code"])
    assert is_boolean(contract["manager_supported"])
    assert is_valid_str(contract["container_version"])
    assert is_valid_container_image(contract["container_image"])
    assert is_valid_container_type(contract["container_type"])

    # Validate contract fields coming from connector_config_schema.json files
    if contract["manager_supported"]:
        # MUST be present for deployment in XTM Composer
        assert isinstance(contract["config_schema"], dict)
    else:
        # MAY be present (if using BaseConnectorSettings from connectors-sdk)
        assert "config_schema" not in contract or isinstance(
            contract["config_schema"], dict
        )
