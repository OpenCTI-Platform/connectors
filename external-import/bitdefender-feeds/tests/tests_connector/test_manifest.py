"""Repository metadata checks (no OpenCTI runtime required)."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def test_manifest_valid_and_has_required_keys():
    path = ROOT / "__metadata__" / "connector_manifest.json"
    manifest = json.loads(path.read_text(), object_pairs_hook=_without_duplicate_keys)
    required = {
        "contact",
        "license_type",
        "verified",
        "last_verified_date",
        "playbook_supported",
        "max_confidence_level",
        "source_code",
        "manager_supported",
        "container_image",
        "logo",
        "support_version",
    }
    assert required <= manifest.keys()
    assert manifest["container_image"] == "opencti/connector-bitdefender-feeds"
    assert manifest["logo"] == "external-import/bitdefender-feeds/__metadata__/logo.png"
    assert (ROOT / "__metadata__" / "logo.png").is_file()
    assert isinstance(manifest["verified"], bool)
    assert isinstance(manifest["playbook_supported"], bool)
    assert isinstance(manifest["manager_supported"], bool)
