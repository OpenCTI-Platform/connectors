import json
from unittest.mock import MagicMock

from rflib.threat_map import ThreatMap

SHA512_HASH = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)
UNSUPPORTED_HASH = "a" * 96

# ── Tests ─────────────────────────────────────────────────────────────────────


# Scenario: A malware linked to a SHA-512 hash is imported with its indicator (issue #7343)
def test_threat_map_imports_malware_linked_to_sha512_hash():
    # Given a malware threat map whose malware is linked to a SHA-512 hash
    threat_map = _given_threat_map([_given_malware_with_hash("Malware A", SHA512_HASH)])

    # When the threat maps are imported
    _when_threat_map_run(threat_map)

    # Then the malware bundle is sent with the SHA-512 file observable
    bundles = _sent_bundles(threat_map)
    assert len(bundles) == 1
    files = [obj for obj in bundles[0]["objects"] if obj["type"] == "file"]
    assert [file["hashes"] for file in files] == [{"SHA-512": SHA512_HASH}]
    # And the run completes
    threat_map.helper.api.work.to_processed.assert_called_once()


# Scenario: An unconvertible entity is skipped without aborting the run (issue #7343)
def test_threat_map_skips_unconvertible_entity_and_imports_the_others():
    # Given a malware threat map where the first malware is linked to a hash of
    # unsupported length and the second one to a supported hash
    threat_map = _given_threat_map(
        [
            _given_malware_with_hash("Malware A", UNSUPPORTED_HASH),
            _given_malware_with_hash("Malware B", SHA512_HASH),
        ]
    )

    # When the threat maps are imported
    _when_threat_map_run(threat_map)

    # Then only the second malware is sent
    bundles = _sent_bundles(threat_map)
    assert [_malware_names(bundle) for bundle in bundles] == [["Malware B"]]
    # And the skip is logged as a warning with its context
    warning_calls = threat_map.helper.connector_logger.warning.call_args_list
    assert len(warning_calls) == 1
    assert warning_calls[0].args == (
        "[THREAT MAPS] Skipping entity that could not be converted",
    )
    assert warning_calls[0].kwargs["meta"]["entity"] == "Malware A"
    assert warning_calls[0].kwargs["meta"]["threat_map"] == "malware"
    # And the run completes and saves its state
    threat_map.helper.api.work.to_processed.assert_called_once()
    threat_map.helper.set_state.assert_called_once()
    threat_map.helper.connector_logger.error.assert_not_called()


# ── Given helpers ────────────────────────────────────────────────────────────


def _given_threat_map(entities_with_links):
    helper = MagicMock()
    helper.get_state.return_value = {}
    rfapi = MagicMock()
    rfapi.get_threat_maps.return_value = [
        {"type": "malware", "url": "/threat/map/malware"}
    ]
    rfapi.get_entities_mapped.return_value = [
        {"id": entity["entity"]["id"]} for entity in entities_with_links
    ]
    rfapi.get_entities_links.return_value = entities_with_links
    return ThreatMap(helper, rfapi, "amber+strict", 60)


def _given_malware_with_hash(malware_name, file_hash):
    return {
        "entity": {
            "id": f"id-{malware_name}",
            "name": malware_name,
            "type": "type:Malware",
        },
        "links": [
            {
                "type": "type:Hash",
                "name": file_hash,
                "attributes": [{"id": "risk_score", "value": 90}],
            }
        ],
    }


# ── When helpers ─────────────────────────────────────────────────────────────


def _when_threat_map_run(threat_map):
    threat_map.run()


# ── Then helpers ─────────────────────────────────────────────────────────────


def _sent_bundles(threat_map):
    return [
        json.loads(call.args[0])
        for call in threat_map.helper.send_stix2_bundle.call_args_list
    ]


def _malware_names(bundle):
    return [obj["name"] for obj in bundle["objects"] if obj["type"] == "malware"]
