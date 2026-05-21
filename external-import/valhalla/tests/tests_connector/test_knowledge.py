import json
from unittest.mock import MagicMock

from stix2 import TLP_AMBER
from valhalla.knowledge import KnowledgeImporter


def _build_importer(valhalla_client):
    helper = MagicMock()
    helper.metric = MagicMock()
    return KnowledgeImporter(
        helper=helper,
        default_marking=TLP_AMBER,
        valhalla_client=valhalla_client,
    )


def _minimal_rules_response(rules):
    return {
        "api_version": "1",
        "copyright": "Nextron",
        "customer": "test",
        "date": "2026-01-01 00:00:00",
        "legal_note": "-",
        "title": "Valhalla",
        "rules": rules,
    }


def _minimal_rule(name, content, rule_hash):
    return {
        "author": "Nextron",
        "content": content,
        "date": "2026-01-01 00:00:00",
        "description": "desc",
        "minimum_yara": "3.8",
        "name": name,
        "reference": "",
        "required_modules": [],
        "rule_hash": rule_hash,
        "score": 50,
        "tags": [],
    }


def test_process_yara_rules_should_skip_previously_imported_hashes_and_normalize_content():
    valhalla_client = MagicMock()
    valhalla_client.get_rules_json.return_value = _minimal_rules_response(
        [
            _minimal_rule(
                name="known-rule",
                content="rule known { condition: true }",
                rule_hash="known-hash",
            ),
            _minimal_rule(
                name="new-rule",
                content="\ufeffrule new_rule\r\n{\r\n condition:\r\n  true\r\n}\r\n",
                rule_hash="new-hash",
            ),
        ]
    )
    importer = _build_importer(valhalla_client)

    rule_hashes = importer.process_yara_rules(previous_rule_hashes={"known-hash"})

    assert rule_hashes == {"known-hash", "new-hash"}
    assert len(importer.bundle_objects) == 1
    indicator = importer.bundle_objects[0]
    assert indicator.name == "new-rule"
    assert indicator.pattern == "rule new_rule\n{\n condition:\n  true\n}"


def test_run_should_reset_bundle_objects_between_runs():
    valhalla_client = MagicMock()
    valhalla_client.get_rules_json.return_value = _minimal_rules_response(
        [_minimal_rule("rule-1", "rule rule_1 { condition: true }", "hash-1")]
    )
    importer = _build_importer(valhalla_client)
    importer._build_attack_group_mapping = MagicMock()

    first_state = importer.run(work_id=1, previous_rule_hashes=[])
    importer.run(
        work_id=2,
        previous_rule_hashes=first_state[importer._KNOWLEDGE_IMPORTER_RULE_HASHES],
    )

    first_bundle = json.loads(
        importer.helper.send_stix2_bundle.call_args_list[0].args[0]
    )
    second_bundle = json.loads(
        importer.helper.send_stix2_bundle.call_args_list[1].args[0]
    )

    assert len(first_bundle["objects"]) == 2
    assert len(second_bundle["objects"]) == 1
