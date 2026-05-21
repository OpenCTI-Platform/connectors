import pytest
from lib.actor_typing import infer_actor_entity_type


@pytest.mark.parametrize(
    ("actor", "expected"),
    [
        ({"handle": "APT28"}, "Intrusion-Set"),
        ({"handle": "Lazarus Group"}, "Threat-Actor-Group"),
        ({"handle": "LockBit ransomware"}, "Malware"),
        ({"handle": "john_doe"}, "Threat-Actor-Individual"),
        ({"handle": "TA", "type": "threat-actor-group"}, "Threat-Actor-Group"),
        ({"handle": "TA", "entity_type": "intrusion-set"}, "Intrusion-Set"),
        ({"name": "APT29"}, "Intrusion-Set"),
        ({"uid": "Lazarus Group"}, "Threat-Actor-Group"),
        ({}, "Threat-Actor-Individual"),
    ],
)
def test_infer_actor_entity_type(actor, expected):
    assert infer_actor_entity_type(actor) == expected
