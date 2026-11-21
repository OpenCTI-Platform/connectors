from connector.converter_to_stix import ConverterToStix
from connector.misp_client import MispMatch

ENTITY_ID = "ipv4-addr--cb7f3d1e-1a2b-5c3d-9e4f-0a1b2c3d4e5f"
MARKING = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def _match(comment: str = "Seen in phishing campaign") -> MispMatch:
    return MispMatch(
        event={
            "id": "42",
            "info": "Emotet campaign",
            "date": "2026-03-01",
            "threat_level_id": "1",
            "Tag": [{"name": "tlp:green"}, {"name": "malware:emotet"}],
            "Attribute": [
                {
                    "category": "External analysis",
                    "type": "comment",
                    "value": "Analyst view",
                },
                {"category": "Network activity", "type": "ip-dst", "value": "1.2.3.4"},
            ],
            "Object": [
                {
                    "Attribute": [
                        {
                            "category": "External analysis",
                            "type": "comment",
                            "value": "Object comment",
                        }
                    ]
                }
            ],
        },
        attributes=[
            {
                "id": "1001",
                "category": "Network activity",
                "type": "ip-dst",
                "value": "1.2.3.4",
                "first_seen": None,
                "last_seen": "2026-03-02T00:00:00+00:00",
                "to_ids": True,
                "object_id": "0",
                "comment": comment,
                "Tag": [{"name": "kill-chain:c2"}],
            }
        ],
    )


def test_enrich_entity_merges_external_references_and_labels():
    converter = ConverterToStix("https://misp.example.com/")
    entity = {
        "id": ENTITY_ID,
        "type": "ipv4-addr",
        "value": "1.2.3.4",
        "labels": ["existing"],
        "external_references": [
            {
                "source_name": "MISP Event #42",
                "url": "https://misp.example.com/events/view/42",
            }
        ],
    }
    other_match = MispMatch(event={"id": "43", "info": "Other"})

    enriched = converter.enrich_entity(
        entity, [_match(), other_match], ["existing", "new"]
    )

    assert enriched["labels"] == ["existing", "new"]
    assert enriched["external_references"] == [
        {
            "source_name": "MISP Event #42",
            "url": "https://misp.example.com/events/view/42",
        },
        {
            "source_name": "MISP Event #43",
            "url": "https://misp.example.com/events/view/43",
            "description": "Other",
        },
    ]
    assert "labels" in entity and entity["labels"] == ["existing"]


def test_create_note():
    converter = ConverterToStix("https://misp.example.com")

    note = converter.create_note(_match(), ["1.2.3.4"], ENTITY_ID, [MARKING])

    assert note.abstract == 'MISP match: 1.2.3.4 in "Emotet campaign"'
    assert note.object_refs == [ENTITY_ID]
    assert note.object_marking_refs == [MARKING]
    assert note.created_by_ref == converter.author["id"]
    assert note.created.isoformat().startswith("2026-03-01")
    assert note.content == "\n".join(
        [
            "#### Attribute #1001\n",
            "- **Category**: Network activity",
            "- **Type**: ip-dst",
            "- **Value**: `1.2.3.4`",
            "- **First Seen**: N/A",
            "- **Last Seen**: 2026-03-02T00:00:00+00:00",
            "- **To IDS**: Yes",
            "- **Comment**: Seen in phishing campaign",
            "- **Tags**: kill-chain:c2",
            "",
            "### Event: Emotet campaign\n",
            "- **Threat level**: High",
            "- **Tags**: tlp:green, malware:emotet",
            "- **URL**: [https://misp.example.com/events/view/42](https://misp.example.com/events/view/42)",
            "- **Analysis comments**:",
            "  - Analyst view",
            "  - Object comment",
        ]
    )


def test_note_id_is_deterministic():
    converter = ConverterToStix("https://misp.example.com")

    first = converter.create_note(_match(), ["1.2.3.4"], ENTITY_ID, [])
    second = converter.create_note(_match(), ["1.2.3.4"], ENTITY_ID, [])

    assert first.id == second.id


def test_comment_regex_keeps_matching_comment():
    converter = ConverterToStix("https://misp.example.com", "(?i)phishing")

    note = converter.create_note(_match(), ["1.2.3.4"], ENTITY_ID, [])

    assert "- **Comment**: Seen in phishing campaign" in note.content


def test_comment_regex_drops_only_the_comment_line():
    converter = ConverterToStix("https://misp.example.com", "^SOC:")

    note = converter.create_note(_match(), ["1.2.3.4"], ENTITY_ID, [])

    assert "**Comment**" not in note.content
    assert "- **Tags**: kill-chain:c2" in note.content
    assert "  - Analyst view" in note.content


def test_create_report():
    converter = ConverterToStix("https://misp.example.com")

    report = converter.create_report(_match(), ENTITY_ID, [MARKING])

    assert report.name == "Emotet campaign"
    assert report.object_refs == [ENTITY_ID]
    assert report.labels == ["tlp:green", "malware:emotet"]
    assert report.published.isoformat().startswith("2026-03-01")
    assert (
        report.external_references[0].url == "https://misp.example.com/events/view/42"
    )
    assert report.id == converter.create_report(_match(), ENTITY_ID, []).id
