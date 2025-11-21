import json
from typing import Any

from main import ReversingLabsSpectraAnalyzeConnector


def find_dict_by_key_value(dicts: list[dict], key: str, value: Any) -> dict | None:
    for d in dicts:
        if isinstance(d, dict) and key in d and d[key] == value:
            return d
    return None


def test_should_run_connector():
    ReversingLabsSpectraAnalyzeConnector()


def test_should_enrich_file(file_enrichment_message, detailed_report_response):
    connector = ReversingLabsSpectraAnalyzeConnector()

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)
        return sent_bundle["objects"]

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector._process_message(file_enrichment_message)

    malware = find_dict_by_key_value(sent_bundle["objects"], "type", "malware")
    malware_name = detailed_report_response.classification_result.split(".")[2]

    assert malware_name == malware["name"]

    indicator = find_dict_by_key_value(sent_bundle["objects"], "type", "indicator")

    malware_group = detailed_report_response.classification_result.split(".")[1]

    assert malware_name in indicator["labels"]
    assert malware_group in indicator["labels"]
    assert detailed_report_response.classification in indicator["labels"]

    assert (
        indicator["pattern"]
        == "[file:hashes. 'SHA-256' = '" + detailed_report_response.sha256 + "']"
    )
    assert indicator["name"] in detailed_report_response.aliases
    assert (
        indicator["x_mitre_platforms"] in detailed_report_response.classification_result
    )
    assert indicator["x_opencti_score"] == detailed_report_response.riskscore * 10

    assert str(detailed_report_response.file_size) in indicator["description"]
    assert str(detailed_report_response.file_type) in indicator["description"]
    assert str(detailed_report_response.ticore.story) in indicator["description"]
