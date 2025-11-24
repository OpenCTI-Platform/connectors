import json
from typing import Any

from main import ReversingLabsSpectraAnalyzeConnector


def find_dict_by_key_value(dicts: list[dict], key: str, value: Any) -> dict | None:
    for d in dicts:
        if isinstance(d, dict) and key in d and d[key] == value:
            return d
    return None


def filter_by_key_value(items: list[dict], key: str, value: Any) -> list[dict]:
    return [item for item in items if item.get(key) == value]


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


def test_should_enrich_url(
    url_enrichment_message,
    network_url_report_response,
    submit_url_for_analysis_response,
    check_submitted_url_status_response,
    get_classification_v3_response,
):
    connector = ReversingLabsSpectraAnalyzeConnector()

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)
        return sent_bundle["objects"]

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector._process_message(url_enrichment_message)

    malwares = filter_by_key_value(sent_bundle["objects"], "type", "malware")
    malware_names = [m["name"] for m in malwares]
    threat_names = [
        threat.threat_name.split(".")[2]
        for threat in network_url_report_response.analysis.top_threats
    ]
    threat_names.append(
        check_submitted_url_status_response.classification_result.split(".")[2]
    )
    assert set(malware_names) == set(threat_names)
