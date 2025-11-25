import json
from typing import Any

from main import ReversingLabsSpectraAnalyzeConnector
from pycti import OpenCTIConnectorHelper
from settings import ConfigLoader


def find_dict_by_key_value(dicts: list[dict], key: str, value: Any) -> dict | None:
    for d in dicts:
        if isinstance(d, dict) and key in d and d[key] == value:
            return d
    return None


def filter_by_key_value(items: list[dict], key: str, value: Any) -> list[dict]:
    return [item for item in items if item.get(key) == value]


def test_should_run_connector():
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    ReversingLabsSpectraAnalyzeConnector(config=config, helper=helper)


def test_should_enrich_file(file_enrichment_message, detailed_report_response):
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    connector = ReversingLabsSpectraAnalyzeConnector(config=config, helper=helper)

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
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    connector = ReversingLabsSpectraAnalyzeConnector(config=config, helper=helper)

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
    assert set(threat_names).issubset(set(malware_names))


def test_should_enrich_ipv4(
    ipv4_enrichment_message,
    network_files_from_ip_aggregated_response,
    network_ip_addr_report_response,
    network_ip_to_domain_aggregated_response,
    network_domain_report_response,
    network_urls_from_ip_aggregated_response,
    network_url_report_response,
):
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    connector = ReversingLabsSpectraAnalyzeConnector(config=config, helper=helper)

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)
        return sent_bundle["objects"]

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector._process_message(ipv4_enrichment_message)

    indicators = filter_by_key_value(sent_bundle["objects"], "type", "indicator")
    indicator_names = [m["name"] for m in indicators]
    downloaded_file_hashes = [
        file.sha1 for file in network_files_from_ip_aggregated_response.downloaded_files
    ]
    downloaded_file_urls = [
        file.last_download_url
        for file in network_files_from_ip_aggregated_response.downloaded_files
    ]
    network_domain_report_url = network_domain_report_response.requested_domain
    network_url_report_url = network_url_report_response.requested_url

    assert set(indicator_names) == set(
        downloaded_file_hashes
        + downloaded_file_urls
        + [network_domain_report_url, network_url_report_url]
    )


def test_should_enrich_domain_name(
    domain_name_enrichment_message,
    network_domain_report_response,
):
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    connector = ReversingLabsSpectraAnalyzeConnector(config=config, helper=helper)

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)
        return sent_bundle["objects"]

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector._process_message(domain_name_enrichment_message)

    malwares = filter_by_key_value(sent_bundle["objects"], "type", "malware")
    malware_names = [m["name"] for m in malwares]
    threat_names = [
        threat.threat_name.split(".")[2]
        for threat in network_domain_report_response.top_threats
    ]
    assert set(threat_names).issubset(set(malware_names))
