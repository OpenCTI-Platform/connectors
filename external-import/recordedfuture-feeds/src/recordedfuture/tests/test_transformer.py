import json
import os

from recordedfuture.core.transformer import (
    C2STIXTransformer,
    DomainSTIXTransformer,
    EmergingMalwareSTIXTransformer,
    HashSTIXTransformer,
    IPSTIXTransformer,
    LowHashSTIXTransformer,
    RATSTIXTransformer,
    TorIPSTIXTransformer,
    URLSTIXTransformer,
    VulnerabilitySTIXTransformer,
)
from stix2 import (
    URL,
    DomainName,
    File,
    IPv4Address,
    IPv6Address,
    Malware,
    ObservedData,
    Relationship,
    Vulnerability,
)

DEFAULT_DAYS_THRESHOLD = 1
DEFAULT_DAYS_THRESHOLD_STR = "1"


def load_fixture(filename):
    """Load a fixture file and return its content."""
    filepath = os.path.join(os.path.dirname(__file__), "fixtures", filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Fixture {filename} not found.")
    with open(filepath, "r") as file:
        content = file.read()
        if not content.strip():
            raise ValueError(f"Fixture {filename} is empty.")
        return json.loads(content)


def test_c2stix_detect_transform_to_stix():
    c2_ips_detect = load_fixture("C2_IPS_DETECT.json")
    transformer = C2STIXTransformer()
    transformer.filter_data_by_days_ago(c2_ips_detect["results"])
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # Basic checks
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(
                item,
                (
                    Malware,
                    Relationship,
                    IPv4Address,
                    IPv6Address,
                    ObservedData,
                ),
            )
            for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        c2_ips_detect["results"], days_ago=DEFAULT_DAYS_THRESHOLD_STR
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        assert result == []


def test_c2stix_prevent_transform_to_stix():
    c2_ips_prevent = load_fixture("C2_IPS_PREVENT.json")
    transformer = C2STIXTransformer()
    transformer.filter_data_by_days_ago(c2_ips_prevent["results"])
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # Basic checks
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(
                item,
                (
                    Malware,
                    Relationship,
                    IPv4Address,
                    IPv6Address,
                    ObservedData,
                ),
            )
            for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        c2_ips_prevent["results"], days_ago=DEFAULT_DAYS_THRESHOLD
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(data_entry=indicator)
        assert result == []


def test_ddnsips_tranform_to_stix():
    ddns_ips = load_fixture("DDNS_IPS.json")
    transformer = IPSTIXTransformer()
    transformer.filter_data_by_days_ago(ddns_ips)
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(item, (Relationship, IPv4Address, IPv6Address, ObservedData))
            for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(ddns_ips, days_ago=DEFAULT_DAYS_THRESHOLD_STR)
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix()
        assert result == []


def test_ffluxips_tranform_to_stix():
    fflux_ips = load_fixture("FFLUX_IPS.json")
    transformer = IPSTIXTransformer()
    transformer.filter_data_by_days_ago(fflux_ips)
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(item, (Relationship, IPv4Address, IPv6Address, ObservedData))
            for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(fflux_ips, days_ago=DEFAULT_DAYS_THRESHOLD_STR)
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix()
        assert result == []


def test_domains_detect_tranform_to_stix():
    domains_detect = load_fixture("DOMAINS_DETECT.json")
    transformer = DomainSTIXTransformer()
    transformer.filter_data_by_days_ago(domains_detect["results"])

    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(item, (Relationship, ObservedData, DomainName))
            for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        domains_detect["results"], days_ago=DEFAULT_DAYS_THRESHOLD
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(
            data_entry=indicator, days_threshold=DEFAULT_DAYS_THRESHOLD
        )
        assert result == []


def test_domains_prevent_tranform_to_stix():
    domains_prevent = load_fixture("DOMAINS_PREVENT.json")
    transformer = DomainSTIXTransformer()
    transformer.filter_data_by_days_ago(domains_prevent["results"])
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(item, (Relationship, ObservedData, DomainName))
            for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        domains_prevent["results"], days_ago=DEFAULT_DAYS_THRESHOLD
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(
            data_entry=indicator, days_threshold=DEFAULT_DAYS_THRESHOLD
        )
        assert result == []


def test_emerging_malware_tranform_to_stix():
    emerging_malware = load_fixture("EMERGING_MALWARE_HASHES.json")
    transformer = EmergingMalwareSTIXTransformer()
    transformer.filter_data_by_days_ago(emerging_malware)
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(item, (File, ObservedData, Relationship)) for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        emerging_malware, days_ago=DEFAULT_DAYS_THRESHOLD_STR
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix()
        assert result == []


def test_rat_controller_tranform_to_stix():
    rat_controller = load_fixture("RAT_CONTROLLERS_IPS.json")
    transformer = RATSTIXTransformer()
    transformer.filter_data_by_days_ago(rat_controller)
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1

        for item in result:
            if not isinstance(
                item,
                (
                    Malware,
                    Relationship,
                    ObservedData,
                    IPv4Address,
                    IPv6Address,
                    URL,
                ),
            ):
                print(f"Unexpected object type: {type(item)}, Value: {item}")

        assert all(
            isinstance(
                item,
                (
                    Malware,
                    Relationship,
                    ObservedData,
                    IPv4Address,
                    IPv6Address,
                    URL,
                ),
            )
            for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        rat_controller, days_ago=DEFAULT_DAYS_THRESHOLD_STR
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix()
        assert result == []


def test_urls_prevent_tranform_to_stix():
    urls_prevent = load_fixture("URLS_PREVENT.json")
    transformer = URLSTIXTransformer()
    transformer.filter_data_by_days_ago(urls_prevent["results"])
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(item, (URL, Relationship, ObservedData)) for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        urls_prevent["results"], days_ago=DEFAULT_DAYS_THRESHOLD
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(data_entry=indicator)
        assert result == []

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        urls_prevent["results"], days_ago=DEFAULT_DAYS_THRESHOLD_STR
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        assert result == []


def test_vulns_patch_tranform_to_stix():
    vulns_patch = load_fixture("VULNS_PATCH.json")
    transformer = VulnerabilitySTIXTransformer()
    transformer.filter_data_by_days_ago(vulns_patch["results"])
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(
                item,
                (Relationship, Vulnerability, Malware, ObservedData, File),
            )
            for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        vulns_patch["results"], days_ago=DEFAULT_DAYS_THRESHOLD_STR
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix()
        assert result == []


def test_hashes_prevent_tranform_to_stix():
    hashes_prevent = load_fixture("HASHES_PREVENT.json")
    transformer = HashSTIXTransformer()
    transformer.filter_data_by_days_ago(hashes_prevent["results"])
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1
        for item in result:
            if not isinstance(
                item, (Relationship, Vulnerability, Malware, ObservedData)
            ):
                print(f"Unexpected object type: {type(item)}, Value: {item}")
        assert all(
            isinstance(
                item,
                (Relationship, Vulnerability, Malware, ObservedData, File),
            )
            for item in result
        )
    # # Test days_threshold filter
    # transformer.filter_data_by_days_ago(hashes_prevent["results"], days_ago=DEFAULT_DAYS_THRESHOLD)
    # for indicator in transformer.filtered_data_set:
    #     result = transformer.transform_to_stix(data_entry=indicator)
    #     assert result == []


def test_tor_ips_tranform_to_stix():
    tor_ips = load_fixture("TOR_IPS.json")
    transformer = TorIPSTIXTransformer()
    transformer.filter_data_by_days_ago(tor_ips)
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        # # Basic checkss
        assert result
        assert len(result) >= 1
        assert all(
            isinstance(item, (IPv4Address, IPv6Address, ObservedData, Relationship))
            for item in result
        )

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(tor_ips, days_ago=DEFAULT_DAYS_THRESHOLD)
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(data_entry=indicator)
        assert result
        assert len(result) >= 1


def test_low_detect_malware_tranform_to_stix():
    low_detect_malware = load_fixture("LOW_DETECT_MALWARE_HASHES.json")
    transformer = LowHashSTIXTransformer()
    transformer.filter_data_by_days_ago(low_detect_malware)
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(indicator)
        if result != []:
            assert result
            assert len(result) == 2
            assert all(
                isinstance(item, (File, Relationship, ObservedData)) for item in result
            )
        else:
            assert result == []

    # Test days_threshold filter
    transformer.filter_data_by_days_ago(
        low_detect_malware, days_ago=DEFAULT_DAYS_THRESHOLD_STR
    )
    for indicator in transformer.filtered_data_set:
        result = transformer.transform_to_stix(data_entry=indicator)
        assert result == []
