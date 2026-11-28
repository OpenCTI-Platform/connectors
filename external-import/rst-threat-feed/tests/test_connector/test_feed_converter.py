import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


def _load_feed_converter():
    """Import feed_converter without pulling in connectors-sdk via the package."""
    try:
        from connector.feed_converter import FeedType, feed_converter

        return FeedType, feed_converter
    except ModuleNotFoundError:
        pycti = types.ModuleType("pycti")

        class _Id:
            @staticmethod
            def generate_id(*args, **kwargs):
                parts = [str(arg) for arg in args]
                parts.extend(f"{key}={value}" for key, value in sorted(kwargs.items()))
                return "id-" + "|".join(parts)

        for name in (
            "AttackPattern",
            "Campaign",
            "Identity",
            "Indicator",
            "IntrusionSet",
            "Malware",
            "Tool",
            "Vulnerability",
        ):
            setattr(pycti, name, _Id)
        sys.modules["pycti"] = pycti

        module_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "connector"
            / "feed_converter.py"
        )
        spec = importlib.util.spec_from_file_location(
            "feed_converter_under_test", module_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.FeedType, module.feed_converter


FeedType, feed_converter = _load_feed_converter()

NOW = 1_700_000_000
IP = "141.98.197.31"
IPV4_PATTERN = f"[ipv4-addr:value = '{IP}']"


def _port_clause(port: int) -> str:
    return (
        f"[network-traffic:dst_ref.value = '{IP}' AND "
        f"network-traffic:dst_port = {port}]"
    )


def _write_feed(tmp_path: Path, record: dict) -> str:
    path = tmp_path / "feed.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    return str(path)


def _ip_record(ports) -> dict:
    return {
        "ip": {"v4": IP},
        "lseen": NOW,
        "fseen": NOW - 10,
        "collect": NOW,
        "threat": ["emotet"],
        "tags": {"str": ["c2"]},
        "description": "c2 server",
        "ports": ports,
        "score": {"total": 50, "src": 40},
        "src": {"report": "https://example.com/report"},
    }


def _convert(path: str, mode: str = "skip", feed_type: str = FeedType.IP):
    return feed_converter(
        path,
        feed_type,
        0,
        True,
        False,
        True,
        False,
        True,
        None,
        mode,
    )


def _by_type(iocs: dict) -> dict:
    return {ioc["observable_type"]: ioc for ioc in iocs.values()}


def test_skip_keeps_ipv4_indicator_when_ports_are_present(tmp_path: Path):
    path = _write_feed(tmp_path, _ip_record([5003]))

    iocs, _, mapping = _convert(path, "skip")

    assert list(_by_type(iocs)) == ["IPv4-Addr"]
    assert _by_type(iocs)["IPv4-Addr"]["pattern"] == IPV4_PATTERN
    assert _by_type(iocs)["IPv4-Addr"]["name"] == IP
    assert len(mapping) == 1


def test_default_mode_matches_skip(tmp_path: Path):
    path = _write_feed(tmp_path, _ip_record([5003]))

    iocs, _, _ = feed_converter(path, FeedType.IP, 0, True, False)

    assert list(_by_type(iocs)) == ["IPv4-Addr"]


def test_add_creates_ip_and_network_traffic_indicators(tmp_path: Path):
    path = _write_feed(tmp_path, _ip_record([5003]))

    iocs, threats, mapping = _convert(path, "add")
    by_type = _by_type(iocs)

    assert set(by_type) == {"IPv4-Addr", "Network-Traffic"}
    assert by_type["IPv4-Addr"]["pattern"] == IPV4_PATTERN
    assert by_type["Network-Traffic"]["pattern"] == _port_clause(5003)
    assert by_type["Network-Traffic"]["name"] == f"{IP}:5003"
    assert "Ports:" in by_type["Network-Traffic"]["descr"]
    assert len(threats) == 1
    assert len(mapping) == 2
    assert {entry[0] for entry in mapping} == set(iocs)


def test_replace_creates_only_the_network_traffic_indicator(tmp_path: Path):
    path = _write_feed(tmp_path, _ip_record(["5003"]))

    iocs, _, mapping = _convert(path, "replace")
    by_type = _by_type(iocs)

    assert list(by_type) == ["Network-Traffic"]
    assert by_type["Network-Traffic"]["pattern"] == _port_clause(5003)
    assert len(mapping) == 1


def test_multiple_ports_are_or_ed_in_one_pattern(tmp_path: Path):
    path = _write_feed(tmp_path, _ip_record([5003, 80, 5003, -1]))

    iocs, _, _ = _convert(path, "replace")
    pattern = _by_type(iocs)["Network-Traffic"]["pattern"]

    assert pattern == f"{_port_clause(80)} OR {_port_clause(5003)}"
    assert _by_type(iocs)["Network-Traffic"]["name"] == f"{IP}:80,5003"


def test_long_port_lists_are_split_across_patterns(tmp_path: Path):
    ports = list(range(1, 42))
    path = _write_feed(tmp_path, _ip_record(ports))

    iocs, _, _ = _convert(path, "replace")
    network = [
        ioc for ioc in iocs.values() if ioc["observable_type"] == "Network-Traffic"
    ]

    assert len(network) == 2
    assert network[0]["pattern"].count(" OR ") == 39
    assert network[1]["pattern"] == _port_clause(41)


def test_replace_without_ports_keeps_the_ipv4_indicator(tmp_path: Path):
    path = _write_feed(tmp_path, _ip_record([-1]))

    iocs, _, _ = _convert(path, "replace")

    assert list(_by_type(iocs)) == ["IPv4-Addr"]
    assert _by_type(iocs)["IPv4-Addr"]["pattern"] == IPV4_PATTERN


def test_add_without_ports_does_not_create_network_traffic(tmp_path: Path):
    path = _write_feed(tmp_path, _ip_record([]))

    iocs, _, _ = _convert(path, "add")

    assert list(_by_type(iocs)) == ["IPv4-Addr"]


def test_network_traffic_mode_does_not_change_other_feeds(tmp_path: Path):
    record = {
        "domain": "evil.example",
        "lseen": NOW,
        "fseen": NOW - 10,
        "collect": NOW,
        "threat": [],
        "tags": {"str": []},
        "description": "domain",
        "score": {"total": 50, "src": 40},
        "src": {"report": "https://example.com/report"},
    }
    path = _write_feed(tmp_path, record)

    iocs, _, _ = _convert(path, "replace", FeedType.DOMAIN)

    assert list(_by_type(iocs)) == ["Domain-Name"]
    assert (
        _by_type(iocs)["Domain-Name"]["pattern"]
        == "[domain-name:value = 'evil.example']"
    )


def test_unknown_mode_is_treated_as_skip(tmp_path: Path):
    path = _write_feed(tmp_path, _ip_record([5003]))

    iocs, _, _ = _convert(path, "both")

    assert list(_by_type(iocs)) == ["IPv4-Addr"]


def _base_meta(**overrides) -> dict:
    record = {
        "lseen": NOW,
        "fseen": NOW - 10,
        "collect": NOW,
        "threat": ["emotet"],
        "tags": {"str": ["c2"]},
        "description": "indicator",
        "score": {"total": 50, "src": 40},
        "src": {"report": "https://example.com/report"},
    }
    record.update(overrides)
    return record


def test_url_feed_creates_url_indicator(tmp_path: Path):
    path = _write_feed(
        tmp_path,
        _base_meta(url="https://evil.example/path?q='1", threat=["emotet"]),
    )

    iocs, _, _ = _convert(path, feed_type=FeedType.URL)
    by_type = _by_type(iocs)

    assert list(by_type) == ["Url"]
    assert by_type["Url"]["pattern"] == "[url:value = 'https://evil.example/path?q=%271']"
    assert by_type["Url"]["name"] == "https://evil.example/path?q=%271"


def test_hash_feed_creates_stixfile_indicator(tmp_path: Path):
    md5 = "a" * 32
    sha1 = "b" * 40
    sha256 = "c" * 64
    path = _write_feed(
        tmp_path,
        _base_meta(md5=md5, sha1=sha1, sha256=sha256, threat=["emotet"]),
    )

    iocs, _, _ = _convert(path, feed_type=FeedType.HASH)
    by_type = _by_type(iocs)

    assert list(by_type) == ["StixFile"]
    pattern = by_type["StixFile"]["pattern"]
    assert f"file:hashes.MD5 = '{md5}'" in pattern
    assert f"file:hashes.'SHA-1' = '{sha1}'" in pattern
    assert f"file:hashes.'SHA-256' = '{sha256}'" in pattern
    assert by_type["StixFile"]["name"] == sha256


def test_only_new_skips_stale_indicators(tmp_path: Path):
    path = _write_feed(
        tmp_path,
        _base_meta(
            domain="old.example",
            lseen=NOW - 100_000,
            collect=NOW,
            threat=["emotet"],
        ),
    )

    iocs, _, _ = feed_converter(
        path,
        FeedType.DOMAIN,
        min_score=0,
        only_new=True,
        attributed_only=False,
    )
    assert iocs == {}


def test_attributed_only_skips_unattributed(tmp_path: Path):
    path = _write_feed(
        tmp_path,
        _base_meta(domain="lonely.example", threat=[""]),
    )

    iocs, _, _ = feed_converter(
        path,
        FeedType.DOMAIN,
        min_score=0,
        only_new=False,
        attributed_only=True,
    )
    assert iocs == {}


def test_min_score_filters_low_scoring_indicators(tmp_path: Path):
    path = _write_feed(
        tmp_path,
        _base_meta(
            domain="low.example",
            threat=["emotet"],
            score={"total": 10, "src": 5},
        ),
    )

    iocs, _, _ = feed_converter(
        path,
        FeedType.DOMAIN,
        min_score=20,
        only_new=False,
        attributed_only=False,
    )
    assert iocs == {}


@pytest.mark.parametrize(
    ("threat_tag", "expected_type", "expected_name_fragment"),
    [
        ("apt29_group", "intrusion-set", "APT29"),
        ("spring_campaign", "campaign", "Spring"),
        ("cobalt_strike_tool", "tool", "Cobalt Strike"),
        ("living_off_land_technique", "attack-pattern", "Living Off Land"),
        ("lockbit_ransomware", "malware_ransomware", "Ransomware"),
        ("plugx_backdoor", "malware_backdoor", "Plugx"),
        ("nanocore_rat", "malware_rat", "RAT"),
        ("zero_day_exploit", "malware_exploit", "Zero Day"),
        ("xmrig_miner", "malware_miner", "Xmrig"),
        ("printnightmare_vuln", "vulnerability", "Printnightmare"),
        ("emotet", "malware", "Emotet"),
    ],
)
def test_threat_suffix_paths(
    tmp_path: Path, threat_tag, expected_type, expected_name_fragment
):
    path = _write_feed(
        tmp_path,
        _base_meta(domain="suffix.example", threat=[threat_tag]),
    )

    _, threats, mapping = feed_converter(
        path,
        FeedType.DOMAIN,
        min_score=0,
        only_new=False,
        attributed_only=False,
        keep_named_vulns=True,
        create_custom_ttps=True,
    )

    assert len(threats) == 1
    threat = next(iter(threats.values()))
    assert threat["type"] == expected_type
    assert expected_name_fragment in threat["name"]
    assert threat["aliases"] == [threat_tag]
    assert len(mapping) == 1


def test_named_vuln_skipped_when_keep_named_vulns_false(tmp_path: Path):
    path = _write_feed(
        tmp_path,
        _base_meta(domain="vuln.example", threat=["printnightmare_vuln"]),
    )

    _, threats, _ = feed_converter(
        path,
        FeedType.DOMAIN,
        min_score=0,
        only_new=False,
        attributed_only=False,
        keep_named_vulns=False,
        create_custom_ttps=True,
    )

    # Falls through to generic malware naming when named vulns are disabled.
    threat = next(iter(threats.values()))
    assert threat["type"] == "malware"


def test_cve_and_industry_create_extra_threats(tmp_path: Path):
    path = _write_feed(
        tmp_path,
        _base_meta(
            domain="enriched.example",
            threat=["emotet"],
            cve=["cve-2024-1234"],
            industry=["financial"],
        ),
    )

    iocs, threats, mapping = feed_converter(
        path,
        FeedType.DOMAIN,
        min_score=0,
        only_new=False,
        attributed_only=False,
    )

    assert len(iocs) == 1
    types = {threat["type"] for threat in threats.values()}
    assert "malware" in types
    assert "vulnerability" in types
    assert "sector" in types
    assert any(threat["name"] == "CVE-2024-1234" for threat in threats.values())
    assert any(threat["name"] == "Financial" for threat in threats.values())
    assert len(mapping) >= 3


def test_mitre_ttp_mapping_creates_attack_pattern(tmp_path: Path):
    path = _write_feed(
        tmp_path,
        _base_meta(domain="ttp.example", threat=["emotet"], ttp=["T1059"]),
    )

    _, threats, mapping = feed_converter(
        path,
        FeedType.DOMAIN,
        min_score=0,
        only_new=False,
        attributed_only=False,
        create_mitre_ttps=True,
        mitre_ttp_mapping={"T1059": "Command and Scripting Interpreter"},
    )

    ttp_threats = [
        threat
        for threat in threats.values()
        if threat.get("mitre_id") == "T1059"
    ]
    assert len(ttp_threats) == 1
    assert ttp_threats[0]["type"] == "attack-pattern"
    assert ttp_threats[0]["name"] == "Command and Scripting Interpreter"
    assert len(mapping) >= 2
