import importlib.util
import json
import sys
import types
from pathlib import Path


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
