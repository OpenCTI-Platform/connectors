import pytest

data = [
    (
        """[artifact:mime_type = 'application/vnd.tcpdump.pcap' AND artifact:payload_bin MATCHES '\\\\xd4\\\\xc3\\\\xb2\\\\xa1\\\\x02\\\\x00\\\\x04\\\\x00' AND artifact:hashes.'SHA-256' = 'cead3f77f6cda6ec00f57d76c9a6879f' OR artifact:hashes.'SHA-256' = 'abcde3f77f6cda6ec00f57d76c9a6879f']""",
        {
            "type": "artifact",
            "file": {
                "hash": {
                    "sha256": [
                        "cead3f77f6cda6ec00f57d76c9a6879f",
                        "abcde3f77f6cda6ec00f57d76c9a6879f",
                    ]
                },
                "mime_type": ["application/vnd.tcpdump.pcap"],
            },
        },
    ),
    (
        """[file:hashes.MD5 = 'e8d77d19e1c6f462f4a5bf6fbe673a3c'  OR file:hashes.'SHA-256' = 'f6dcd4a5590d8922332ed342c59fe67318153ddd' OR file:hashes.'SHA-1' = 'f6dcd4a5590d8922332ed342c59fe67318153ddd']""",
        {
            "type": "file",
            "file": {
                "hash": {
                    "md5": ["e8d77d19e1c6f462f4a5bf6fbe673a3c"],
                    "sha1": ["f6dcd4a5590d8922332ed342c59fe67318153ddd"],
                    "sha256": ["f6dcd4a5590d8922332ed342c59fe67318153ddd"],
                }
            },
        },
    ),
    (
        """[autonomous-system:name = 'Foo Bar' AND autonomous-system:number = 12345]""",
        {
            "type": "autonomous-system",
            "as": {"number": ["12345"], "organization": {"name": ["Foo Bar"]}},
        },
    ),
    (
        """[domain-name:value = 'www.5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1/32']""",
        {"type": "domain-name", "domain": ["www.5z8.info"], "ip": ["198.51.100.1/32"]},
    ),
    (
        """[email-addr:value = 'jdoe@example.com' AND email-addr:display_name = 'Not J Doe']""",
        {
            "type": "email-addr",
            "email": {"address": ["jdoe@example.com"], "display_name": ["Not J Doe"]},
        },
    ),
    (
        """[ipv4-addr:value = '10.2.4.5/32' AND ipv4-addr:resolves_to_refs[*].value = 'd2:fb:49:24:37:18' AND ipv4-addr:belongs_to_refs[*].value = '15169']""",
        {
            "type": "ipv4-addr",
            "ip": ["10.2.4.5/32"],
            "mac": ["d2:fb:49:24:37:18"],
            "as": {"number": ["15169"]},
        },
    ),
    (
        """[ipv6-addr:value = '2001:0db8::/96' AND ipv6-addr:resolves_to_refs[*].value = 'd2:fb:49:24:37:18' AND ipv6-addr:belongs_to_refs[*].value = '15169']""",
        {
            "type": "ipv6-addr",
            "ip": ["2001:0db8::/96"],
            "mac": ["d2:fb:49:24:37:18"],
            "as": {"number": ["15169"]},
        },
    ),
    (
        """[mac-addr:value = 'd2:fb:49:24:37:18']""",
        {"type": "mac-addr", "mac": ["d2:fb:49:24:37:18"]},
    ),
    (
        """[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32'] """,
        {"type": "network-traffic", "destination": {"ip": ["203.0.113.33/32"]}},
    ),
    (
        """[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '192.168.100.5/24' AND network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32'] """,
        {
            "type": "network-traffic",
            "source": {"ip": ["192.168.100.0/24"]},
            "destination": {"ip": ["203.0.113.33/32"]},
        },
    ),
    (
        """[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '192.168.100.5' AND network-traffic:protocols = 'ipv4,tcp,dns']""",
        {
            "type": "network-traffic",
            "source": {"ip": ["192.168.100.5"]},
            "network": {"transport": ["tcp"], "protocol": ["dns"], "type": ["ipv4"]},
        },
    ),
    (
        """[process:command_line MATCHES '-add GlobalSign.cer -c -s -r localMachine Root'] FOLLOWEDBY [process:command_line MATCHES'-add GlobalSign.cer -c -s -r localMachineTrustedPublisher'] WITHIN 300 SECONDS""",
        {
            "type": "process",
            "process": {
                "command_line": [
                    "-add GlobalSign.cer -c -s -r localMachine Root",
                    "-add GlobalSign.cer -c -s -r localMachineTrustedPublisher",
                ]
            },
        },
    ),
    (
        """[x-opencti-hostname:value = 'jon-steak.duckdns.org']""",
        {"type": "domain-name", "domain": ["jon-steak.duckdns.org"]},
    ),
]


@pytest.mark.parametrize("pattern,expected", data)
def test_stix2ecs(pattern, expected) -> None:
    from elastic_threatintel.stix2ecs import StixIndicator

    item: StixIndicator = StixIndicator.parse_pattern(pattern)[0]
    result = item.get_ecs_indicator()

    assert result == expected
