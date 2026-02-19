from feedly.opencti_connector.connector import FeedlyConnector

IPV4_ID = "ipv4-addr--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"


def _make_bundle(objects):
    return {"type": "bundle", "id": "bundle--test", "objects": objects}


class TestFixIpAddressesWithPorts:
    def test_ipv4_with_port_strips_port_and_creates_network_traffic(self):
        ip_obj = {
            "type": "ipv4-addr",
            "id": IPV4_ID,
            "value": "1.2.3.4:8080",
        }
        bundle = _make_bundle([ip_obj])

        FeedlyConnector._fix_ip_addresses_with_ports(bundle)

        assert ip_obj["value"] == "1.2.3.4"
        network_traffics = [
            o for o in bundle["objects"] if o["type"] == "network-traffic"
        ]
        assert len(network_traffics) == 1
        nt = network_traffics[0]
        assert nt["dst_ref"] == IPV4_ID
        assert nt["dst_port"] == 8080
        assert nt["protocols"] == ["tcp"]
        assert nt["id"].startswith("network-traffic--")

    def test_plain_ipv4_without_port_is_unchanged(self):
        ip_obj = {
            "type": "ipv4-addr",
            "id": IPV4_ID,
            "value": "1.2.3.4",
        }
        bundle = _make_bundle([ip_obj])

        FeedlyConnector._fix_ip_addresses_with_ports(bundle)

        assert ip_obj["value"] == "1.2.3.4"
        network_traffics = [
            o for o in bundle["objects"] if o["type"] == "network-traffic"
        ]
        assert len(network_traffics) == 0
