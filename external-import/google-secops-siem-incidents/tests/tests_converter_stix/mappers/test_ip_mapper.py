"""RED tests — IP address mapper.

Tests extraction of IPv4 / IPv6 observables from Chronicle alert outcomes.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

from connectors_sdk.models import IPV4Address, IPV6Address

# --- import under test (will cause ImportError → RED) ---
from google_secops_siem_incidents.mappers.ip_mapper import (  # noqa: E402
    map_ip_addresses,
)
from tests_converter_stix.factories import (
    make_author,
    make_ip_outcomes,
    make_multi_ip_outcomes,
    make_tlp_marking,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _when_map_ips(outcomes):
    return map_ip_addresses(
        outcomes,
        author=make_author(),
        tlp_marking=make_tlp_marking(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestIpMapper:
    def test_then_ipv4_addresses_extracted(self):
        """Given principal IPs ['10.0.0.1','192.168.1.5'] + SourceIsIpv6=false → 2 IPV4Address."""
        # _given_
        outcomes = make_ip_outcomes(["10.0.0.1", "192.168.1.5"], is_ipv6=False)

        # _when_
        result = _when_map_ips(outcomes)

        # _then_
        assert len(result) == 2
        assert all(isinstance(ip, IPV4Address) for ip in result)
        values = {ip.value for ip in result}
        assert values == {"10.0.0.1", "192.168.1.5"}

    def test_then_ipv6_addresses_extracted(self):
        """Given principal IPs ['2001:db8::1'] + SourceIsIpv6=true → 1 IPV6Address."""
        # _given_
        outcomes = make_ip_outcomes(["2001:db8::1"], is_ipv6=True)

        # _when_
        result = _when_map_ips(outcomes)

        # _then_
        assert len(result) == 1
        assert isinstance(result[0], IPV6Address)
        assert result[0].value == "2001:db8::1"

    def test_then_defaults_to_ipv4_when_flag_absent(self):
        """Trap guard: Given SourceIsIpv6 key absent → defaults to IPv4."""
        # _given_
        outcomes = make_ip_outcomes(["10.0.0.1"], is_ipv6=None)  # no flag

        # _when_
        result = _when_map_ips(outcomes)

        # _then_
        assert len(result) == 1
        assert isinstance(result[0], IPV4Address)

    def test_then_empty_ip_list_returns_empty(self):
        """Given empty IP list → returns []."""
        # _given_
        outcomes = make_ip_outcomes([])

        # _when_
        result = _when_map_ips(outcomes)

        # _then_
        assert result == []


class TestIpMapperMultiOutcome:
    def test_then_two_ip_outcomes_return_all_ips(self):
        """Given 2 principal_ip outcomes each with their own IPs → all IPs returned."""
        # _given_
        outcomes = make_multi_ip_outcomes(
            [["10.0.0.1", "10.0.0.2"], ["192.168.1.1"]],
            is_ipv6=False,
        )

        # _when_
        result = _when_map_ips(outcomes)

        # _then_
        assert len(result) == 3
        values = {ip.value for ip in result}
        assert values == {"10.0.0.1", "10.0.0.2", "192.168.1.1"}
        assert all(isinstance(ip, IPV4Address) for ip in result)

    def test_then_no_deduplication_across_outcomes(self):
        """Verify deduplication is NOT applied — same IP in two outcomes appears twice."""
        # _given_
        outcomes = make_multi_ip_outcomes(
            [["10.0.0.1"], ["10.0.0.1"]],
            is_ipv6=False,
        )

        # _when_
        result = _when_map_ips(outcomes)

        # _then_
        assert len(result) == 2
        assert all(ip.value == "10.0.0.1" for ip in result)

    def test_then_ipv6_flag_applies_to_all_outcomes(self):
        """Given 2 principal_ip outcomes + SourceIsIpv6=true → all returned as IPv6."""
        # _given_
        outcomes = make_multi_ip_outcomes(
            [["2001:db8::1"], ["2001:db8::2"]],
            is_ipv6=True,
        )

        # _when_
        result = _when_map_ips(outcomes)

        # _then_
        assert len(result) == 2
        assert all(isinstance(ip, IPV6Address) for ip in result)
