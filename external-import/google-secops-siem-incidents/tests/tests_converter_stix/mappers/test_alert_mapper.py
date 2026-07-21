"""Tests — Alert-field mapper.

Tests extraction of observables from alert field stringVal values.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

from google_secops_siem_incidents.mappers.alert_mapper import (
    map_alert_fields,
)
from tests_converter_stix.factories import (
    AlertFieldFactory,
    make_author,
    make_tlp_marking,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _when_map_alert_fields(fields):
    return map_alert_fields(
        fields,
        author=make_author(),
        tlp_marking=make_tlp_marking(),
    )


# ---------------------------------------------------------------------------
# Tests — Value-based classification
# ---------------------------------------------------------------------------
class TestAlertFieldMapperIPv4:
    def test_then_ipv4_extracted(self):
        """Given a field with an IPv4 stringVal → IPV4Address observable."""
        fields = [AlertFieldFactory.build(name="ip", string_val="10.0.0.1")]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].value == "10.0.0.1"

    def test_then_ipv6_extracted(self):
        """Given a field with an IPv6 stringVal → IPV6Address observable."""
        fields = [
            AlertFieldFactory.build(name="src_ip", string_val="::1"),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].value == "::1"


class TestAlertFieldMapperHostname:
    def test_then_hostname_with_dots_extracted(self):
        """Given a field with a FQDN → Hostname observable."""
        fields = [
            AlertFieldFactory.build(name="hostname", string_val="webserver.corp.local"),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].value == "webserver.corp.local"

    def test_then_short_hostname_classified_by_name(self):
        """Given a field named 'hostname' with short value → Hostname via name hint."""
        fields = [
            AlertFieldFactory.build(name="hostname", string_val="srv01"),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].value == "srv01"


class TestAlertFieldMapperEmail:
    def test_then_email_extracted(self):
        """Given a field with an email → EmailAddress observable."""
        fields = [
            AlertFieldFactory.build(name="email", string_val="alice@example.com"),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].value == "alice@example.com"


class TestAlertFieldMapperURL:
    def test_then_url_extracted(self):
        """Given a field with a URL → URL observable."""
        fields = [
            AlertFieldFactory.build(
                name="target_url", string_val="https://malware.example.com/payload"
            ),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].value == "https://malware.example.com/payload"


class TestAlertFieldMapperMAC:
    def test_then_mac_extracted(self):
        """Given a field with a MAC address → MACAddress observable."""
        fields = [
            AlertFieldFactory.build(name="mac", string_val="AA:BB:CC:DD:EE:FF"),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].value == "AA:BB:CC:DD:EE:FF"


class TestAlertFieldMapperUserAccount:
    def test_then_user_account_from_name_hint(self):
        """Given a field named 'user' with unclassifiable value → UserAccount."""
        fields = [
            AlertFieldFactory.build(name="user", string_val="alice"),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].user_id == "alice"
        assert result[0].account_login == "alice"


# ---------------------------------------------------------------------------
# Tests — Edge cases
# ---------------------------------------------------------------------------
class TestAlertFieldMapperEdgeCases:
    def test_then_empty_fields_returns_empty_list(self):
        """Given no fields → returns empty list."""
        result = _when_map_alert_fields([])
        assert result == []

    def test_then_field_without_string_val_skipped(self):
        """Given a field with no stringVal → skipped."""
        fields = [AlertFieldFactory.build(name="ip", string_val=None)]

        result = _when_map_alert_fields(fields)

        assert result == []

    def test_then_whitespace_only_string_val_skipped(self):
        """Given a field with whitespace-only stringVal → skipped."""
        fields = [AlertFieldFactory.build(name="ip", string_val="   ")]

        result = _when_map_alert_fields(fields)

        assert result == []

    def test_then_unclassifiable_value_skipped(self):
        """Given a field with unclassifiable value and unknown name → skipped."""
        fields = [
            AlertFieldFactory.build(name="unknown_field", string_val="random_text_123"),
        ]

        result = _when_map_alert_fields(fields)

        assert result == []

    def test_then_duplicates_are_deduplicated(self):
        """Given two fields with the same value → single observable."""
        fields = [
            AlertFieldFactory.build(name="src_ip", string_val="10.0.0.1"),
            AlertFieldFactory.build(name="dst_ip", string_val="10.0.0.1"),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].value == "10.0.0.1"


# ---------------------------------------------------------------------------
# Tests — Multiple fields
# ---------------------------------------------------------------------------
class TestAlertFieldMapperMultipleFields:
    def test_then_mixed_types_extracted(self):
        """Given fields with mixed types → correct observables for each."""
        fields = [
            AlertFieldFactory.build(name="ip", string_val="185.100.87.136"),
            AlertFieldFactory.build(name="hostname", string_val="srv01"),
            AlertFieldFactory.build(name="email", string_val="admin@corp.local"),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 3
        values = {getattr(r, "value", getattr(r, "user_id", None)) for r in result}
        assert "185.100.87.136" in values
        assert "srv01" in values
        assert "admin@corp.local" in values

    def test_then_values_are_stripped(self):
        """Given a field with leading/trailing whitespace → value is stripped."""
        fields = [
            AlertFieldFactory.build(name="ip", string_val="  10.0.0.1  "),
        ]

        result = _when_map_alert_fields(fields)

        assert len(result) == 1
        assert result[0].value == "10.0.0.1"
