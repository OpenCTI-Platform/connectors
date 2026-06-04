"""Unit tests for ``AttributeConverter.create_stix2_ip_address``.

Pins the IPv4 / IPv6 type-tagging contract added in this PR:

* Single-host IPv4 (``1.2.3.4``) → ``stix2.IPv4Address`` (regression
  guard — pre-PR behaviour also handled this correctly).
* CIDR-form IPv4 (``192.168.0.0/24``) → ``stix2.IPv4Address`` (THE bug
  this PR set out to fix — pre-PR these were silently routed to the
  IPv6 fallback because ``IPv4Address(value)`` raised on the ``/``).
* Single-host IPv6 (``::1``, ``2001:db8::1``) → ``stix2.IPv6Address``.
* CIDR-form IPv6 (``2001:db8::/32``) → ``stix2.IPv6Address``.
* ``1.2.3.4/24`` (host bits set) → ``stix2.IPv4Address``
  (``strict=False`` lets MISP's address-with-mask form through).
* Malformed-prefix (``1.2.3.4/999``) → ``stix2.IPv6Address`` fallback
  — the previous "validate only the address half" guard would have
  let this through as IPv4 with a structurally invalid ``value``.
* Extra-slash (``1.2.3.4/24/extra``) → ``stix2.IPv6Address`` fallback,
  same reasoning.
* Plain garbage (``"garbage"``, ``""``) → ``stix2.IPv6Address``
  fallback — preserves the connector's prior contract that
  anything that does not parse as IPv4 is type-tagged as IPv6 (the
  MISP source of truth gets to decide what is and is not a valid IP;
  the converter only chooses the STIX type).
"""

import pytest
import stix2
from connector.use_cases.common import ConverterConfig
from connector.use_cases.convert_attribute import AttributeConverter


@pytest.fixture
def attribute_converter() -> AttributeConverter:
    return AttributeConverter(
        config=ConverterConfig(external_reference_base_url="http://dummy")
    )


@pytest.mark.parametrize(
    "value",
    [
        # Single host IPv4 (regression guard for the pre-PR happy path).
        "1.2.3.4",
        "0.0.0.0",
        "255.255.255.255",
        # CIDR IPv4 — THE bug this PR sets out to fix. Pre-PR these
        # were silently routed to the IPv6 fallback because
        # ``IPv4Address(value)`` raised on the ``/``.
        "192.168.0.0/24",
        "10.0.0.0/8",
        # Host-bits-set CIDRs (MISP's address-with-mask form).
        # ``strict=False`` makes ``ip_network`` accept these.
        "1.2.3.4/24",
        "192.168.1.5/16",
    ],
)
def test_ipv4_values_return_ipv4_address(attribute_converter, value):
    result = attribute_converter.create_stix2_ip_address(
        value=value, markings=[], custom_properties={}
    )

    assert isinstance(result, stix2.IPv4Address)
    # ``value`` must round-trip verbatim — the connector intentionally
    # does NOT canonicalise the CIDR (1.2.3.4/24 stays as-is instead of
    # being rewritten to 1.2.3.0/24) because the MISP source of truth
    # is the authority on the address-with-mask presentation.
    assert result.value == value


@pytest.mark.parametrize(
    "value",
    [
        # Single host IPv6.
        "::1",
        "2001:db8::1",
        "fe80::1%eth0".split("%")[0],  # canonical form without zone id
        # CIDR IPv6.
        "2001:db8::/32",
        "::/0",
    ],
)
def test_ipv6_values_return_ipv6_address(attribute_converter, value):
    result = attribute_converter.create_stix2_ip_address(
        value=value, markings=[], custom_properties={}
    )

    assert isinstance(result, stix2.IPv6Address)
    assert result.value == value


@pytest.mark.parametrize(
    "value",
    [
        # Malformed prefix length — the pre-fix split-and-validate-half
        # guard let these through as IPv4 with a structurally invalid
        # ``value``. ``ip_network`` rejects them.
        "1.2.3.4/999",
        "1.2.3.4/-1",
        # Extra-slash garbage.
        "1.2.3.4/24/extra",
        # Truly invalid input — preserves the connector's prior
        # "everything that does not parse as IPv4 is type-tagged as
        # IPv6" contract so the bundle still gets an observable for
        # the operator to triage.
        "not-an-ip",
        "",
        "999.999.999.999",
    ],
)
def test_invalid_values_fall_back_to_ipv6(attribute_converter, value):
    """Malformed / unparseable values fall back to the IPv6 type tag.

    This is a deliberate compatibility decision — the connector's prior
    behaviour was to type-tag anything that was not a valid IPv4 as
    IPv6 (without re-validating that the value actually was IPv6),
    leaving the source-of-truth call to MISP. The fix narrows the
    "is IPv4" check (so CIDR ranges no longer trip into the fallback)
    but keeps the fallback branch as-is so the contract for genuinely
    invalid input is unchanged.
    """
    result = attribute_converter.create_stix2_ip_address(
        value=value, markings=[], custom_properties={}
    )

    assert isinstance(result, stix2.IPv6Address)
    assert result.value == value
