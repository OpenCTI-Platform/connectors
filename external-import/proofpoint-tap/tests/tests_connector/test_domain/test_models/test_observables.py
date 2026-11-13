# pragma: no cover # do not include tests modules in coverage metrics
"""Test the observable models."""

import pytest
from proofpoint_tap.domain.models.octi.observables import EmailAddress


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("user@example.com", id="simple"),
        pytest.param("user@localhost", id="domain_without_dot"),
        pytest.param("user@mail.local", id="special_use_domain"),
        pytest.param("first.last+tag@sub.example.co", id="plus_and_subdomain"),
    ],
)
def test_email_address_accepts_addresses_accepted_by_opencti(value: str):
    """Test the email address accepts the values that OpenCTI accepts."""
    # When creating an email address
    email_address = EmailAddress(value=value, author=None)
    # Then the value is kept
    assert email_address.value == value  # noqa: S101


def test_email_address_lowers_the_domain_only():
    """Test the email address keeps the local part case and lowers the domain."""
    # When creating an email address with upper case letters
    email_address = EmailAddress(value="John.Doe@Example.COM", author=None)
    # Then only the domain is lowered
    assert email_address.value == "John.Doe@example.com"  # noqa: S101


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("", id="empty"),
        pytest.param("   ", id="whitespace"),
        pytest.param("not-an-email", id="missing_at"),
        pytest.param("user@[mail.example.com]", id="bracketed_domain"),
        pytest.param('"John Doe"@example.com', id="quoted_local_part"),
        pytest.param("user@example.com\n", id="trailing_new_line"),
    ],
)
def test_email_address_rejects_addresses_rejected_by_opencti(value: str):
    """Test the email address rejects the values that OpenCTI rejects."""
    # When creating an email address with an invalid value
    # Then a validation error is raised
    with pytest.raises(ValueError):
        EmailAddress(value=value, author=None)
