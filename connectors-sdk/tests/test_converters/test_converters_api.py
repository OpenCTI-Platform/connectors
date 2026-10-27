# pragma: no cover # Do not compute coverage on test files
"""Offer tests for the converters public API."""

import connectors_sdk.converters as converters


def test_public_converters_api_is_present() -> None:
    """Test that features are not removed by mistake."""
    assert set(converters.__all__) == {"AbstractConverter", "ConversionError"}
