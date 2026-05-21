"""Input validation helpers for the PortSpoofPro connector.

This module deliberately exposes a minimal surface — only the helpers
that the connector actually calls. The earlier shape carried several
unused validators (``validate_session_state``, ``validate_session_id``,
``validate_numeric_range``, ``validate_event_type``,
``validate_intelligence_data``, ``validate_stix_id``,
``sanitize_string``, ``validate_list_of_strings``) which never had a
call site in this codebase, so they were duplicating constraints that
the ``pydantic`` boundary models in ``main.py`` already enforce. Keep
this file lean so the validation contract stays single-sourced at the
``FullSessionState`` pydantic model.
"""

import ipaddress


class ValidationError(Exception):
    """Raised when input validation fails."""


def validate_ip_address(ip_address: str) -> None:
    """Validate IPv4 or IPv6 address format using the standard library.

    Delegates to ``ipaddress.ip_address`` so we accept the full set of
    valid IPv4/IPv6 representations (including compressed forms like
    ``::1`` and IPv4-mapped IPv6) and reject malformed inputs (for
    example strings of bare colons) that ad-hoc regexes tend to miss.
    """
    if not isinstance(ip_address, str):
        raise ValidationError(
            f"IP address must be a string, got {type(ip_address).__name__}"
        )

    try:
        ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise ValidationError(f"Invalid IP address format: {ip_address}") from exc
