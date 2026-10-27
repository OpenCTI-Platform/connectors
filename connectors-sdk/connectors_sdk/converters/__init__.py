"""Offer converters from provider payloads to OpenCTI objects.

Provider converters live in sub-packages (e.g. ``connectors_sdk.converters.crowdstrike``)
and are not re-exported here.
"""

from connectors_sdk.converters.base import AbstractConverter
from connectors_sdk.converters.exceptions import ConversionError

__all__ = [
    "AbstractConverter",
    "ConversionError",
]
