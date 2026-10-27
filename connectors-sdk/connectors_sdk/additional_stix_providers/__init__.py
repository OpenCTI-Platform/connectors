"""Offer providers fetching additional OpenCTI objects for given ids.

Provider-specific providers live in sub-packages (e.g.
``connectors_sdk.additional_stix_providers.crowdstrike``) and are not
re-exported here.
"""

from connectors_sdk.additional_stix_providers.base import (
    AbstractAdditionalStixProvider,
)

__all__ = [
    "AbstractAdditionalStixProvider",
]
