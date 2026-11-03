"""Shared STIX Identity author for all WhoisFreaks processors."""

from __future__ import annotations

import stix2
from pycti import Identity

_AUTHOR_NAME = "WhoisFreaks"
AUTHOR_ID = Identity.generate_id(_AUTHOR_NAME, "organization")

# Single shared author object — both processors use identical ID + description
# so the description never alternates in the OpenCTI UI regardless of which
# processor sends last.
SHARED_AUTHOR = stix2.Identity(
    id=AUTHOR_ID,
    name=_AUTHOR_NAME,
    identity_class="organization",
    description="WhoisFreaks commercial domain intelligence (threat feeds and NRD).",
)
