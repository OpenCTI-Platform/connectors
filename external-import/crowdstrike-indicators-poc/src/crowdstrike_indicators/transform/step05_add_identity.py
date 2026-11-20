"""Add the CrowdStrike author identity to a STIX bundle."""

import uuid
from datetime import UTC, datetime
from typing import Any

from stix2.canonicalization.Canonicalize import canonicalize
from stix2.exceptions import STIXError
from stix2.v21 import Bundle, Identity

from shared.errors import ItemConversionError
from shared.transformer import AbstractTransformer

AUTHOR_NAME = "CrowdStrike"
AUTHOR_IDENTITY_CLASS = "organization"

# The namespace pycti's ``Identity.generate_id`` uses: ids computed with it
# match the author of the existing CrowdStrike connector.
IDENTITY_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# CrowdStrike gives no date for itself. A fixed date keeps the identity
# identical, id and content, in every bundle.
IDENTITY_DATE = datetime(1970, 1, 1, tzinfo=UTC)


def identity_id(name: str, identity_class: str) -> str:
    """Return the STIX id of the identity ``name`` of class ``identity_class``.

    Same algorithm as pycti's ``Identity.generate_id``, which the existing
    CrowdStrike connector uses for its author, without depending on pycti:
    the UUIDv5 of the canonical JSON of the lowercased, stripped name and
    class.
    """
    data = canonicalize(
        {"name": name.lower().strip(), "identity_class": identity_class.lower()},
        utf8=False,
    )
    return f"identity--{uuid.uuid5(IDENTITY_NAMESPACE, data)}"


def author_identity() -> Identity:
    """Return the ``CrowdStrike`` organization, author of every object.

    Built like the existing connector's author (``create_organization``):
    same name, class and id, and no ``created_by_ref``. Its dates are fixed.
    """
    return Identity(
        id=identity_id(AUTHOR_NAME, AUTHOR_IDENTITY_CLASS),
        name=AUTHOR_NAME,
        identity_class=AUTHOR_IDENTITY_CLASS,
        created=IDENTITY_DATE,
        modified=IDENTITY_DATE,
    )


class CrowdStrikeAddIdentity(AbstractTransformer[Bundle, Bundle]):
    """Add the CrowdStrike author identity to a STIX bundle.

    Runs after :class:`MakeStixBundle`. The returned bundle has the same id,
    holds the identity first, then every object of the input bundle, in
    order, with a ``created_by_ref`` to the identity. An object that already
    has a ``created_by_ref`` keeps it. An identity of the same id already in
    the bundle is not repeated. Nothing else changes: custom
    properties are kept. The same input always gives the same output. No
    network call is made.
    """

    def __init__(self) -> None:
        self.identity = author_identity()

    def _created_by(self, obj: Any) -> Any:
        if obj.get("created_by_ref"):
            return obj
        return type(obj)(
            **dict(obj),
            created_by_ref=self.identity.id,
            allow_custom=obj.has_custom,
        )

    def convert(self, item: Bundle) -> Bundle:
        """Return ``item`` with the identity added and referenced.

        :raises ItemConversionError: if stix2 rejects an object or the
            bundle.
        """
        try:
            objects = [
                self._created_by(obj)
                for obj in item.get("objects", [])
                if obj.id != self.identity.id
            ]
            return Bundle(
                id=item.id, objects=[self.identity, *objects], allow_custom=True
            )
        except STIXError as error:
            raise ItemConversionError(item.id, str(error)) from error
