from censys_enrichmentapis.builders import (
    CertificateStixBuilder,
    GeographyStixBuilder,
    NetworkStixBuilder,
    ServiceStixBuilder,
)
from censys_enrichmentapis.builders.base import StixBuildContext
from connectors_sdk.models import BaseObject, OrganizationAuthor, TLPMarking


class CensysStixBuilder:
    """Coordinate area-specific STIX builders over one shared bundle."""

    def __init__(self) -> None:
        self._context = StixBuildContext()
        self.geography = GeographyStixBuilder(self._context)
        self.network = NetworkStixBuilder(self._context)
        self.certificates = CertificateStixBuilder(self._context)
        self.services = ServiceStixBuilder(self._context)

    @property
    def author(self) -> OrganizationAuthor:
        return self._context.author

    @property
    def marking(self) -> TLPMarking:
        return self._context.marking

    @property
    def bundle(self) -> list[BaseObject]:
        return self._context.bundle

    def reset(self) -> None:
        self._context.reset()
        self.services.reset()

    def add_author_and_marking(self) -> None:
        self._context.add_author_and_marking()
