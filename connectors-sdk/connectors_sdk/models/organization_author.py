"""OrganizationAuthor."""

from connectors_sdk.models.base_author_entity import BaseAuthorEntity
from connectors_sdk.models.organization import Organization
from stix2.v21 import Identity as Stix2Identity


class OrganizationAuthor(BaseAuthorEntity, Organization):
    """Represent an organization author.

    This class extends the Organization class to include author-specific fields that will be
    widely used for all other entities a connector processes.

    Examples:
        >>> my_author = OrganizationAuthor(name="Company providing SIEM")
        >>> org = Organization(name="Example Corp", author=my_author)
        >>> entity = org.to_stix2_object()

    """

    def to_stix2_object(self) -> Stix2Identity:
        """Make stix object."""
        return Organization.to_stix2_object(self)
