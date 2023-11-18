from stix2 import DomainName
from validators import domain as domain_validator

from .hostio_utils import get_tlp_marking


class HostioDomainStixTransform:
    """Class to transform a Domain into a STIX DomainName object."""

    def __init__(self, domain, marking_refs="TLP:WHITE", entity_id=None):
        """Initialize the class with the domain and entity id."""
        self.marking_refs = [get_tlp_marking(marking_refs)]
        if domain_validator(domain):
            self.domain = domain
        else:
            raise ValueError(f"Domain provided failed validation: {domain}")
        self.entity_id = None if entity_id is None else [entity_id]

        # Create STIX objects for the Domain Name and External Reference and add them to the list of STIX objects.
        self.stix_objects = self._create_domain_observable()

    def _create_domain_observable(self):
        """Create the STIX DomainName object."""
        domain_name_sco = DomainName(
            value=self.domain,
            type="domain-name",
            resolves_to_refs=self.entity_id,
            object_marking_refs=self.marking_refs,
        )
        return [domain_name_sco]

    def get_stix_objects(self):
        """Return the list of STIX objects."""
        return self.stix_objects
