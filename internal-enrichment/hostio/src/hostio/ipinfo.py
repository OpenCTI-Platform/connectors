import logging

from ipinfo import getHandler

from .hostio_utils import dict_to_pretty_markdown, is_ipv4, is_ipv6, is_valid_token
from .transform_to_stix import IPInfoStixTransformation

SUPPORTED_RESPONSE_KEYS = {"ip", "total", "domains", "page"}

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


class IPInfo:
    """
    Purpose of this Class is to use the HostIO API to request for the full contents of a Domain.
    The results are then added to the Class as attributes.
    """

    def __init__(self, token, ip, author, marking_refs="TLP:CLEAP", entity_id=None):
        self.ip = ip
        self.marking_refs = marking_refs
        self.entity_id = entity_id
        self.author = author
        if is_valid_token(token):
            self.handler = getHandler(token=token)
        else:
            LOGGER.error("Invalid API token provided.")
            raise ValueError("Invalid API token provided.")
        if is_ipv4(ip) or is_ipv6(ip):
            self.details = self.handler.getDetails(ip).all
        else:
            LOGGER.error(f"Invalid IP address: {ip}")
            raise ValueError(f"Invalid IP address: {ip}")
        self.stix_transform = IPInfoStixTransformation(
            ipinfo_object=self.details,
            author=self.author,
            marking_refs=self.marking_refs,
            entity_id=self.entity_id,
        )
        self.labels = self.stix_transform.get_labels()
        LOGGER.info(f"IPInfo API request for {ip} successful.")

    def get_details(self):
        """Submit API request, iterate through response, update attributes."""
        return self.details

    def get_labels(self):
        return self.labels

    def get_stix_objects(self):
        """Return STIX objects for the Domain."""
        return self.stix_transform.get_stix_objects()

    def get_note_content(self):
        """Return the note content for the Domain."""
        # Update Indicator Description with results from IPInfo.
        if isinstance(self.get_details(), dict):
            return "\n---\n".join(
                dict_to_pretty_markdown(header="IPInfo", obj=self.get_details())
            )
