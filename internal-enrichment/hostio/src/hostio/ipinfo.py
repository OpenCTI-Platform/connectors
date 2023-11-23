import logging

from ipinfo import getHandler

from .hostio_utils import is_ipv4, is_ipv6, is_valid_token, object_to_pretty_json
from .transform_to_stix import IPInfoStixTransformation

SUPPORTED_RESPONSE_KEYS = {"ip", "total", "domains", "page"}

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


class IPInfo:
    """
    Purpose of this Class is to use the HostIO API to request for the full contents of a Domain.
    The results are then added to the Class as attributes.
    """

    def __init__(self, token, ip, marking_refs="TLP:CLEAP", entity_id=None):
        self.ip = ip
        self.marking_refs = marking_refs
        self.entity_id = entity_id
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
            self.details, self.marking_refs, self.entity_id
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
        note_content = str()
        for key in self.get_details().keys():
            if self.get_details().get(key) is not None:
                message = f"IPInfo `{key}`:"
                if self.get_details().get(key) in [None, [], {}, "None"]:
                    # do nothing
                    pass
                elif isinstance(self.get_details().get(key), (dict, list)):
                    pretty_message = object_to_pretty_json(self.get_details().get(key))
                    message += f"\n\n```\n{pretty_message}\n```"
                elif isinstance(self.get_details().get(key), (str, int, float, bool)):
                    message += f"\t```{self.get_details().get(key)}```"
                note_content += f"\n\n{message}"
        return note_content
