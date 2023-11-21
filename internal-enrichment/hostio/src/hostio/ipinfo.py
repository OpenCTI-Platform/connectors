import logging

from .hostio_utils import is_valid_token, is_ipv4, is_ipv6

from ipinfo import getHandler



SUPPORTED_RESPONSE_KEYS = {"ip", "total", "domains", "page"}

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


class IPInfo:
    """
    Purpose of this Class is to use the HostIO API to request for the full contents of a Domain.
    The results are then added to the Class as attributes.
    """

    def __init__(self, token, ip, limit=5):
        self.ip = ip
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
        LOGGER.info(f"IPInfo API request for {ip} successful.")


    def get_details(self):
        """Submit API request, iterate through response, update attributes."""
        return self.details
