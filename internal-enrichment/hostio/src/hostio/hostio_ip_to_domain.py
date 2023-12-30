import logging

import requests

from .hostio_utils import is_valid_token
from .transform_to_stix import HostIOIPtoDomainStixTransform

HOSTIO_ENDPOINT = "https://host.io/api/domains/ip/{}?limit={}&page={}"
SUPPORTED_RESPONSE_KEYS = {"ip", "total", "domains", "page"}

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


class HostIOIPtoDomain:
    """
    Purpose of this Class is to use the HostIO API to request for the full contents of a Domain.
    The results are then added to the Class as attributes.
    """

    def __init__(
        self, token, ip, author, entity_id=None, marking_refs="TLP:WHITE", limit=5
    ):
        self.ip = ip
        if is_valid_token(token):
            self.headers = {"Authorization": f"Bearer {token}"}
        else:
            LOGGER.error(f"Invalid token provided: {token}")
            raise ValueError(f"Invalid token provided: {token}")
        self.page = 0
        self.limit = limit
        self.total = 0
        self.has_next = True
        self.domains = []
        self.entity_id = entity_id
        self.marking_refs = marking_refs
        self.author = author

    def _request_data(self):
        """Internal method to handle API requests."""
        try:
            url = HOSTIO_ENDPOINT.format(self.ip, self.limit, self.page)
            response = requests.get(
                url=url,
                headers=self.headers,
                params=None,
            )

            LOGGER.info(f"HTTP Get Request to endpoint ({url}).")

            if response.status_code == 200:
                return response.json()
            elif response.status_code in (404, 429) and "error" in response.json():
                LOGGER.warn(
                    f"Error while fetching data from ({url}):\n{response.json().get('error')}."
                )
                return None
            else:
                LOGGER.error(
                    f"Error while fetching data from ({url}):\n{response.json()}."
                )
                response.raise_for_status()
                return None
        except requests.RequestException as e:
            LOGGER.error(f"Error while fetching data from ({url}):\n{e}.")
            return None

    def request_ip_to_domain(self):
        """Submit API request, iterate through response, update attributes."""
        response = self._request_data()
        if response is None:
            LOGGER.warning("Failed to fetch data.")
            self.domains = []
            self.has_next = False
            return

        if hasattr(response, "keys"):
            LOGGER.info("Response received.")
            for key in response.keys():
                if key not in SUPPORTED_RESPONSE_KEYS:
                    LOGGER.warning(f"Unsupported response key: {key}")
                else:
                    setattr(self, key, response[key])
            self.page += 1
            if (self.page * self.limit) < (self.total):
                self.has_next = True
            else:
                self.has_next = False
        else:
            LOGGER.warning("Response is empty.")
            return

    def request_next_page(self):
        """Submit API request, iterate through response, update attributes."""
        if not self.has_next:
            return None
        self.request_ip_to_domain()
        return self.domains

    def get_stix_objects(self):
        """Return STIX objects for the Domain."""
        stix_objects = []
        for domain in self.domains:
            stix_objects.extend(
                HostIOIPtoDomainStixTransform(
                    domain=domain,
                    entity_id=self.entity_id,
                    author=self.author,
                    marking_refs=self.marking_refs,
                ).get_stix_objects()
            )
        return stix_objects
