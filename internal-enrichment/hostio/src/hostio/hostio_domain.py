import logging

import requests

from .hostio_utils import dict_to_pretty_markdown, format_value, is_valid_token
from .transform_to_stix import HostIODomainStixTransformation

HOSTIO_ENDPOINT = "https://host.io/api/full/{}"
SUPPORTED_RESPONSE_KEYS = ["dns", "ipinfo", "web", "related", "domain"]

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


class HostIODomain:
    """
    Purpose of this Class is to use the HostIO API to request for the full contents of a Domain.
    The results are then added to the Class as attributes.
    """

    def __init__(self, token, domain, author, marking_refs="TLP:WHITE", entity_id=None):
        self.domain = domain
        if is_valid_token(token):
            self.headers = {"Authorization": f"Bearer {token}"}
        else:
            LOGGER.error(f"Invalid token provided: {token}")
            raise ValueError(f"Invalid token provided: {token}")
        self.entity_id = entity_id
        self.marking_refs = marking_refs
        self.author = author
        self.dns = {}
        self.ipinfo = {}
        self.web = {}
        self.related = {}
        self.response = {}
        # Request for Domain Info, update Class attributes.
        self.request_full_domain_info()

    def _request_data(self):
        """Internal method to handle API requests."""
        try:
            response = requests.get(
                url=HOSTIO_ENDPOINT.format(self.domain),
                headers=self.headers,
                params=None,
            )

            LOGGER.info(
                f"HTTP Get Request to endpoint ({HOSTIO_ENDPOINT.format(self.domain)})."
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            error_message = f"Error while fetching data from ({HOSTIO_ENDPOINT.format(self.domain)}):\n{e}."
            LOGGER.error(error_message)
            return None

    def request_full_domain_info(self):
        """Submit API request, iterate through response, update attributes."""
        response = self._request_data()
        if response is None:
            LOGGER.warning("Failed to fetch data.")
            return

        if hasattr(response, "keys"):
            LOGGER.info("Response received.")
            for key in response.keys():
                if key not in SUPPORTED_RESPONSE_KEYS:
                    LOGGER.warning(f"Unsupported response key: {key}")
                else:
                    setattr(self, key, response[key])
        else:
            LOGGER.warning("Response is empty.")
            return

    def get_stix_objects(self):
        """Return STIX objects for the Domain."""
        hostio_domain = HostIODomainStixTransformation(
            domain_object=self,
            entity_id=self.entity_id,
            author=self.author,
            marking_refs=self.marking_refs,
        )
        return hostio_domain.get_stix_objects()

    def get_note_content(self):
        """Return Host IO enrichment notes."""
        note_content = []
        unsupported_values = ["", "None", None, [], {}]
        for key in SUPPORTED_RESPONSE_KEYS:
            if hasattr(self, key) and not getattr(self, key) in unsupported_values:
                LOGGER.debug(f"Parsing key: {key}:{getattr(self, key)}")
                message = str()
                if isinstance(getattr(self, key), (dict)):
                    message = dict_to_pretty_markdown(
                        header=key, obj=getattr(self, key)
                    )
                else:
                    message = format_value(key, getattr(self, key))
                if message:
                    note_content.extend(message)
        return "\n---\n".join(note_content)
