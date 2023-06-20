"""OpenCTI AlienVault client module."""
from __future__ import annotations

from datetime import datetime
from typing import List

from pycti import OpenCTIConnectorHelper

import pydantic
from alienvault.models import Pulse
from OTXv2 import OTXv2,RetryError
import requests
from requests.adapters import HTTPAdapter

from requests.packages.urllib3.util import Retry

try:
    from urllib.parse import urlencode, urlparse, parse_qs
except ImportError:
    from urllib import urlencode

__all__ = [
    "AlienVaultClient",
]

class OTXv2Fixed(OTXv2):
    def create_url(self, url_path, **kwargs):
        """ Turn a path into a valid fully formatted URL. Supports query parameter formatting as well.

        :param url_path: Request path (i.e. "/search/pulses")
        :param kwargs: key value pairs to be added as query parameters (i.e. limit=10, page=5)
        :return: a formatted url (i.e. "/search/pulses")
        """
        uri = url_path.format(self.server)
        uri = uri if uri.startswith("http") else self.server.rstrip('/') + uri
        if kwargs:
            uri += "?" + urlencode(kwargs)
        print("URI"+uri)
        return uri

    def session(self):
        if self.request_session is None:
            self.request_session = requests.Session()

            # This will allow 5 tries at a url, with an increasing backoff.  Only applies to a specific set of codes
            self.request_session.mount('https://', HTTPAdapter(
                max_retries=Retry(
                    total=0,
                    status_forcelist=[429, 500, 502, 503, 504],
                    backoff_factor=1,
                )
            ))

        return self.request_session
    
    def set_helper(self, helper : OpenCTIConnectorHelper):
        self.helper = helper

    def walkapi_iter(self, url, max_page=None, max_items=None, method='GET', body=None):
        next_page_url = url
        page_size = parse_qs(url)['limit'] if 'limit' in parse_qs(url) else 20
        count = 0
        item_count = 0
        while next_page_url:
            self.helper.log_debug(f"Requesting {next_page_url}")
            count += 1
            if max_page and count > max_page:
                break
            
            if method == 'GET':
                try:
                    data = self.get(next_page_url)
                except RetryError as e:
                    self.helper.log_debug("Retry error at: "+next_page_url+"...")
                    if count==1:
                        next_page_url+="&page=2"

                    last_page_number=int(next_page_url[next_page_url.rfind("=") + 1:])
                    next_page_url=next_page_url[:next_page_url.rfind("=")]+str(last_page_number+1)
                    last_index = 0
                    start_index = page_size * (count - 1) + 1
                    end_index = start_index + page_size
                    for index in range(start_index, end_index):
                        try :
                            last_index = index
                            new_url_parsed = urlparse(next_page_url)
                            queries = parse_qs(new_url_parsed.query)
                            queries['page'] = index
                            queries['limit'] = 1

                            new_url_parsed = new_url_parsed._replace(query=urlencode(queries))
                            new_url = new_url_parsed.geturl()
                            yield list(self.get(new_url)["results"])[0]
                        except RetryError as e:
                            self.helper.log_debug(f"Retry error at pulse indexed: {last_index}")
                    continue
                        

                    #TODO:get page size from config
                    
            elif method == 'POST':
                data = self.post(next_page_url, body=body)
            else:
                raise Exception("Unsupported method type: {}".format(method))

            for el in data['results']:
                item_count += 1
                if max_items and item_count > max_items:
                    break

                yield el

            next_page_url = data["next"]


class AlienVaultClient:
    """AlienVault client."""

    def __init__(self, base_url: str, api_key: str, helper : OpenCTIConnectorHelper) -> None:
        """
        Initializer.
        :param base_url: Base API url.
        :param api_key: API key.
        """
        server = base_url if not base_url.endswith("/") else base_url[:-1]

        self.otx = OTXv2Fixed(api_key, server=server)
        self.otx.set_helper(helper=helper)

    def get_pulses_subscribed(
        self,
        modified_since: datetime,
        limit: int = 20,
    ) -> List[Pulse]:
        """
        Get any subscribed pulses.
        :param modified_since: Filter by results modified since this date.
        :param limit: Return limit.
        :return: A list of pulses.
        """
        pulse_data = self.otx.getsince(timestamp=modified_since, limit=limit)
        pulses = pydantic.parse_obj_as(List[Pulse], pulse_data)

        return pulses
