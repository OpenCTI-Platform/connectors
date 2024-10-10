import logging
from collections import UserDict

import requests
from taxii2client import DEFAULT_USER_AGENT
from taxii2client.common import (
    MEDIA_TYPE_TAXII_V21,
    TAXIIServiceException,
    _HTTPConnection,
    _to_json,
)


class ResponseWithHeaders(UserDict):
    def __init__(self, data, added_first=None, added_last=None):
        super(ResponseWithHeaders, self).__init__(data)

        self.taxii_added_first = added_first
        self.taxii_added_last = added_last


class HTTPConnectionWithTAXIIHeaders(_HTTPConnection):

    def __init__(
        self, user=None, password=None, verify=True, proxies=None, auth=None, cert=None
    ):
        user_agent = f"{DEFAULT_USER_AGENT} - OpenCTI connector eset-taxii2"
        super().__init__(
            user,
            password,
            verify,
            proxies,
            user_agent,
            "2.1",
            auth,
            cert,
        )

    def get(self, url, headers=None, params=None):
        logger = logging.getLogger("taxii2.connection")

        merged_headers = self._merge_headers(headers)

        if "Accept" not in merged_headers:
            merged_headers["Accept"] = MEDIA_TYPE_TAXII_V21
        accept = merged_headers["Accept"]

        resp = self.session.get(url, headers=merged_headers, params=params)

        logger.debug("Sent request to '%s', status %s", resp.url, resp.status_code)

        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 406:
                # Provide more details about this error since it's usually an import problem.
                # Import the correct version of the TAXII Client.
                logging.error(
                    "Server Response: 406 Client Error "
                    "If you are trying to contact a TAXII 2.1 Server use 'from taxii2client.v21 import X'"
                )
            raise e

        content_type = resp.headers["Content-Type"]
        if not self.valid_content_type(content_type=content_type, accept=accept):
            msg = (
                "Unexpected Response. Got Content-Type: '{}' for Accept: '{}'\n"
                "If you are trying to contact a TAXII 2.1 Server use 'from taxii2client.v21 import X'"
            )
            raise TAXIIServiceException(msg.format(content_type, accept))

        return ResponseWithHeaders(
            _to_json(resp),
            added_first=resp.headers.get("X-TAXII-Date-Added-First"),
            added_last=resp.headers.get("X-TAXII-Date-Added-Last"),
        )


HTTPConnectionWithTAXIIHeaders.get.__doc__ = _HTTPConnection.get.__doc__
