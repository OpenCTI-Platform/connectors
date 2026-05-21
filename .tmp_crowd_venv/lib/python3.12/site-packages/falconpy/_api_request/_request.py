"""FalconPy API Request object.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""
from typing import Union, Dict, Optional, List, Any
from logging import Logger
from ._request_behavior import RequestBehavior
from ._request_connection import RequestConnection
from ._request_meta import RequestMeta
from ._request_payloads import RequestPayloads
from .._log import LogFacility


class APIRequest:
    """This class represents a request made to the CrowdStrike API."""

    # ____ ____ _  _ ____ ___ ____ _  _ ____ ___ ____ ____
    # |    |  | |\ | [__   |  |__/ |  | |     |  |  | |__/
    # |___ |__| | \| ___]  |  |  \ |__| |___  |  |__| |  \
    #
    def __init__(self,
                 endpoint: str,
                 initializer: Optional[Dict[str, Any]] = None
                 ):
        """Construct an instance of the APIRequest class."""
        if initializer:
            # Key metadata regarding this API request
            self._meta = RequestMeta(endpoint, initializer.get("method", "GET"))
            # Payloads for the request
            self._payloads = RequestPayloads(params=initializer.get("params", None),
                                             body=initializer.get("body", None),
                                             data=initializer.get("data", None),
                                             files=initializer.get("files", [])
                                             )
            # Connection specific details for creating the request
            self._connection = RequestConnection(user_agent=initializer.get("user_agent", None),
                                                 proxy=initializer.get("proxy", {}),
                                                 timeout=initializer.get("timeout", None),
                                                 verify=initializer.get("verify", True)
                                                 )
            # Behavioral flags that alter the behavior of request processing
            self._behavior = RequestBehavior(expand_result=initializer.get("expand_result", False),
                                             container=initializer.get("container", False),
                                             stream=initializer.get("stream", False),
                                             authenticating=initializer.get("authenticating", False),
                                             perform=initializer.get("perform", True),
                                             body_validator=initializer.get("body_validator", None),
                                             body_required=initializer.get("body_required", None)
                                             )
            # Logging functionality
            self._request_log = LogFacility(log=initializer.get("log_util", None),
                                            debug_record_count=initializer.get("debug_record_count", None),
                                            sanitize_log=initializer.get("sanitize", None)
                                            )

        else:
            self._meta = RequestMeta()
            self._payloads = RequestPayloads()
            self._connection = RequestConnection()
            self._behavior = RequestBehavior()
            self._request_log: Optional[LogFacility] = None

    # _  _ ____ ___ _  _ ____ ___  ____
    # |\/| |___  |  |__| |  | |  \ [__
    # |  | |___  |  |  | |__| |__/ ___]
    #
    def log_error(self, code: int = 500, msg: str = None, content: Union[dict, str, bytes] = None):
        """Leverage the attached log utility to log the passed error detail if logging is enabled."""
        if self.log_util:
            self.log_util.error(msg)
            self.log_util.debug("STATUS CODE: %s", code)
            self.log_util.debug("RESULT: %s", content)

    def log_warning(self, msg: str = None):
        """Leverage the attached log utility to log the passed warning detail if logging is enabled."""
        if self.log_util:
            self.log_util.warning(msg)

    # ___  ____ ____ ___  ____ ____ ___ _ ____ ____                        |
    # |__] |__/ |  | |__] |___ |__/  |  | |___ [__          \_            /;
    # |    |  \ |__| |    |___ |  \  |  | |___ ___]         `\~--.._     //'
    #                                                        `//////\  \\/;'
    # All of these properties reflect states for               ~/////\~\`)'
    # properties of connected attribute objects.                   `~'  |
    #                                                              ;'_\'\
    # _  _ ____ ___ ____                                          /~/ '" "'
    # |\/| |___  |  |__|                                         `\/' CROWDSTRIKE
    # |  | |___  |  |  |
    @property
    def meta(self) -> RequestMeta:
        """Return the RequestMeta object."""
        return self._meta

    @property
    def endpoint(self) -> Optional[str]:
        """Return the endpoint attribute."""
        return self.meta.endpoint

    @property
    def method(self) -> str:
        """Return the method attribute."""
        return self.meta.method

    @property
    def debug_headers(self) -> Optional[Dict[str, Optional[Union[str, int, float]]]]:
        """Return the debug headers."""
        return self.meta.debug_headers

    @debug_headers.setter
    def debug_headers(self, value):
        """Set the debug headers."""
        self.meta.debug_headers = value

    # ___  ____ _   _ _    ____ ____ ___  ____
    # |__] |__|  \_/  |    |  | |__| |  \ [__
    # |    |  |   |   |___ |__| |  | |__/ ___]
    @property
    def payloads(self) -> RequestPayloads:
        """Retrieve the payloads object."""
        return self._payloads

    # Body
    @property
    def body_payload(self) -> Optional[Union[bytes, Dict[str, Union[str, int, dict, list, bytes]]]]:
        """Retrieve the body payload from the payloads object."""
        return self.payloads.body

    # Params
    @property
    def param_payload(self) -> Optional[Dict[str, Optional[Union[str, int, float, list, dict]]]]:
        """Retrieve the param payload from the payloads object."""
        return self.payloads.params

    # Data
    @property
    def data_payload(self) -> Optional[Union[bytes, Dict[str, Union[str, int, dict, list, bytes]]]]:
        """Retrieve the data payload from the data object."""
        return self.payloads.data

    # Files
    @property
    def files(self) -> Optional[List[tuple]]:
        """Retrieve the files payload from the files object."""
        return self.payloads.files

    # ___  ____ _  _ ____ _  _ _ ____ ____
    # |__] |___ |__| |__| |  | | |  | |__/
    # |__] |___ |  | |  |  \/  | |__| |  \
    @property
    def behavior(self) -> RequestBehavior:
        """Return the RequestBehavior object."""
        return self._behavior

    @property
    def expand_result(self) -> bool:
        """Return a boolean indicator if result expansion is requested."""
        return self.behavior.expand_result

    @property
    def container(self) -> bool:
        """Return a boolean indicating if this is a container API request."""
        return self.behavior.container

    @property
    def stream(self) -> bool:
        """Return a boolean indicating if this is a streaming download request."""
        return self.behavior.stream

    @property
    def authenticating(self) -> bool:
        """Return a boolean indicating if this is an authentication request."""
        return self.behavior.authenticating

    @property
    def perform(self) -> bool:
        """Return the perform boolean."""
        return self.behavior.perform

    @perform.setter
    def perform(self, value: bool):
        """Set the perform boolean (this request has passed validation)."""
        self.behavior.perform = value

    @property
    def body_validator(self) -> Optional[Dict[str, Any]]:
        """Return the body payload validator from the behavior object."""
        return self.behavior.body_validator

    @property
    def body_required(self) -> Optional[List[str]]:
        """Return the body required list from the behavior object."""
        return self.behavior.body_required

    # _    ____ ____    \ /
    # |    |  | | __     |
    # |___ |__| |__]    /o\
    @property
    def request_log(self) -> LogFacility:
        """Return the LogFacility object."""
        return self._request_log

    @property
    def log_util(self) -> Optional[Logger]:
        """Return the Logger from the request log object."""
        return self.request_log.log

    @property
    def max_debug(self) -> int:
        """Return the maximum number of records to log per debug entry setting."""
        return self.request_log.debug_record_count

    @property
    def sanitize_log(self) -> bool:
        """Return the sanitize logs setting."""
        return self.request_log.sanitize_log

    # ____ ____ _  _ _  _ ____ ____ ___ _ ____ _  _
    # |    |  | |\ | |\ | |___ |     |  | |  | |\ |
    # |___ |__| | \| | \| |___ |___  |  | |__| | \|
    @property
    def connection(self) -> RequestConnection:
        """Return the RequestConnection object."""
        return self._connection

    @property
    def user_agent(self) -> Optional[str]:
        """Return the User Agent string."""
        return self.connection.user_agent

    @property
    def proxy(self) -> Optional[Dict[str, str]]:
        """Return the proxy dictionary."""
        return self.connection.proxy

    @property
    def timeout(self) -> Optional[Union[int, tuple]]:
        """Return the timeout from the connection object.."""
        return self.connection.timeout

    @property
    def verify(self) -> bool:
        """Return the SSL verification setting."""
        return self.connection.verify
