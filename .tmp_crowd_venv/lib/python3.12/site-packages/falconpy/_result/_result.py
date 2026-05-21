"""API Response formatting class.

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
from typing import Dict, Union, Optional, List, Tuple
from requests.structures import CaseInsensitiveDict
from ._meta import Meta
from ._errors import Errors
from ._headers import Headers
from ._resources import Resources, BinaryFile, RawBody, ResponseComponent


class BaseResult:
    """Base class for all result objects."""

    # _______ _______ _______ _     _  _____  ______  _______
    # |  |  | |______    |    |_____| |     | |     \ |______
    # |  |  | |______    |    |     | |_____| |_____/ ______|
    #
    def __init__(self,
                 status_code: Optional[int] = 0,
                 headers: Optional[Dict[str, Union[str, int, float]]] = None,
                 body: Optional[Dict[str, Union[str, dict, list, int, float, bytes]]] = None,
                 head_request: bool = False
                 ):
        """Construct an instance of the class."""
        self._pos: int = 0

        # Configure defaults
        self.status_code = status_code  # Will default to 0
        self.headers = Headers()
        self.meta = Meta()
        self.resources = Resources([])
        self.errors = Errors()
        self.raw = RawBody()
        # RTR Batch session init and batch responses only
        self.batch_id = None
        self.batch_get_cmd_req_id = None

        if (status_code and headers and body) or head_request:
            self.status_code = status_code
            _headers = headers
            if isinstance(_headers, CaseInsensitiveDict):
                _headers = dict(headers)
            self.headers = Headers(_headers)
            self._parse_body(body_rcv=body)

    def _parse_body(self, body_rcv: Dict[str, Union[str, dict, list, int, float, bytes]]):
        if isinstance(body_rcv, list):
            # Specific to report_executions_download_get returning raw
            # JSON payloads as a list. There will be no Meta or Errors
            # branch in this response.
            self.resources = Resources(body_rcv)  # pragma: no cover
        elif isinstance(body_rcv, bytes):
            # Binary response
            self.resources = BinaryFile(body_rcv)
            self.meta = Meta()
            self.errors = Errors()
        elif isinstance(body_rcv, str):
            # Invalid or raw response
            if not body_rcv.strip():
                body_rcv = {}
            self.raw = RawBody(body_rcv)
            self.meta = Meta()
            self.resources = Resources()
            self.errors = Errors()
        elif body_rcv.get("access_token", None):
            # Authentication response
            self.raw = RawBody(body_rcv)
            self.meta = Meta()
            self.resources = Resources()
            self.errors = Errors()
        else:
            # Standard responses, GraphQL and RTR
            self.meta = Meta(body_rcv.get("meta", {}))
            self.errors = Errors(body_rcv.get("errors", []))
            # RTR Batch responses
            if body_rcv.get("batch_id", {}):
                # Batch session init returns as a dictionary
                self.raw = RawBody(body_rcv)
                self.batch_id = body_rcv.get("batch_id")
                self.resources = ResponseComponent(body_rcv.get("resources"))
            elif body_rcv.get("combined", {}):
                # Batch session results return as a dictionary.
                self.batch_get_cmd_req_id = body_rcv.get("batch_get_cmd_req_id", None)
                self.raw = RawBody(body_rcv)
                self.resources = ResponseComponent(body_rcv.get("combined"))
            elif body_rcv.get("data", {}):  # pragma: no cover
                # GraphQL uses a custom response payload. Due to
                # environment constraints, this is manually tested.
                self.raw = RawBody(body_rcv)
                self.resources = ResponseComponent(body_rcv)
            elif body_rcv.get("resources", None) is None:
                # No resources, this must be a raw dictionary
                # Probably came from the container API
                self.raw = RawBody(body_rcv)
            elif isinstance(body_rcv.get("resources", []), dict):
                # Catch unusual response payloads not explicitly handled
                self.raw = RawBody(body_rcv)
                self.resources = ResponseComponent(body_rcv.get("resources"))
            else:
                # Standard API responses
                self.resources = Resources(body_rcv.get("resources", []))

    # Iteration handlers
    def __iter__(self):
        """Return this object for iteration handling."""
        _returned = self
        if self.data:
            _returned = self.resources.data.__iter__()
        return _returned

    def __reversed__(self):
        """Reverse the iteration order."""
        _returned = self
        if self.data:
            _returned = self.resources.data.__reversed__()
        return _returned

    def __next__(self):
        """Retrieve the next item in the list."""
        _returned = None
        if self.resources.data:
            _returned = next(self.__iter__())
            self._pos += 1
            if self._pos >= len(self.resources.data):
                raise StopIteration
        else:
            raise StopIteration

        return _returned

    def __getitem__(self, pos):
        """Retrieve an item by position from the resources list."""
        _returned = None
        if isinstance(self.resources.data, list) and isinstance(pos, int):
            if len(self.resources.data) >= pos:
                _returned = self.resources.data.__getitem__(pos)

        return _returned

    # Returns the length of the resources data attribute
    def __len__(self) -> int:
        """Return the length of the resources list when taking the length of this object."""
        return len(self.resources.data)
    # Return a boolean if the string matches

    def __contains__(self, substr):
        """Return a boolean if the search string is found within the list. Exact matches only."""
        return bool(substr in self.resources.data)

    # Legacy handler that emulates functionality in versions prior to v1.3.
    def __call__(self, status_code: int, headers, body: dict):
        """Legacy Result object functionality.

        This method provides the legacy result object functionality and should not be removed.
        """
        return {
            "status_code": status_code,
            # force standard dictionary to prevent json issues
            "headers": dict(headers),
            "body": body
        }

    # Return the entire structure as a JSON formatted string.
    # I'm back and forth on how to best implement this still.
    def __repr__(self) -> str:
        """Return a clean string representation of the result."""
        _body = {}
        if self.raw:
            _body = self.raw.data
        if not _body:
            _body = {
                "meta": self.meta.data,
                "resources": self.resources.data,
                "errors": self.errors.data
            }

        return str({
            "status_code": self.status_code,
            "headers": self.headers.data,
            "body": _body
        })

    @property
    def data(self) -> list:
        """Return the contents of the data property from the underlying Resources object."""
        return self.resources.data


class Result(BaseResult):
    """CrowdStrike API response representation class."""

    def __init__(self,
                 status_code: Optional[int] = None,
                 headers: Optional[Dict[str, str]] = None,
                 body: Optional[Union[bytes,
                                      Dict[str, Union[str, dict, list, int, float, bytes]]
                                      ]] = None,
                 full: Dict[str, Union[int,
                                       Dict[str, str],
                                       Dict[str, Union[str, dict, list, int, float, bytes]]
                                       ]] = None,
                 head_request: bool = False
                 ):
        """Class constructor.

        Provides the ability to create a full object from a result dictionary.
        """
        # Default behavior is to create an empty object to emulate previous functionality.
        # Status code, headers and body must all be present, or full must be provided in
        # order to create a fully populated instance of this object.
        # if full:
        if isinstance(full, dict):
            status_code = full.get("status_code", None)
            headers = full.get("headers", None)
            body = full.get("body", None)

        super().__init__(status_code=status_code,
                         headers=headers,
                         body=body,
                         head_request=head_request
                         )

    # Easy filter method
    def prune(self, substr) -> list:
        """Return a list of matches for the search string from the result list."""
        _returned = list(self.resources.contains(substr))
        return _returned

    # ___  ____ ____ ___  ____ ____ ___ _ ____ ____
    # |__] |__/ |  | |__] |___ |__/  |  | |___ [__
    # |    |  \ |__| |    |___ |  \  |  | |___ ___]
    @property
    def total(self) -> Optional[Union[int, str, float]]:
        """Return the total record count from the underlying Meta object."""
        _returned: Optional[Union[int, str, float]] = 0
        if self.meta:
            _returned = self.meta.total
        return _returned

    @property
    def after(self) -> Optional[Union[int, str, float]]:
        """Return the record after from the underlying Meta object."""
        _returned: Optional[Union[int, str, float]] = None
        if self.meta:
            _returned = self.meta.after
        return _returned

    @property
    def offset(self) -> Optional[Union[int, str, float]]:
        """Return the record offset from the underlying Meta object."""
        _returned: Optional[Union[int, str, float]] = None
        if self.meta:
            _returned = self.meta.offset
        return _returned

    @property
    def limit(self) -> Optional[Union[int, str, float]]:
        """Return the record limit from the underlying Meta object."""
        _returned: Optional[Union[int, str, float]] = 0
        if self.meta:
            _returned = self.meta.limit
        return _returned

    @property
    def query_time(self) -> Optional[Union[int, float]]:
        """Return the query execution time from the underlying Meta object."""
        _returned: Optional[Union[int, float]] = 0
        if self.meta:
            _returned = self.meta.query_time
        return _returned

    @property
    def powered_by(self) -> Optional[str]:
        """Return the powered by value from the underlying Meta object."""
        _returned: Optional[str] = None
        if self.meta:
            _returned = self.meta.powered_by
        return _returned

    @property
    def trace_id(self) -> Optional[str]:
        """Return the trace ID from the underlying Meta or Headers object."""
        _returned: Optional[str] = None
        if self.meta:
            _returned = self.meta.trace_id
        elif self.headers:  # pragma: no cover
            _returned = self.headers.trace_id
        return _returned

    @property
    def content_encoding(self) -> Optional[str]:
        """Return the content encoding from the underlying Headers object."""
        return self.headers.content_encoding

    @property
    def content_type(self) -> Optional[str]:
        """Return the content type from the underlying Headers object."""
        return self.headers.content_type

    @property
    def content_length(self) -> Optional[Union[int, float]]:
        """Return the content length from the underlying Headers object."""
        return self.headers.content_length

    @property
    def date(self) -> Optional[str]:
        """Return the date of the request from the underlying Headers object."""
        return self.headers.date

    @property
    def region(self) -> Optional[str]:
        """Return the CrowdStrike region from the underlying Headers object."""
        return self.headers.region

    @property
    def ratelimit_limit(self) -> Optional[int]:
        """Return the rate limit total from the underlying Headers object."""
        return self.headers.ratelimit_limit

    @property
    def ratelimit_remaining(self) -> Optional[int]:
        """Return the rate limit remaining from the underlying Headers object."""
        return self.headers.ratelimit_remaining

    @property
    def headers_object(self) -> bool:
        """Return if the headers data is a dictionary or Headers object."""
        return isinstance(self.headers.data, Headers)

    @property
    def meta_object(self) -> bool:
        """Return if the meta data is a dictionary or a Meta object."""
        return isinstance(self.meta.data, Meta)

    @property                                       # Doh!
    def tupled(self) -> Tuple[int,               # \o_
                              Dict[str, str],  # __/
                              Union[bytes,      # /
                                    Dict[str,
                                         Union[str, Dict[str, Union[str, List[Union[str, dict]]]]]
                                         ]
                                    ]
                              ]:
        """Results expansion.

        Emulates legacy Results expansions functionality by returning
        the contents of the Result object as a tuple.
        """
        _content: Optional[Union[Dict[str, Union[dict, list]], bytes]] = None
        if self.resources.binary:
            _content = bytes(self.resources)
        elif self.raw:
            _content = self.raw
        else:
            _content = {
                "meta": self.meta.data,
                "resources": self.resources.data,
                "errors": self.errors.data
            }
        return (self.status_code, self.headers.data, _content)

    @property
    def body(self) -> dict:
        """Shortcut property to access just the body dictionary."""
        return dict({"meta": self.meta,
                     "resources": self.resources,
                     "errors": self.errors
                     })

    @property
    def binary(self) -> bool:
        """Return a flag indicating if the downloaded content is a bianry object."""
        return isinstance(self.resources, BinaryFile)  # self.resources.binary

    @property
    def full_return(self) -> dict:
        """Full dictionary representation of the result.

        Used by internal methods for returning contents back to the user.
        """
        if not self.binary:
            _body = self.raw.data if self.raw else {}
            _headers = {}
            if not _body:
                _body = {}
                if self.meta or self.resources or self.errors:
                    _meta = {}
                    _resources = []
                    _errors = []
                    if self.meta:
                        _meta = dict(self.meta.data)
                    if self.resources:
                        _resources = self.resources.data
                    if self.errors.data:
                        _errors = self.errors.data
                    _body["meta"] = _meta
                    _body["resources"] = _resources
                    _body["errors"] = _errors
            if self.headers:
                _headers = dict(self.headers.data)
            if "meta" in _body:
                _body = dict(_body)

            _returned = {
                "status_code": int(self.status_code),
                "headers": _headers,
                "body": _body
            }
        else:
            _returned = bytes(self.resources)

        return _returned
