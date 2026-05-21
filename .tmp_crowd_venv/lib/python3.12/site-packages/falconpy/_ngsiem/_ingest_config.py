"""CrowdStrike NGSIEM API HEC configuration.

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
from typing import Union
from .._enum import IngestFormat, IngestBaseURL


class IngestConfig:
    """This class represents the HEC configuration."""

    def __init__(self,
                 ingest_key,
                 ingest_url_key,
                 ingest_format: str = "json",
                 ingest_region: str = "us1",
                 ingest_timeout: int = 5,
                 ingest_timeunit: str = "nanoseconds",
                 raw_ingest: bool = False,
                 **_
                 ):
        """Create an instance of the ingest configuration class."""
        self._ingest_key = ingest_key
        self._ingest_url_key = ingest_url_key
        try:
            self._ingest_format = IngestFormat[ingest_format.upper()].value
        except KeyError:
            self._ingest_format = IngestFormat["JSON"].value
        self._ingest_region = ingest_region
        self._ingest_timeout = ingest_timeout
        self._ingest_timeunit = ingest_timeunit
        self._raw_ingest = raw_ingest

    @property
    def ingest_base_url(self) -> str:
        """API Ingest base URL."""
        return IngestBaseURL[self._ingest_region.upper()].value

    @ingest_base_url.setter
    def ingest_base_url(self, value: str):
        """Set the API ingest base URL value."""
        try:
            value = value.replace("-", "")
            self._ingest_base_url = IngestBaseURL[value.upper()].value
            self._ingest_region = value.upper()
        except KeyError:
            self._ingest_base_url = value

    @property
    def ingest_region(self) -> str:
        """Ingest region."""
        return self._ingest_region

    @ingest_region.setter
    def ingest_region(self, value: str):
        """Set the ingest region."""
        self._ingest_region = value

    @property
    def ingest_format(self) -> int:
        """Request format."""
        return self._ingest_format

    @ingest_format.setter
    def ingest_format(self, value: str):
        """Set the request format."""
        try:
            self._ingest_format = IngestFormat[value.upper()].value
        except KeyError:
            self._ingest_format = value

    @property
    def ingest_timeout(self) -> int:
        """Request timeout."""
        if not self._ingest_timeout:
            self._ingest_timeout = 5
        return self._ingest_timeout

    @ingest_timeout.setter
    def ingest_timeout(self, value: Union[int, str]):
        """Set the request timeout."""
        self._ingest_timeout = int(value)

    @property
    def ingest_key(self) -> str:
        """Return the ingest API key."""
        return self._ingest_key

    @ingest_key.setter
    def ingest_key(self, value: str):
        """Set the ingest API key."""
        self._ingest_key = value

    @property
    def ingest_url_key(self) -> str:
        """Return the ingest URL key."""
        return self._ingest_url_key

    @ingest_url_key.setter
    def ingest_url_key(self, value: str):
        """Set the ingest URL key."""
        self._ingest_url_key = value

    @property
    def ingest_timeunit(self) -> str:
        """Return the ingest timestamp unit."""
        return self._ingest_timeunit

    @ingest_timeunit.setter
    def ingest_timeunit(self, value: str):
        """Set the ingest timestamp unit."""
        self._ingest_timeunit = value

    @property
    def raw_ingest(self) -> bool:
        """Return the raw ingest setting."""
        return self._raw_ingest

    @raw_ingest.setter
    def raw_ingest(self, value: bool):
        """Set the raw ingest flag."""
        self._raw_ingest = value
