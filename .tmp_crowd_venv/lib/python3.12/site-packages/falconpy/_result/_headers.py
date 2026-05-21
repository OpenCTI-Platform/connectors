"""FalconPy Headers object.

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
from typing import Optional, Union
from ._base_dictionary import BaseDictionary


class Headers(BaseDictionary):
    """This class represents the headers of an API response."""

    @property
    def content_encoding(self) -> Optional[str]:
        """Return the contents of the Content-Encoding key."""
        return self.get_property("Content-Encoding", None)

    @property
    def content_length(self) -> Optional[Union[int, float]]:
        """Return the contents of the Content-Length key."""
        return self.get_property("Content-Length", 0)

    @property
    def content_type(self) -> Optional[str]:
        """Return the contents of the Content-Type key."""
        return self.get_property("Content-Type", None)

    @property
    def date(self) -> Optional[str]:
        """Return the contents of the Date key."""
        return self.get_property("Date", None)

    @property
    def region(self) -> Optional[str]:
        """Return the contents of the X-Cs-Region key."""
        return self.get_property("X-Cs-Region", None)

    @property
    def ratelimit_limit(self) -> Optional[int]:
        """Return the contents of the X-Ratelimit-Limit key."""
        return self.get_property("X-Ratelimit-Limit", None)

    @property
    def ratelimit_remaining(self) -> Optional[int]:
        """Return the contents of the X-Ratelimit-Remaining key."""
        return self.get_property("X-Ratelimit-Remaining", None)

    @property
    def trace_id(self) -> Optional[str]:  # pragma: no cover
        """Return the contents of the X-Cs-Traceid key."""
        return self.get_property("X-Cs-Traceid", None)
