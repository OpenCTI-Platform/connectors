"""FalconPy Meta object.

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
from typing import Union, Dict, Optional
from ._base_dictionary import BaseDictionary


class Meta(BaseDictionary):
    """Class to represent the metadata API response within a result."""

    @property
    def pagination(self) -> Dict[str, Union[int, str, float]]:
        """Return the contents of the pagination branch."""
        return self.get_property("pagination", {})

    @property
    def query_time(self) -> Optional[float]:
        """Return the the contents of the query_time key."""
        return self.get_property("query_time", None)

    @property
    def after(self) -> Optional[Union[int, str, float]]:
        """Return the the contents of the after key."""
        return self.pagination.get("after", None)

    @property
    def offset(self) -> Optional[Union[int, str, float]]:
        """Return the the contents of the offset key."""
        return self.pagination.get("offset", None)

    @property
    def limit(self) -> Optional[Union[int, str, float]]:
        """Return the the contents of the limit key."""
        return self.pagination.get("limit", None)

    @property
    def total(self) -> Optional[Union[int, str, float]]:
        """Return the the contents of the total key."""
        return self.pagination.get("total", None)

    @property
    def expires_at(self) -> Optional[Union[int, str, float]]:
        """Return the the contents of the expires_at key."""
        return self.pagination.get("expires_at", None)

    @property
    def powered_by(self) -> Optional[str]:
        """Return the the contents of the powered_by key."""
        return self.get_property("powered_by", None)

    @property
    def trace_id(self) -> Optional[str]:
        """Return the the contents of the trace_id key."""
        return self.get_property("trace_id", None)
