"""FalconPy Request Meta class.

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
from typing import Dict, Union, Optional


class RequestMeta:
    """This class contains the relevant metadata for the API request being performed."""

    # ____ ____ _  _ ____ ___ ____ _  _ ____ ___ ____ ____
    # |    |  | |\ | [__   |  |__/ |  | |     |  |  | |__/
    # |___ |__| | \| ___]  |  |  \ |__| |___  |  |__| |  \
    #
    def __init__(self,
                 endpoint: Optional[str] = None,
                 method: str = "GET",
                 debug_headers: Optional[Dict[str, Optional[Union[str, int, float]]]] = None
                 ):
        """Construct an instance of RequestMeta class."""
        self._endpoint: Optional[str] = endpoint
        self._method: str = method

        self._debug_headers: Optional[Dict[str, Optional[Union[str, int, float]]]] = debug_headers
        if debug_headers is None:
            self._debug_headers = {}

    # ___  ____ ____ ___  ____ ____ ___ _ ____ ____
    # |__] |__/ |  | |__] |___ |__/  |  | |___ [__
    # |    |  \ |__| |    |___ |  \  |  | |___ ___]
    #
    @property
    def endpoint(self) -> Optional[str]:
        """Return the endpoint attribute."""
        return self._endpoint

    @endpoint.setter
    def endpoint(self, value: Optional[str]):
        """Set the endpoint attribute."""
        self._endpoint = value

    @property
    def method(self) -> str:
        """Return the method attribute."""
        return self._method

    @method.setter
    def method(self, value: str):
        """Set the method attribute."""
        self._method = value

    @property
    def debug_headers(self) -> Optional[Dict[str, Optional[Union[str, int, float]]]]:
        """Return the debug headers."""
        return self._debug_headers

    @debug_headers.setter
    def debug_headers(self, value: Dict[str, Optional[Union[str, int, float]]]):
        """Set the debug headers."""
        self._debug_headers = value
