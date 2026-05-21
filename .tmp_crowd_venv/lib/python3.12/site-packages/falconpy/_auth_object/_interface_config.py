"""Interface Configuration class.

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


class InterfaceConfiguration:
    """This class represents the configuration of the interface."""

    # ____ ____ _  _ ____ ___ ____ _  _ ____ ___ ____ ____
    # |    |  | |\ | [__   |  |__/ |  | |     |  |  | |__/
    # |___ |__| | \| ___]  |  |  \ |__| |___  |  |__| |  \
    #
    def __init__(self,
                 base_url: Optional[str] = None,
                 proxy: Optional[Dict[str, str]] = None,
                 timeout: Optional[Union[int, tuple]] = None,
                 user_agent: Optional[str] = None,
                 ssl_verify: Optional[bool] = True
                 ):
        """Construct an instance of the InterfaceConfiguration class."""
        self._base_url: Optional[str] = base_url
        self._proxy: Optional[Dict[str, str]] = proxy
        self._timeout: Optional[Union[int, tuple]] = timeout
        self._user_agent: Optional[str] = user_agent

        self._ssl_verify: bool = True
        if isinstance(ssl_verify, bool):
            self._ssl_verify = ssl_verify

    # ___  ____ ____ ___  ____ ____ ___ _ ____ ____
    # |__] |__/ |  | |__] |___ |__/  |  | |___ [__
    # |    |  \ |__| |    |___ |  \  |  | |___ ___]
    #
    @property
    def base_url(self) -> str:
        """Return the base URL."""
        return self._base_url

    @base_url.setter
    def base_url(self, value: str):
        """Change the base URL."""
        self._base_url = value

    @property
    def proxy(self) -> Optional[Dict[str, str]]:
        """Return the proxy."""
        return self._proxy

    @proxy.setter
    def proxy(self, value: Optional[Dict[str, str]] = None):
        """Update or replace the proxy dictionary."""
        self._proxy = value

    @property
    def timeout(self) -> Union[int, tuple]:
        """Return the timeout."""
        return self._timeout

    @timeout.setter
    def timeout(self, value: Union[int, tuple]):
        """Update or change the timeout."""
        self._timeout = value

    @property
    def user_agent(self) -> str:
        """Return the user agent string."""
        return self._user_agent

    @user_agent.setter
    def user_agent(self, value: Optional[str] = None):
        """Alter the user agent string."""
        self._user_agent = value

    @property
    def ssl_verify(self) -> bool:
        """Return the SSL verification setting."""
        return self._ssl_verify

    @ssl_verify.setter
    def ssl_verify(self, value: bool):
        """Change the SSL verification setting."""
        self._ssl_verify = value
