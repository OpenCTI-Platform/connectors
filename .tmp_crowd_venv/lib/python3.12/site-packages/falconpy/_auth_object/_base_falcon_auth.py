"""Authentication Object base class.

This file contains the definition of the base class that provides the
necessary functions to authenticate to the CrowdStrike Falcon OAuth2 API.

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
from abc import ABC, abstractmethod
from typing import Dict, Union


class BaseFalconAuth(ABC):
    """Abstract class that provides a skeleton interface for the CrowdStrike Falcon OAuth2 API.

    This class does not implement a generic constructor and is not intended to be used by
    developers directly. In order to leverage the functionality provided by the authorization
    object, you should work with a derivative of this class, such as a FalconAuth class.
    """

    #  ______  _______ _______ _______ _     _        _______
    #  |     \ |______ |______ |_____| |     | |         |
    #  |_____/ |______ |       |     | |_____| |_____    |
    #
    #  _______ _______ _______ _     _  _____  ______  _______
    #  |  |  | |______    |    |_____| |     | |     \ |______
    #  |  |  | |______    |    |     | |_____| |_____/ ______|
    #
    # The generic login and logout handlers must be individually defined by all
    # inheriting classes. The private methods defined here are used to allow for
    # easy overriding of login and logout processing by inheriting classes without
    # altering the parent handler method that may be leveraged by other inheriting
    # class types.
    @abstractmethod
    def login(self) -> Union[dict, bool]:
        """Login handler generic abstract."""

    @abstractmethod
    def logout(self) -> Union[dict, bool]:
        """Logout handler generic abstract."""

    #   _____   ______  _____   _____  _______  ______ _______ _____ _______ _______
    #  |_____] |_____/ |     | |_____] |______ |_____/    |      |   |______ |______
    #  |       |    \_ |_____| |       |______ |    \_    |    __|__ |______ ______|
    #
    # These properties are present within all BaseFalconAuth derivatives.
    @property
    @abstractmethod
    def auth_headers(self) -> Dict[str, str]:
        """Get a dictionary of headers that can authenticate a HTTP request."""

    @property
    @abstractmethod
    def cred_format_valid(self) -> bool:
        """Read-only property that returns a boolean if the creds dictionary format is valid."""
