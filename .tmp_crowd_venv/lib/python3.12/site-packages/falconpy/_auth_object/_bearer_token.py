"""Bearer Token class.

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
import time
from typing import Optional
from .._constant import MIN_TOKEN_RENEW_WINDOW, MAX_TOKEN_RENEW_WINDOW


class BearerToken:
    """This class represents a bearer token received from the API."""

    # ____ ____ _  _ ____ ___ ____ _  _ ____ ___ ____ ____
    # |    |  | |\ | [__   |  |__/ |  | |     |  |  | |__/
    # |___ |__| | \| ___]  |  |  \ |__| |___  |  |__| |  \
    #
    # Tokens can be instantiated without a value (e.g. invalid or expired).
    def __init__(self,
                 token_value: Optional[str] = None,
                 expiration: Optional[int] = 0,
                 status: Optional[int] = None
                 ):
        """Create an instance of the BearerToken class."""
        self._value = token_value

        # String containing the error message received from the API when token generation failed.
        self._fail_reason: Optional[str] = None
        # Number of seconds between token expiration and now before a token is considered stale.
        self._renew_window: int = 120

        # Integer specifying the amount of time remaining before the token expires (in seconds).
        self._expiration: int = 0
        if isinstance(expiration, int):
            self._expiration = expiration

        # Integer representing the HTTP status code received when generating the token.
        self._status: Optional[int] = None
        if isinstance(status, int):
            self._status = status

        # Float indicating the moment in time that the token was generated (timestamp).
        self._token_time: float = 0
        if token_value:
            self._token_time = time.time()

    # _  _ ____ ___ _  _ ____ ___  ____
    # |\/| |___  |  |__| |  | |  \ [__
    # |  | |___  |  |  | |__| |__/ ___]
    #
    def fail_token(self, status_code: Optional[int] = None, reason: Optional[str] = None):
        """Fail the token by clearing the token value and setting the expiration to zero."""
        self.expiration = 0
        self.value = None
        self.status = 403
        if status_code:
            if isinstance(status_code, int):
                self.status = status_code
        if reason:
            self.fail_reason = reason

    # ___  ____ ____ ___  ____ ____ ___ _ ____ ____    ---     __o
    # |__] |__/ |  | |__] |___ |__/  |  | |___ [__      ---  _`\<,_
    # |    |  \ |__| |    |___ |  \  |  | |___ ___]    ---  (*)/ (*)
    #
    # These properties are present and mutable within all FalconInterface derivatives.
    @property
    def expiration(self) -> int:
        """Return the current expiration setting."""
        return self._expiration

    @expiration.setter
    def expiration(self, value: int):
        """Set the current token expiration."""
        self._expiration = value

    @property
    def token_time(self) -> float:
        """Return the current token_time setting."""
        return self._token_time

    @token_time.setter
    def token_time(self, value: float):
        """Change the token time."""
        self._token_time = value

    @property
    def fail_reason(self) -> Optional[str]:
        """Return the current fail_reason setting."""
        return self._fail_reason

    @fail_reason.setter
    def fail_reason(self, value: Optional[str]):
        """Update the token failure reason."""
        self._fail_reason = value

    @property
    def status(self) -> Optional[int]:
        """Return the current status setting."""
        return self._status

    @status.setter
    def status(self, value: Optional[int]):
        """Update the token status code."""
        self._status = value

    @property
    def value(self) -> Optional[str]:
        """Return the current value setting."""
        return self._value

    @value.setter
    def value(self, value: str):
        """Change the token value."""
        self._value = value

    @property
    def renew_window(self) -> int:
        """Return the current renew_window setting."""
        return self._renew_window

    @renew_window.setter
    def renew_window(self, value: int):
        """Set the token renew window."""
        _value = max(min(MAX_TOKEN_RENEW_WINDOW, value), MIN_TOKEN_RENEW_WINDOW)
        self._renew_window = _value
