"""FalconPy warnings.

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
from typing import Dict, Optional, Union
from requests.structures import CaseInsensitiveDict
from .._result import Result


class SDKWarning(RuntimeWarning):
    """Base class for all SDK generated warnings."""

    _code: int = 100
    _message: str = "An unexpected warning was generated."
    _headers: Dict[str, Optional[Union[str, int, float]]] = {}
    warning: bool = True

    def __init__(self,
                 code: int = None,
                 message: str = None,
                 headers: dict = None
                 ):
        """Construct an instance of the class."""
        self.code = self._code
        self.message = self._message
        self.headers = self._headers
        if isinstance(code, int):
            self.code = code
        if message:
            self.message = message
        # Allow CaseInsensitiveDict from requests
        if headers:
            if isinstance(headers, CaseInsensitiveDict):
                headers = dict(headers)
            self.headers = headers

        super().__init__(self.message)

    @property
    def result(self) -> dict:
        """Return a properly formatted result leveraging the Result object."""
        _body = {"errors": [{"message": f"{self.message}"}], "resources": []}
        return Result()(self.code, self.headers, _body)

    @property
    def simple(self) -> dict:
        """Return the warning in a simple format that includes the error code."""
        return f"[{self.code}] {self.message}"


class SSLDisabledWarning(SDKWarning):
    """SSL verify has been disabled for requests to the CrowdStrike API."""

    _code = 400
    _message = "SSL verification is currently disabled for requests to the CrowdStrike API."


class NoContentWarning(SDKWarning):
    """No content was received."""

    _code = 204
    _message = "No content was received for this request."


class NoAuthenticationMechanism(SDKWarning):
    """No authentication mechanism was specified when creating this class."""

    _code = 400
    _message = "No authentication mechanism has been specified for this class."


class UnnecessaryEncodingUsed(SDKWarning):
    """An argument was urlencoded when it should not be."""

    _code = 400
    _message = "A provided argument utilizes unnecessary encoding."


class SDKDeprecationWarning(FutureWarning):
    """SDK specific deprecation warning."""

    _code = 299
    _message = "This method has been deprecated."
    warning: bool = True

    def __init__(self,
                 code: int = None,
                 message: str = None
                 ):
        """Construct an instance of the class."""
        self.code = self._code
        self.message = self._message

        if isinstance(code, int):
            self.code = code
        if message:
            self.message = message

        super().__init__(self.message)


class DeprecatedOperation(SDKDeprecationWarning):
    """This API operation has been deprecated."""

    _message = "This operation has been deprecated."

    def __init__(self,
                 code: int = None,
                 operation: str = None,
                 new_operation: str = None
                 ):
        """Construct an instance of the class."""
        if code:
            self._code = code
        self.code = self._code
        if operation:
            self._message = f"The {operation} operation has been deprecated."
        if new_operation:
            self._message = f"{self._message} " \
                            f"Update code to leverage the {new_operation} operation instead."
        self.message = self._message
        super().__init__(self.message)


class DeprecatedClass(SDKDeprecationWarning):
    """This Service Class has been deprecated."""

    _message = "This service class has been deprecated."

    def __init__(self,
                 code: int = None,
                 class_name: str = None,
                 new_class_name: str = None
                 ):
        """Construct an instance of the class."""
        if code:
            self._code = code
        self.code = self._code
        if class_name:
            self._message = f"The {class_name} service class has been deprecated."
        if new_class_name:
            self._message = f"{self._message} " \
                            f"Update code to leverage the {new_class_name} service class instead."
        self.message = self._message
        super().__init__(self.message)
