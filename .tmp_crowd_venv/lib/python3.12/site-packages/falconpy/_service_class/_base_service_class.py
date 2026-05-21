"""Service Class generic base class.

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
import inspect
from abc import ABC, abstractmethod
from logging import Logger, getLogger
from typing import Dict, Type, Union, Optional
from .._constant import MAX_DEBUG_RECORDS
from .._auth_object import FalconInterface, UberInterface
from .._error import FunctionalityNotImplemented


class BaseServiceClass(ABC):
    """Base class for all Service Classes."""

    #  _______  _____  __   _ _______ _______  ______ _     _ _______ _______  _____   ______
    #  |       |     | | \  | |______    |    |_____/ |     | |          |    |     | |_____/
    #  |_____  |_____| |  \_| ______|    |    |    \_ |_____| |_____     |    |_____| |    \_
    #
    def __init__(self: "BaseServiceClass",
                 auth_object: Optional[FalconInterface] = None,
                 default_auth_object_class: Optional[Union[Type[FalconInterface], Type[UberInterface]]] = FalconInterface,
                 **kwargs
                 ):
        """Construct an instance of the base class."""
        # All Service Classes excluding OAuth2 contain a FalconInterface derivative
        # as an attribute (auth_object). This object can be shared between
        # instances of Service Classes, and is leveraged for all authentication
        # processing. Unlike the OAuth2 and Uber Class, regular Service Classes
        # do not maintain authentication detail outside of the auth_object.
        # An auth_object is treated as an atomic collection.
        if auth_object:
            if isinstance(auth_object, FalconInterface):  # Issue 1043
                self.auth_object: Union[FalconInterface, UberInterface] = auth_object
            else:
                # Easy Object Authentication
                # Look for an auth_object as an attribute to the object they
                # provided. This attribute must be a FalconInterface derivative.
                if hasattr(auth_object, "auth_object"):
                    if isinstance(auth_object.auth_object, FalconInterface):
                        self.auth_object: Union[FalconInterface, UberInterface] = auth_object.auth_object
        else:
            # Get all constructor arguments for the default authentication class.
            auth_kwargs = {
                param: kwargs[param]
                for param in inspect.signature(default_auth_object_class).parameters
                if param in kwargs
            }
            # Create an instance of the default auth_object using the provided keywords.
            self.auth_object: Union[FalconInterface, UberInterface] = default_auth_object_class(**auth_kwargs)

        # Service Classes can enable logging individually, allowing developers to
        # debug API activity for only that service collection within their code.
        self._log: Optional[Union[Logger, bool]] = None
        if kwargs.get("debug", False):
            # Allow a Service Class to enable logging individually.
            _log_target = kwargs.get("debug", False)
            self._log: Logger = _log_target if isinstance(_log_target, Logger) else getLogger(__name__)
        if kwargs.get("debug", None) is False:
            # Allow a Service Class to disable logging individually.
            self._log: bool = False
        # Allow a Service Class to customize the number of debug records logged.
        # This allows developers to individually set maximum records logged per Service Class.
        self._debug_record_count: Optional[int] = None
        if kwargs.get("debug_record_count", None):
            self._debug_record_count = kwargs.get("debug_record_count", MAX_DEBUG_RECORDS)

        # Should logs be sanitized - redacts client_id, client_secret, member_cid, and tokens.
        # Performance impacts when enabled, but defaults to true to prevent unintentional
        # sensitive data disclosure. Can be disabled with the sanitize_log keyword.
        # Set the sanitization flag if they provided it
        _sanitize_log = kwargs.get("sanitize_log", None)
        if isinstance(_sanitize_log, bool):
            self._sanitize: Optional[bool] = _sanitize_log
        else:
            self._sanitize: Optional[bool] = None

        self._pythonic = kwargs.get("pythonic", None)

    #  _______ _______ _______ _     _  _____  ______  _______
    #  |  |  | |______    |    |_____| |     | |     \ |______
    #  |  |  | |______    |    |     | |_____| |_____/ ______|
    #
    # The generic login and logout handlers must be individually defined by all
    # inheriting classes. The default functionality provided by the embedded
    # auth_object is a perfectly acceptable option for this, and is what is used
    # by the standard ServiceClass object.
    @abstractmethod
    def login(self) -> Union[dict, bool]:
        """Login handler abstract."""

    @abstractmethod
    def logout(self) -> Union[dict, bool]:
        """Logout handler abstract."""

    #   _____   ______  _____   _____  _______  ______ _______ _____ _______ _______
    #  |_____] |_____/ |     | |_____] |______ |_____/    |      |   |______ |______
    #  |       |    \_ |_____| |       |______ |    \_    |    __|__ |______ ______|
    #
    # These properties are present within all Service Class derivatives. These are
    # typically maintained within the underlying auth_object, but can be overridden
    # to implement additional functionality as necessary.

    # _  _ _  _ ___ ____ ___  _    ____
    # |\/| |  |  |  |__| |__] |    |___
    # |  | |__|  |  |  | |__] |___ |___
    #
    # Changes made to these properties will effect the underlying auth_object
    # and all Service Classes that happen to be sharing the same auth_object.
    @property
    def base_url(self) -> str:
        """Provide the base_url to code that reads it straight from the service class."""
        return self.auth_object.base_url

    @base_url.setter
    def base_url(self, value: str):
        """Set the base_url in the underlying auth_object."""
        self.auth_object.base_url = value

    @property
    def ssl_verify(self) -> bool:
        """Provide the ssl_verify value to legacy code."""
        return self.auth_object.ssl_verify

    # Changing this setting will impact all traffic thru the interface.
    @ssl_verify.setter
    def ssl_verify(self, value: bool):
        """Allow code to flip the underlying SSL verify flag via the this class."""
        self.auth_object.ssl_verify = value

    # _ _  _ _  _ _  _ ___ ____ ___  _    ____
    # | |\/| |\/| |  |  |  |__| |__] |    |___
    # | |  | |  | |__|  |  |  | |__] |___ |___
    #
    # These properties cannot be changed in the base implementation of a Service Class.
    @property
    def log(self) -> Logger:
        """Property to expose the underlying logger of a Service Class (if enabled)."""
        _returned = None
        if self._log:
            # Logging is unique for this Service Class.
            _returned = self._log
        elif self._log is False:
            # Logging is forcibly disabled for this Service Class.
            _returned = None
        elif self.auth_object:
            _returned = self.auth_object.log

        return _returned

    @property
    # Extended via the inheriting ServiceClass class.
    def headers(self) -> Dict[str, str]:
        """Provide a complete set of request headers."""
        return {**self.auth_object.auth_headers}

    @property
    def token_status(self) -> int:
        """Provide the current token_status."""
        return self.auth_object.token_status

    @property
    def token_fail_reason(self) -> str:
        """Error message received on token generation failure."""
        return self.auth_object.token_fail_reason

    @property
    def refreshable(self) -> bool:
        """Flag indicating if the token for this auth_object is refreshable."""
        return self.auth_object.cred_format_valid

    @property
    def debug(self) -> bool:
        """Return a boolean if this Service Class is in debug mode."""
        _returned = bool(self.log)
        if not _returned:
            _returned = bool(self.auth_object.log)

        return _returned

    # These properties are defined as mutable within the inheriting ServiceClass class.

    @property
    def proxy(self) -> dict:
        """Provide the proxy from the auth_object."""
        return self.auth_object.proxy

    @proxy.setter
    def proxy(self, _):
        raise FunctionalityNotImplemented

    @property
    def timeout(self) -> int:
        """Provide the timeout from the auth_object."""
        return self.auth_object.timeout

    @property
    def renew_window(self) -> int:
        """Provide the renew_window from the auth_object."""
        return self.auth_object.renew_window

    @property
    def user_agent(self) -> int:
        """Provide the user_agent from the auth_object."""
        return self.auth_object.user_agent

    @user_agent.setter
    def user_agent(self, _):
        raise FunctionalityNotImplemented

    # Mutable
    @property
    def debug_record_count(self) -> int:
        """Return the maximum number of records to log to a debug log."""
        _returned = self.auth_object.debug_record_count
        if isinstance(self._debug_record_count, int):
            _returned = self._debug_record_count

        return _returned

    @debug_record_count.setter
    def debug_record_count(self, value):
        """Set the custom debug record count value for this Service Class."""
        self._debug_record_count = value

    @property
    def sanitize_log(self) -> bool:
        """Return a flag if log sanitization is enabled."""
        _returned = self.auth_object.sanitize_log
        if _returned != self._sanitize and isinstance(self._sanitize, bool):
            _returned = self._sanitize
        return _returned

    @sanitize_log.setter
    def sanitize_log(self, value):
        """Enable or disable log sanitization."""
        if self._sanitize is not None:
            self._sanitize = value
        else:
            self.auth_object.sanitize_log = value

    @property
    def pythonic(self) -> bool:
        """Return the current pythonic mode setting."""
        _returned = self.auth_object.pythonic
        if _returned != self._pythonic and isinstance(self._pythonic, bool):
            _returned = self._pythonic
        return _returned
