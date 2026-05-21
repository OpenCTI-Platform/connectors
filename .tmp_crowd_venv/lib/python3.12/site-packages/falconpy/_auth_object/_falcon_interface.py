"""API Interface base class.

This file contains the definition of the standard base class that provides
necessary functionality to authenticate to the CrowdStrike Falcon OAuth2 API.

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
import os
import warnings
from contextvars import copy_context
from logging import Logger, getLogger
from typing import Dict, Optional, Union
from ._base_falcon_auth import BaseFalconAuth
from ._bearer_token import BearerToken
from .._log import LogFacility
from .._constant import MIN_TOKEN_RENEW_WINDOW, MAX_TOKEN_RENEW_WINDOW
from ._interface_config import InterfaceConfiguration
from .._enum import TokenFailReason
from .._util import (
    autodiscover_region,
    confirm_base_url,
    perform_request,
    log_class_startup,
    login_payloads,
    logout_payloads,
    review_provided_credentials
    )
from .._error import InvalidCredentials, NoAuthenticationMechanism


# pylint: disable=R0902,R0904
class FalconInterface(BaseFalconAuth):
    """Standard Falcon API interface used by Service Classes."""

    # _______  _____  __   _ _______ _______  ______ _     _ _______ _______  _____   ______
    # |       |     | | \  | |______    |    |_____/ |     | |          |    |     | |_____/
    # |_____  |_____| |  \_| ______|    |    |    \_ |_____| |_____     |    |_____| |    \_
    #
    # The default constructor for all authentication objects. Ingests provided credentials
    # and sets the necessary class attributes based upon the authentication detail received.
    # pylint: disable=R0912,R0913,R0914
    def __init__(self,  # noqa: C901
                 access_token: Optional[Union[str, bool]] = False,
                 base_url: Optional[str] = "https://api.crowdstrike.com",
                 creds: Optional[Dict[str, str]] = None,
                 client_id: Optional[str] = None,
                 client_secret: Optional[str] = None,
                 member_cid: Optional[str] = None,
                 ssl_verify: Optional[bool] = True,
                 proxy: Optional[Dict[str, str]] = None,
                 timeout: Optional[Union[float, tuple]] = None,
                 user_agent: Optional[str] = None,
                 renew_window: Optional[int] = 120,
                 debug: Optional[Union[bool, Logger]] = False,
                 debug_record_count: Optional[int] = None,
                 sanitize_log: Optional[bool] = None,
                 pythonic: Optional[bool] = False,
                 environment: Optional[Dict[str, str]] = None
                 ) -> "FalconInterface":
        """Construct an instance of the FalconInterface class."""
        # Set the pythonic behavior mode.
        self._pythonic: bool = False
        if isinstance(pythonic, bool):
            self._pythonic = pythonic

        # Setup our configuration object using the provided keywords.
        self._config: InterfaceConfiguration = InterfaceConfiguration(base_url=base_url,
                                                                      proxy=proxy,
                                                                      timeout=timeout,
                                                                      user_agent=user_agent,
                                                                      ssl_verify=ssl_verify
                                                                      )            # \ o /
        # ____ _  _ ___ _  _ ____ _  _ ___ _ ____ ____ ___ _ ____ _  _                 |
        # |__| |  |  |  |__| |___ |\ |  |  | |    |__|  |  | |  | |\ |                / \
        # |  | |__|  |  |  | |___ | \|  |  | |___ |  |  |  | |__| | \|
        #
        # Assume no credentials or tokens are provided.
        # A NoAuthenticationMechanism warning will be generated if a
        # valid authentication mechanism is not specified or detected.
        #
        # Then try to authenticate in the following order:
        #    1. Direct
        #    2. Credential
        #    3. Token (Legacy)
        #    4. Context (Foundry)
        #    5. Environment
        #
        # Remaining authentication checks are skipped once a successful mechanism has been determined.
        #
        # Object Authentication is handled within the ServiceClass object and leverages the existing
        # authentication used for the underlying authentication object attribute.

        # Set up an empty Bearer Token container.
        self._token: BearerToken = BearerToken()

        # ___  _ ____ ____ ____ ___    ____ _  _ ___     ____ ____ ____ ___  ____ _  _ ___ _ ____ _
        # |  \ | |__/ |___ |     |     |__| |\ | |  \    |    |__/ |___ |  \ |___ |\ |  |  | |__| |
        # |__/ | |  \ |___ |___  |     |  | | \| |__/    |___ |  \ |___ |__/ |___ | \|  |  | |  | |___
        #
        # Direct Authentication checks provided values and return a creds dictionary based upon the contents.
        # Authorization is derived from the bearer token generated using the provided credentials.
        self._creds, self._auth_style = review_provided_credentials(client_id, client_secret, creds, member_cid)

        # ___ ____ _  _ ____ _  _
        #  |  |  | |_/  |___ |\ |
        #  |  |__| | \_ |___ | \|
        #
        # Token (Legacy) Authentication
        # Authorization is derived from the provided bearer token.
        # A login event is unnecessary when using this authentication mechanism.
        if not self.cred_format_valid:
            if access_token:
                # Store this non-refreshable token, assuming it was just generated.
                self._token: BearerToken = BearerToken(access_token, 1799, 201)
                self._auth_style = "TOKEN"

        # ____ ____ _  _ ___ ____ _  _ ___
        # |    |  | |\ |  |  |___  \/   |
        # |___ |__| | \|  |  |___ _/\_  |
        #
        # Context Authentication searches the current running context for
        # an object containing a bearer token as an attribute or property.
        # Authorization is derived from the discovered bearer token.
        # A login event is unnecessary when using this authentication mechanism.
        if not self.cred_format_valid and not self.token_value:
            for cvar in copy_context().values():
                try:
                    # Any object is acceptable as long as it has an attribute or property named "access_token".
                    self._token: BearerToken = BearerToken(cvar.access_token, 1799, 201)
                    # Attempt to retrieve the cloud region from the same object.
                    # Fall back to our previously set default on failure.
                    try:
                        if cvar.cs_cloud:
                            self._config.base_url = confirm_base_url(cvar.cs_cloud)
                    except AttributeError:
                        if self.token_value:
                            self._config.base_url = confirm_base_url(os.getenv("CS_CLOUD", "auto"))
                    self._auth_style = "CONTEXT"
                    break
                except AttributeError:
                    pass

        # ____ _  _ _  _ _ ____ ____ _  _ _  _ ____ _  _ ___
        # |___ |\ | |  | | |__/ |  | |\ | |\/| |___ |\ |  |
        # |___ | \|  \/  | |  \ |__| | \| |  | |___ | \|  |
        #
        # Environment Authentication searches the current environment for variables containing credentials.
        # Authorization is derived from the bearer token generated using the discovered credentials.
        # Developers may customize which variable names are searched by leveraging the environment keyword (dictionary).
        self._environment = environment if environment else {}
        if not self.cred_format_valid and not self.token_value:
            # Both variables must be present within the running environment.
            if os.getenv(f"{self.env_prefix}{self.env_key}") and os.getenv(f"{self.env_prefix}{self.env_secret}"):
                api_id = os.getenv(f"{self.env_prefix}{self.env_key}") \
                    if "client_id" not in self.creds else self.creds["client_id"]
                api_sec = os.getenv(f"{self.env_prefix}{self.env_secret}") \
                    if "client_secret" not in self.creds else self.creds["client_secret"]
                # Environment Authentication will not override values that preexist in the creds dictionary.
                self._creds = {
                    "client_id": api_id,
                    "client_secret": api_sec
                }
                # Provide member_cid for MSSP environment authentication scenarios. Issue #1105.
                if member_cid:
                    self._creds["member_cid"] = member_cid
                self._auth_style = "ENVIRONMENT"

        # Set the token renewal window, ignored when using Legacy or Context Authentication.
        self.renew_window: int = max(min(renew_window, MAX_TOKEN_RENEW_WINDOW),
                                     MIN_TOKEN_RENEW_WINDOW
                                     )

        # _    ____ ____ ____ _ _  _ ____
        # |    |  | | __ | __ | |\ | | __
        # |___ |__| |__] |__] | | \| |__]
        #
        # Log the creation of this object if debugging is enabled.
        # Starting with v1.3.0 minimal Python native logging is available. In order to reduce
        # potential impacts to developer configurations, this facility is extremely limited
        # and not implemented by default. (Meaning logs are not generated.)
        # To enable logging, pass the keyword "debug" with a value of True to the constructor.
        if debug:
            # Ignored when debugging is disabled.
            _debug_record_count: int = debug_record_count if debug_record_count else None
            # Allow log sanitization to be overridden.
            _sanitize = sanitize_log if isinstance(sanitize_log, bool) else None
            # Logging facility for all classes using this interface, defaults to disabled.
            self._log: LogFacility = LogFacility(debug if isinstance(debug, Logger) else getLogger(__name__),
                                                 _debug_record_count,
                                                 _sanitize
                                                 )
            # Log the startup of this class.
            log_class_startup(self, self.log)
        else:
            # Set up an empty log facility
            self._log: LogFacility = LogFacility()

        # _  _ ____ _    _ ___  ____ ___ ____
        # |  | |__| |    | |  \ |__|  |  |___
        #  \/  |  | |___ | |__/ |  |  |  |___
        #
        # Validation occurs after the logging object is created.
        try:
            # Check to see if we have a valid authentication mechanism configured.
            if not self.cred_format_valid and not self.token_value:
                raise NoAuthenticationMechanism
        except NoAuthenticationMechanism as no_auth_mechanism:
            # Warn appropriately if we do not.
            if pythonic:
                warnings.warn(no_auth_mechanism.message, NoAuthenticationMechanism, stacklevel=2)
            if self.log:
                self.log.warning(no_auth_mechanism.message)

    #  _______ _______ _______ _     _  _____  ______  _______
    #  |  |  | |______    |    |_____| |     | |     \ |______
    #  |  |  | |______    |    |     | |_____| |_____/ ______|
    #
    # The generic login and logout handlers are provided here and leverage private methods
    # to perform the operation. These private methods can be overridden to provide individual
    # login and logout functionality to different inheriting class types.
    def login(self) -> Union[dict, bool]:
        """Login to the Falcon API by requesting a new token."""
        return self._login_handler()

    def logout(self) -> Union[dict, bool]:
        """Log out of the Falcon API by revoking the current token."""
        return self._logout_handler()

    def child_login(self, member_cid: str = None) -> bool:
        """Perform a login leveraging the provided member_cid."""
        returned = False
        if member_cid:
            self.creds["member_cid"] = member_cid
            do_login = self.login()
            if isinstance(do_login, bool):
                returned = do_login
            else:
                if do_login["status_code"] == 201:
                    returned = True
        return returned

    def child_logout(self, login_as_parent: bool = True) -> bool:
        """Perform a logout of the child, and potentially relog in as the parent."""
        returned = False
        if self.creds["member_cid"]:
            self.creds.pop("member_cid", None)
        if login_as_parent:
            do_loginout = self.login()
        else:
            do_loginout = self.logout()
        if isinstance(do_loginout, bool):
            returned = do_loginout
        else:
            if do_loginout["status_code"] == 201:
                returned = True

        return returned

    # The default behavior for both the login and logout handlers is to return
    # the entire dictionary created by the token API response.
    def _login_handler(self, stateful: bool = True) -> dict:
        """Login by requesting a new token.

        This method can also be leveraged to generate tokens without impacting authorization state.
        """
        _returned_headers = {}
        try:
            if self.cred_format_valid:
                operation, target_url, data_payload = login_payloads(self.creds, self.base_url)
                # Log the call to this operation if debugging is enabled.
                if self.log:
                    self.log.debug("OPERATION: %s", operation)
                returned = perform_request(method="POST", endpoint=target_url, data=data_payload,
                                           headers={}, verify=self.ssl_verify, proxy=self.proxy,
                                           timeout=self.timeout, user_agent=self.user_agent,
                                           log_util=self.log, authenticating=True,
                                           sanitize=self.sanitize_log
                                           )
                _returned_headers = returned["headers"]
                if stateful:
                    self.token_status = returned["status_code"]
                    if self.token_status == 201:
                        # Token generation was successful.
                        self.bearer_token = BearerToken(token_value=returned["body"]["access_token"],
                                                        expiration=returned["body"]["expires_in"],
                                                        status=201
                                                        )
                        # Cloud Region auto discovery.
                        self.base_url = autodiscover_region(self.base_url, returned)
                    else:
                        # Token generation failure, reset the current token and check for an error response.
                        self.bearer_token = BearerToken(status=returned["status_code"])
                        # Retrieve the list of errors, there should only be one item in the list.
                        error_list = returned["body"].get("errors", [])
                        if error_list:
                            self.bearer_token.fail_token(returned["status_code"],
                                                         error_list[0]["message"]
                                                         )
            else:
                if stateful:
                    self.bearer_token.fail_token(403, TokenFailReason["INVALID"])
                raise InvalidCredentials(headers=_returned_headers)

        except InvalidCredentials as bad_creds:
            returned = bad_creds.result
            if self.log:
                self.log.error(bad_creds.message)

        return returned

    def _logout_handler(self, token_value: str = None, stateful: bool = True, client_id: str = None) -> dict:
        """Log out by revoking the current token.

        This method can also be leveraged to revoke other tokens.
        """
        try:
            if self.cred_format_valid:
                if not token_value:
                    token_value = self.token_value
                operation, target_url, data_payload, header_payload = logout_payloads(
                    creds=self.creds,
                    base=self.base_url,
                    token_val=token_value,
                    client_id=client_id
                    )
                # Log the call to this operation if debugging is enabled.
                if self.log:
                    self.log.debug("OPERATION: %s", operation)
                returned = perform_request(method="POST", endpoint=target_url, data=data_payload,
                                           headers=header_payload, verify=self.ssl_verify,
                                           proxy=self.proxy, timeout=self.timeout,
                                           user_agent=self.user_agent, log_util=self.log,
                                           sanitize=self.sanitize_log
                                           )
                if stateful:
                    self.bearer_token: BearerToken = BearerToken()
            else:
                raise InvalidCredentials
        except InvalidCredentials as bad_creds:
            returned = bad_creds.result
            if self.log:
                self.log.error(bad_creds.message)

        return returned

    #  _____   ______  _____   _____  _______  ______ _______ _____ _______ _______
    # |_____] |_____/ |     | |_____] |______ |_____/    |      |   |______ |______
    # |       |    \_ |_____| |       |______ |    \_    |    __|__ |______ ______|
    #
    # These properties are present in all FalconInterface derivatives.
    @property
    def creds(self) -> Dict[str, str]:
        """Return the current credential dictionary."""
        return self._creds

    @creds.setter
    def creds(self, value: Dict[str, str]):
        self._creds = value

    @property
    def config(self) -> InterfaceConfiguration:
        """Return the interface configuration object for this interface."""
        return self._config

    @config.setter
    def config(self, value: InterfaceConfiguration):
        if not isinstance(value, InterfaceConfiguration):
            raise ValueError
        self._config = value

    @property
    def base_url(self) -> str:
        """Return the base URL for this interface from the configuration object."""
        return self.config.base_url

    @base_url.setter
    def base_url(self, value):
        self.config.base_url = value

    @property
    def ssl_verify(self) -> bool:
        """Return the SSL verification setting from the configuration object."""
        return self.config.ssl_verify

    @ssl_verify.setter
    def ssl_verify(self, value: bool):
        self.config.ssl_verify = value

    @property
    def proxy(self) -> Dict[str, str]:
        """Return the current proxy setting."""
        return self.config.proxy

    @proxy.setter
    def proxy(self, value: Dict[str, str]):
        self.config.proxy = value

    @property
    def user_agent(self) -> str:
        """Return the current user agent setting."""
        return self.config.user_agent

    @user_agent.setter
    def user_agent(self, value: str):
        self.config.user_agent = value

    @property
    def timeout(self) -> Union[int, tuple]:
        """Return the current timeout setting."""
        return self.config.timeout

    @timeout.setter
    def timeout(self, value: Union[int, tuple]):
        self.config.timeout = value

    @property
    def debug_record_count(self) -> int:
        """Return the current debug record count setting."""
        return self.log_facility.debug_record_count

    @debug_record_count.setter
    def debug_record_count(self, value: int):
        self.log_facility.debug_record_count = value

    @property
    def sanitize_log(self) -> bool:
        """Return the current log sanitization."""
        return self.log_facility.sanitize_log

    @sanitize_log.setter
    def sanitize_log(self, value):
        self.log_facility.sanitize_log = value

    # These properties provide reflection into the token object
    @property
    def bearer_token(self) -> BearerToken:
        """Return the bearer token object for this configuration."""
        return self._token

    @bearer_token.setter
    def bearer_token(self, value: BearerToken):
        """Set the bearer token."""
        self._token = value

    @property
    def renew_window(self) -> int:
        """Return the current token renew window setting."""
        return self.bearer_token.renew_window

    @renew_window.setter
    def renew_window(self, value: int):
        self.bearer_token.renew_window = value

    @property
    def token_expiration(self) -> int:
        """Return the current expiration setting."""
        return self.bearer_token.expiration

    @token_expiration.setter
    def token_expiration(self, value: int):
        self.bearer_token.expiration = value

    @property
    def token_time(self) -> float:
        """Return the current token_time setting."""
        return self.bearer_token.token_time

    @token_time.setter
    def token_time(self, value: float):
        self.bearer_token.token_time = value

    @property
    def token_fail_reason(self) -> str:
        """Return the current fail_reason setting."""
        return self.bearer_token.fail_reason

    @token_fail_reason.setter
    def token_fail_reason(self, value: str):
        self.bearer_token.fail_reason = value

    @property
    def token_status(self) -> int:
        """Return the current status setting."""
        return self.bearer_token.status

    @token_status.setter
    def token_status(self, value: int):
        self.bearer_token.status = value

    @property
    def token_value(self) -> str:
        """Return the current value setting."""
        return self.bearer_token.value

    @token_value.setter
    def token_value(self, value: str):
        self.bearer_token.value = value

    @property
    def pythonic(self) -> bool:
        """Return a boolean if we are in a pythonic mode."""
        return self._pythonic

    @pythonic.setter
    def pythonic(self, value: bool):
        """Enable or disable pythonic mode."""
        self._pythonic = value

    # All properties defined here are by design IMMUTABLE.
    @property
    def refreshable(self) -> bool:
        """Return a boolean if this interface can automatically refresh tokens when they expire."""
        return self.cred_format_valid

    @property
    def token_stale(self) -> bool:
        """Return whether the token is ready to be renewed."""
        return (time.time() - self.token_time) >= (self.token_expiration - self.renew_window)

    @property
    def token_valid(self) -> bool:
        """Return if we are authenticated by retrieving the inverse of token_expired."""
        return not self.token_stale

    @property
    def cred_format_valid(self) -> bool:
        """Return a boolean that the creds dictionary is valid."""
        _returned = False
        if "client_id" in self.creds and "client_secret" in self.creds:
            if isinstance(self.creds["client_id"], str) and isinstance(self.creds["client_secret"], str):
                _returned = True
        return _returned

    @property
    def log(self) -> Logger:
        """Return the logger from our log facility."""
        return self.log_facility.log

    @property
    def log_facility(self) -> LogFacility:
        """Return the entire log facility."""
        return self._log

    # The default functionality of a FalconInterface object performs a token refresh
    # whenever a request is made for the auth_headers property and the token is stale.
    @property
    def auth_headers(self) -> Dict[str, str]:
        """Return a Bearer token baked into an Authorization header ready for an HTTP request."""
        if self.token_stale and self.refreshable:
            self.login()

        return {"Authorization": f"Bearer {self.token_value}"}

    @property
    def debug(self) -> bool:
        """Return a boolean if we are in a debug mode."""
        return bool(self.log)

    @property
    def env_prefix(self) -> str:
        """Return the environment prefix."""
        return self._environment.get("prefix", "FALCON_")

    @property
    def env_key(self) -> str:
        """Return the environment API key name."""
        return self._environment.get("id_name", "CLIENT_ID")

    @property
    def env_secret(self) -> str:
        """Return the environment API key secret."""
        return self._environment.get("secret_name", "CLIENT_SECRET")

    @property
    def auth_style(self) -> str:
        """Return the authentication mechanism used to instantiate this object."""
        return self._auth_style
