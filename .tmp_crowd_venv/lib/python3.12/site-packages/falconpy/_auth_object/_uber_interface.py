"""Uber Interface class.

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
from traceback import extract_tb
from typing import Dict, List, Optional, Union
from ._falcon_interface import FalconInterface
from .._constant import MAX_DEBUG_RECORDS
from .._endpoint import api_endpoints
from .._util import confirm_base_url


class UberInterface(FalconInterface):
    """Uber Class specific interface."""

    # ____ ___ ___ ____ _ ___  _  _ ___ ____ ____
    # |__|  |   |  |__/ | |__] |  |  |  |___ [__
    # |  |  |   |  |  \ | |__] |__|  |  |___ ___]
    #
    # Attributes present only within the Uber Class.
    #
    # A dictionary of every available API operation provided by the library.
    commands: List[List[Union[str, bool, int, List[dict]]]] = []

    # ____ ____ _  _ ____ ___ ____ _  _ ____ ___ ____ ____
    # |    |  | |\ | [__   |  |__/ |  | |     |  |  | |__/
    # |___ |__| | \| ___]  |  |  \ |__| |___  |  |__| |  \
    #
    # Starting in v1.3.0, the Uber Class constructs itself leveraging the generic
    # FalconAuth constructor. This results in the Uber Class benefiting from a new
    # authentication style; Legacy / Token authentication.
    # pylint: disable=R0913
    def __init__(self,
                 access_token: Optional[Union[str, bool]] = False,
                 base_url: Optional[str] = "https://api.crowdstrike.com",
                 creds: Optional[dict] = None,
                 client_id: Optional[str] = None,
                 client_secret: Optional[str] = None,
                 member_cid: Optional[str] = None,
                 ssl_verify: Optional[bool] = True,
                 proxy: Optional[dict] = None,
                 timeout: Optional[Union[float, tuple]] = None,
                 user_agent: Optional[str] = None,
                 renew_window: Optional[int] = 120,
                 debug: Optional[bool] = False,
                 debug_record_count: Optional[int] = MAX_DEBUG_RECORDS,
                 sanitize_log: Optional[bool] = None,
                 pythonic: Optional[bool] = None,
                 environment: Optional[Dict[str, str]] = None
                 ):
        """Construct an instance of the UberInterface class.

        Instantiates an instance of the class, ingests credentials,
        the base URL and the SSL verification boolean.
        Afterwards class attributes are initialized.

        Keyword arguments:
        base_url: CrowdStrike API URL to use for requests. [Default: US-1]
        ssl_verify: Boolean specifying if SSL verification should be used. [Default: True]
        proxy: Dictionary of proxies to be used for requests.
        timeout: Float or tuple specifying timeouts to use for requests.
        creds: Dictionary containing CrowdStrike API credentials.
               Mutually exclusive to client_id / client_secret.
               {
                   "client_id": "CLIENT_ID_HERE",
                   "client_secret": "CLIENT_SECRET_HERE",
                   "member_cid": "CHILD_CID_MSSP_ONLY"
               }
        client_id: Client ID for the CrowdStrike API. Mutually exclusive to creds.
        client_secret: Client Secret for the CrowdStrike API. Mutually exclusive to creds.
        member_cid: Child CID to connect to. (MSSP only) Mutually exclusive to creds.
        user_agent: User-Agent string to use for all requests made to the CrowdStrike API.
                    String. Defaults to crowdstrike-falconpy/VERSION.
        renew_window: Amount of time (in seconds) between now and the token expiration before
                      a refresh of the token is performed. Default: 120, Max: 1200
                      Values over 1200 will be reset to the maximum.
        debug: Enables debugging. Boolean.
        debug_record_count: Maximum number of returned records to write to log files. Integer
                            Max: 5000
        sanitize_log: Enable / Disable log sanitization of client IDs, secrets and tokens.
                      Boolean. Defaults to enabled.
        This method only accepts keywords to specify arguments.
        """
        super().__init__(base_url=confirm_base_url(base_url),
                         ssl_verify=ssl_verify,
                         timeout=timeout,
                         proxy=proxy,
                         user_agent=user_agent,
                         access_token=access_token,
                         creds=creds,
                         client_id=client_id,
                         client_secret=client_secret,
                         member_cid=member_cid,
                         renew_window=renew_window,
                         debug=debug,
                         debug_record_count=debug_record_count,
                         sanitize_log=sanitize_log,
                         pythonic=pythonic,
                         environment=environment
                         )

        # Complete list of available API operations.
        self.commands = api_endpoints

    # _  _ ____ ___ _  _ ____ ___  ____
    # |\/| |___  |  |__| |  | |  \ [__
    # |  | |___  |  |  | |__| |__/ ___]
    #
    # Override the default login and logout handlers to
    # provide Uber Class-specific functionality.
    def login(self) -> bool:
        """Generate an authorization token."""
        super().login()

        return self.token_valid

    def logout(self) -> bool:
        """Revoke the current authorization token."""
        result = super().logout()

        return bool(result["status_code"] == 200)

    def __enter__(self):
        """Allow for entry as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Discard our token when we exit the context and handle any errors."""
        if exc_type is not None:
            if self.log:
                # Log the error and traceback detail
                self.log.error("ERROR: [%s] %s", exc_type.__name__, exc_val)
                frame_list = extract_tb(exc_tb)
                frame = frame_list[len(frame_list)-1]
                lineno = frame.lineno
                func = frame.name
                fname = frame.filename
                self.log.error("LOCATION: %s, Line #%i in Function '%s'", fname, lineno, func)
        self.logout()

    # Legacy property getters maintained for backwards functionality.
    def authenticated(self) -> bool:
        """Return the current authentication status."""
        return self.token_valid

    def token_expired(self) -> bool:
        """Return the current token expiration status."""
        return self.token_stale

    # _    ____ ____ ____ ____ _   _    _  _ ____ _  _ ___  _    ____ ____ ____
    # |    |___ | __ |__| |     \_/     |__| |__| |\ | |  \ |    |___ |__/ [__
    # |___ |___ |__] |  | |___   |      |  | |  | | \| |__/ |___ |___ |  \ ___]
    #
    # These handlers provide legacy Uber Class-specific functionality that will be
    # maintained for provide backwards compatibility purposes.
    def authenticate(self) -> bool:
        """Legacy Uber Class functionality handler.

        DEPRECATED
        ----
        Consider updating your code to leverage the login method.
        """
        return self.login()

    def deauthenticate(self) -> bool:
        """Legacy Uber Class functionality handler.

        DEPRECATED
        ----
        Consider updating your code to leverage the logout method.
        """
        return self.logout()

    def valid_cred_format(self) -> bool:
        """Legacy property to confirm credential dictionary format.

        DEPRECATED
        ----
        Consider updating your code to leverage the cred_format_valid property.
        """
        return self.cred_format_valid

    def headers(self) -> Dict[str, str]:
        """Legacy property getter for the current authorization headers.

        DEPRECATED
        ----
        Consider updating your code to leverage the auth_headers property.
        """
        return self.auth_headers

    @property
    def token_renew_window(self) -> int:
        """Return the current renew window from the auth_object.

        DEPRECATED: This property recreates a legacy attribute.
        Developers should update code to make use of the `renew_window` property.
        """
        return self.renew_window

    @token_renew_window.setter
    def token_renew_window(self, value: int):
        """Allow the renew_window to be changed.

        DEPRECATED: This property recreates a legacy attribute.
        Developers should update code to make use of the `renew_window` property.
        """
        self.renew_window = value

    @property
    def token(self) -> str:
        """Legacy attribute handler to return the token string.

        DEPRECATED
        ----
        Consider updating your code to leverage the token_value property.
        """
        return self.token_value
