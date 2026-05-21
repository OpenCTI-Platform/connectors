"""Falcon OAuth2 Authentication API Interface Class.

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
# pylint: disable=R0902,R0913
from logging import Logger
from typing import Dict, Optional, Union
from ._auth_object import FalconInterface
from ._error import CannotRevokeToken
from ._util import (
    confirm_base_url,
    generate_ok_result,
    )
from ._result import Result


class OAuth2(FalconInterface):
    """OAuth2 Service Class.

    To create an instance of this class you must provide either:
        - your client_id and client_secret.
        - a properly formatted dictionary containing your client_id and client_secret
          Example:
          {
              "client_id": FALCON_CLIENT_ID,
              "client_secret": FALCON_CLIENT_SECRET,
              "member_cid": OPTIONAL_CHILD_CID
          }
        - a valid access_token

    All other class constructor arguments are optional.

    OAuth2 is the only Service Class that inherits directly from the FalconAuth object.
    This means the OAuth2 class does not maintain an auth_object, as it is one.
    """

    def __init__(self,
                 access_token: Optional[Union[str, bool]] = False,
                 base_url: Optional[str] = "https://api.crowdstrike.com",
                 ssl_verify: Optional[bool] = True,
                 proxy: Optional[Dict[str, str]] = None,
                 timeout: Optional[Union[float, tuple]] = None,
                 creds: Optional[Dict[str, str]] = None,
                 client_id: Optional[str] = None,
                 client_secret: Optional[str] = None,
                 user_agent: Optional[str] = None,
                 member_cid: Optional[str] = None,
                 renew_window: Optional[int] = 120,
                 debug: Optional[Union[Logger, bool]] = False,
                 debug_record_count: Optional[int] = None,
                 sanitize_log: Optional[bool] = None,
                 pythonic: Optional[bool] = None,
                 environment: Optional[Dict[str, str]] = None
                 ):
        """Construct an instance of the class.

        Initializes the base class by ingesting credentials,
        the proxy dictionary and specifications for other attributes
        such as the base URL, SSL verification, and timeout.

        Keyword arguments
        ----
        base_url : str
            CrowdStrike API URL to use for requests. [Default: US-1]
        ssl_verify : bool
            Flag specifying if SSL verification should be used. [Default: True]
        proxy : dict
            Dictionary of proxies to be used for requests.
        timeout : float or tuple
            Value specifying timeouts to use for requests.
        creds : dict
            Dictionary containing CrowdStrike API credentials.
            Mutually exclusive to client_id / client_secret.
        client_id : str
            Client ID for the CrowdStrike API. Mutually exclusive to creds.
        client_secret : str
            Client Secret for the CrowdStrike API. Mutually exclusive to creds.
        member_cid : str
            Child CID to connect to. Mutually exclusive to creds.
        renew_window : int
            Amount of time (in seconds) between now and the token expiration before
            a refresh of the token is performed. Default: 120, Max: 1200
            Values over 1200 will be reset to the maximum.

        Arguments
        ----
        This method only supports keywords to specify arguments.

        Returns
        ----
        class (OAuth2)
            A constructed instance of the OAuth2 Service Class.
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
                         member_cid=member_cid,             # |
                         renew_window=renew_window,         # /\
                         debug=debug,                      # |o
                         debug_record_count=debug_record_count,
                         sanitize_log=sanitize_log,
                         pythonic=pythonic,
                         environment=environment
                         )

    def logout(self) -> Union[Dict[str, Union[int, dict]], Result]:
        """Revoke the current token.

        Keyword arguments
        ----
        This method does not accept keyword arguments.

        Arguments
        ----
        This method does not accept arguments.

        Returns
        ----
        dict
            Dictionary object containing API response.
        """
        try:
            returned: dict = super().logout()
            if returned["status_code"] == 200:
                returned = generate_ok_result(message="Current token successfully revoked.",
                                              headers=returned["headers"]
                                              )
            else:
                raise CannotRevokeToken(returned["status_code"], returned["body"]["errors"][0]["message"], returned["headers"])
        except CannotRevokeToken as unable_to_revoke:
            if self.log:
                self.log.warning("Token revocation operation failed.")
            returned = unable_to_revoke.result

        return returned

    def revoke(self,
               token: str,
               alter_state: bool = False,
               client_id: str = None
               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Revoke the specified authorization token.

        HTTP Method: POST

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/oauth2/oauth2RevokeToken

        Keyword arguments
        ----
        client_id : str
            Client ID of the token to be revoked.
        token : str
            Token string to be revoked.
        alter_state : bool
            Flag indicating if the underlying authentication state is changed by this request.

        Arguments
        ----
        When not specified as a keyword, token is assumed as the only accepted argument.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return self._logout_handler(token, not alter_state, client_id)

    def token(self, alter_state: bool = False) -> Union[Dict[str, Union[int, dict]], Result]:
        """Generate an authorization token.

        HTTP Method: POST

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/oauth2/oauth2AccessToken

        Keyword arguments
        ----
        alter_state : bool
            Flag indicating if the underlying authentication state is changed by this request.

        Arguments
        ----
        When not specified as a keyword, alter_state is assumed as the only accepted argument.

        Returns
        ----
        dict
            Dictionary object containing API response.
        """
        return self._login_handler(not alter_state)

    # Legacy method handlers that recreates pre-1.3 functionality.
    def authenticated(self) -> bool:
        """Return the current authentication status."""
        return self.token_valid

    def token_expired(self) -> bool:
        """Return the current token expiration status."""
        return self.token_stale

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    oauth2AccessToken = token
    oAuth2AccessToken = token
    oauth2RevokeToken = revoke
    oAuth2RevokeToken = revoke
