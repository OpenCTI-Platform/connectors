"""All-in-one CrowdStrike Falcon OAuth2 API harness.

 @@@@@@@  @@@@@@@@ @@@@@@@  @@@@@@@  @@@@@@@@  @@@@@@@  @@@@@@  @@@@@@@ @@@@@@@@ @@@@@@@
 @@!  @@@ @@!      @@!  @@@ @@!  @@@ @@!      !@@      @@!  @@@   @@!   @@!      @@!  @@@
 @!@  !@! @!!!:!   @!@@!@!  @!@!!@!  @!!!:!   !@!      @!@!@!@!   @!!   @!!!:!   @!@  !@!
 !!:  !!! !!:      !!:      !!: :!!  !!:      :!!      !!:  !!!   !!:   !!:      !!:  !!!
 :: :  :  : :: :::  :        :   : : : :: :::  :: :: :  :   : :    :    : :: ::: :: :  :

This class is deprecated! Developers should import APIHarnessV2 instead.

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
from logging import Logger, getLogger
from .._util import (
    _ALLOWED_METHODS,
    perform_request,
    generate_b64cred,
    generate_error_result,
    confirm_base_url,
    args_to_params,
    return_preferred_default,
    autodiscover_region,
    )
from .._enum import BaseURL, ContainerBaseURL, TokenFailReason
from .._constant import PREFER_IDS_IN_BODY, MOCK_OPERATIONS
from .._endpoint import api_endpoints
from .._log import LogFacility


class APIHarness:
    """This one does it all. It's like the One Ring with significantly fewer orcs.

    This is the LEGACY version of the UBER CLASS and is DEPRECATED as of v1.3.0.
    Developers should make use of the new Uber Class solution: APIHarnessV2.
    """

    # pylint: disable=too-many-instance-attributes
    _token_fail_headers = {}  # Issue #578

    def __init__(self: object,  # pylint: disable=R0913
                 base_url: str = "https://api.crowdstrike.com",
                 creds: dict = None,
                 client_id: str = None,
                 client_secret: str = None,
                 member_cid: str = None,
                 ssl_verify: bool = True,
                 proxy: dict = None,
                 timeout: float or tuple = None,
                 user_agent: str = None,
                 renew_window: int = 120,
                 debug: bool = False,  # New functionality
                 access_token: str = None,  # pylint: disable=W0613  # Not supported
                 pythonic: bool = False,  # New functionality
                 sanitize_log: bool = True,  # New functionality
                 debug_record_count: int = None  # New functionality
                 ) -> object:
        """Uber class constructor.

        Instantiates an instance of the class, ingests credentials,
        the base URL and the SSL verification boolean.
        Afterwards class attributes are initialized.

        Keyword arguments:
        base_url: CrowdStrike API URL to use for requests. [Default: US-1]
        ssl_verify: Boolean specifying if SSL verification should be used or string representing
                    the path to a CA_BUNDLE file or directory of trusted certificates.
                    Default: True
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

        This method only accepts keywords to specify arguments.
        """
        if client_id and client_secret and not creds:
            creds = {
                "client_id": client_id,
                "client_secret": client_secret
            }
            # Have to pass member_cid the same way you pass client_id / secret
            # If you use a creds dictionary, pass the member_cid there instead
            if member_cid:
                creds["member_cid"] = member_cid
        elif not creds:
            creds = {}
        self.creds = creds
        self.base_url = confirm_base_url(base_url)
        self._pythonic = pythonic
        self._debug = debug
        self.ssl_verify = ssl_verify
        self.proxy = proxy
        self.timeout = timeout
        self.token = False
        self.token_expiration = 0
        self.token_time = time.time()
        self.authenticated = False
        self.token_fail_reason = None
        self.token_status = None
        self.headers = lambda: {"Authorization": f"Bearer {self.token}"} if self.token else {}
        self.commands = api_endpoints
        self.user_agent = user_agent  # Issue #365
        # Maximum renewal window is 20 minutes, Minimum is 2 minutes
        self.token_renew_window = max(min(renew_window, 1200), 120)  # in seconds
        self._log = None
        self._debug_record_count = None
        self._sanitize = None
        if debug:
            # Ignored when debugging is disabled.
            self._debug_record_count: int = debug_record_count if debug_record_count else None
            # Allow log sanitization to be overridden.
            self._sanitize = sanitize_log if isinstance(sanitize_log, bool) else None
            # Logging facility for all classes using this interface, defaults to disabled.
            self._log: LogFacility = LogFacility(getLogger(__name__),
                                                 debug_record_count,
                                                 sanitize_log
                                                 )

    def valid_cred_format(self: object) -> bool:
        """Confirm credential dictionary format.

        Returns a boolean indicating if the client_id and
        client_secret are present in the creds dictionary.
        """
        retval = False
        if "client_id" in self.creds and "client_secret" in self.creds:
            retval = True

        return retval

    def token_expired(self: object) -> bool:
        """Return a boolean based upon the token expiration status."""
        retval = False
        if (time.time() - self.token_time) >= (self.token_expiration - self.token_renew_window):
            retval = True

        return retval

    def authenticate(self: object) -> bool:
        """Generate an authorization token."""
        target = self.base_url+'/oauth2/token'
        data_payload = {}
        if self.valid_cred_format():
            data_payload = {
                'client_id': self.creds['client_id'],
                'client_secret': self.creds['client_secret']
            }
        if "member_cid" in self.creds:
            data_payload["member_cid"] = self.creds["member_cid"]

        result = perform_request(method="POST",
                                 endpoint=target,
                                 data=data_payload,
                                 headers={},
                                 verify=self.ssl_verify,
                                 proxy=self.proxy,
                                 timeout=self.timeout,
                                 user_agent=self.user_agent,
                                 authenticating=True,
                                 log_util=self.log,
                                 pythonic=self.pythonic
                                 )
        if isinstance(result, dict):  # Issue #433
            self.token_status = result["status_code"]
            if self.token_status == 201:
                self.token = result["body"]["access_token"]
                self.token_expiration = result["body"]["expires_in"]
                self.token_time = time.time()
                self.authenticated = True
                self.token_fail_reason = None
                self.base_url = autodiscover_region(self.base_url, result)
            else:
                self.authenticated = False
                self._token_fail_headers = result["headers"]
                if "errors" in result["body"]:
                    if result["body"]["errors"]:
                        self.token_fail_reason = result["body"]["errors"][0]["message"]
        else:  # pragma: no cover
            self.authenticated = False
            self.token_fail_reason = TokenFailReason["UNEXPECTED"].value
            self.token_status = 403

        return self.authenticated

    def deauthenticate(self: object) -> bool:
        """Revoke the current authorization token."""
        target = str(self.base_url)+'/oauth2/revoke'
        b64cred = generate_b64cred(self.creds["client_id"], self.creds["client_secret"])
        header_payload = {"Authorization": f"basic {b64cred}"}
        data_payload = {"token": f"{self.token}"}
        revoked = False
        if perform_request(method="POST", endpoint=target, data=data_payload,
                           headers=header_payload, verify=self.ssl_verify,
                           proxy=self.proxy, timeout=self.timeout, user_agent=self.user_agent,
                           log_util=self.log, pythonic=self.pythonic
                           )["status_code"] == 200:
            self.authenticated = False
            self.token = False
            revoked = True
        else:
            revoked = False

        return revoked

    def _create_header_payload(self: object, passed_arguments: dict) -> dict:
        """Create the HTTP header payload.

        Creates the HTTP header payload based upon the existing class headers and passed arguments.
        """
        payload = self.headers()
        if "headers" in passed_arguments:
            for item in passed_arguments["headers"]:
                payload[item] = passed_arguments["headers"][item]
        if "content_type" in passed_arguments:
            payload["Content-Type"] = str(passed_arguments["content_type"])

        return payload

    @staticmethod
    def _handle_partition(tgt: str, kwa: dict):
        if kwa.get("partition", None) is not None:
            # Partition needs to be embedded into the endpoint URL
            tgt = tgt.format(str(kwa.get("partition", None)))
        return tgt

    @staticmethod
    def _handle_distinct_field(tgt: str, kwa: dict):
        if kwa.get("distinct_field", None) is not None:
            # distinct_field also needs to be embedded into the endpoint URL
            tgt = tgt.format(str(kwa.get("distinct_field", None)))
        return tgt

    @staticmethod
    def _handle_container_image_id(tgt: str, kwa: dict):
        if kwa.get("image_id", None) is not None:
            # container image ID also needs to be embedded into the endpoint URL
            tgt = tgt.format(str(kwa.get("image_id", None)))
        return tgt

    @staticmethod
    def _handle_body_payload_ids(kwa: dict):
        if kwa.get("action", None) in PREFER_IDS_IN_BODY:
            if kwa.get("ids", None):
                # Handle the GET to POST method redirection for passed IDs
                if not kwa.get("body", {}).get("ids", None):
                    if "body" not in kwa:
                        kwa["body"] = {}
                    kwa["body"]["ids"] = kwa["ids"]
            # Handle any body payload ID lists that are still strings
            if isinstance(kwa.get("body", {}).get("ids", {}), str):
                kwa["body"]["ids"] = kwa["body"]["ids"].split(",")
        return kwa

    def _handle_container_operations(self, kwa: dict, base_string: str):
        """Handle Base URLs and keyword arguments for container registry operations."""
        # Default to non-container registry operations
        do_container = False
        if kwa.get("action", None) in MOCK_OPERATIONS:
            for base in [burl for burl in dir(BaseURL) if "__" not in burl]:
                if BaseURL[base].value == self.base_url.replace("https://", ""):
                    base_string = f"https://{ContainerBaseURL[base].value}"
                    do_container = True
            if kwa.get("action", None) == "ImageMatchesPolicy":
                if "parameters" not in kwa:
                    kwa["parameters"] = {}
                kwa["parameters"]["policy_type"] = "image-prevention-policy"
        return kwa, base_string, do_container

    def command(self: object, *args, **kwargs) -> dict or bytes:
        """Uber Class API command method.

        Checks token expiration, renewing when necessary, then performs the request.

        Keyword arguments:
        action: str = ""                                    - API Operation ID to perform
        parameters: dict = {}                               - Parameter payload (Query string)
        body: dict = {}                                     - Body payload (Body)
        data: dict = {}                                     - Data payload (Data)
        headers: dict = {}                                  - Headers dictionary (HTTP Headers)
        ids: list or str = None                             - ID list (IDs to handle)
        partition: int or str = None                        - Partition number
        distinct_field: str = None                          - Distinct Field
        override: str = None   (format: 'METHOD,ENDPOINT')  - Override method and endpoint
        action_name: str = None                             - Action to perform (API specific)
        files: list = []                                    - List of files to upload
        file_name: str = None                               - Name of the file to upload
        content_type: str = None                            - Content_Type HTTP header
        expand_result: bool = False                         - Request expanded results (Tuple)
        image_id: str = None                                - Container image ID (Falcon Container only)

        The first argument passed to this method is assumed to be 'action'. All others are ignored.

        Returns: dict object containing API response or binary object depending on operation ID.
        """
        if self.token_expired():
            # Authenticate them if we can
            self.authenticate()

        try:
            if not kwargs.get("action", None):
                # Assume they're passing it in as the first param
                kwargs["action"] = args[0]
        except IndexError:
            pass  # They didn't specify an action, use the default and try for an override instead

        uber_command = [a for a in self.commands if a[0] == kwargs.get("action", None)]
        if kwargs.get("override", None):
            uber_command = [["Manual"] + kwargs["override"].split(",")]
        if uber_command:
            # Retrieve our default base URL
            url_base = self.base_url
            # Alter keywords and base URL if we are performing a container registry operation
            kwargs, url_base, container = self._handle_container_operations(kwargs, url_base)
            # Retrieve the endpoint URL from the command list and append to our base URL
            target = f"{url_base}{uber_command[0][2]}"
            # Container image ID
            target = self._handle_container_image_id(target, kwargs)
            # Partition
            target = self._handle_partition(target, kwargs)
            # Distinct field
            target = self._handle_distinct_field(target, kwargs)
            # Handle any IDs that are in the wrong payload
            kwargs = self._handle_body_payload_ids(kwargs)
            # Check for authentication
            if self.authenticated:
                # Which HTTP method to execute
                selected_method = uber_command[0][1].upper()
                selected_operation = uber_command[0][0]
                # Log the operation we're performing if enabled.
                if self.log:
                    self.log.debug("OPERATION: %s", selected_operation)
                # Only accept allowed HTTP methods
                if selected_method in _ALLOWED_METHODS:
                    returned = perform_request(method=selected_method,
                                               endpoint=target,
                                               body=kwargs.get("body", return_preferred_default(selected_operation)),
                                               data=kwargs.get("data", return_preferred_default(selected_operation)),
                                               params=args_to_params(kwargs.get("parameters", {}),
                                                                     kwargs,
                                                                     self.commands,
                                                                     selected_operation,
                                                                     self.log,
                                                                     self.pythonic
                                                                     ),
                                               headers=self._create_header_payload(kwargs),
                                               files=kwargs.get("files",
                                                                return_preferred_default(selected_operation, "list")
                                                                ),
                                               verify=self.ssl_verify,
                                               proxy=self.proxy,
                                               timeout=self.timeout,
                                               user_agent=self.user_agent,
                                               expand_result=kwargs.get("expand_result", False),
                                               container=container,
                                               log_util=self.log,
                                               pythonic=self.pythonic
                                               )
                else:
                    # Bad HTTP method
                    returned = generate_error_result(message="Invalid HTTP method specified.",
                                                     code=405
                                                     )
            else:
                # Invalid token / Bad creds
                returned = generate_error_result(message="Failed to issue token.",
                                                 code=401,
                                                 headers=self._token_fail_headers
                                                 )
        else:
            # That command doesn't exist, have a cup of tea instead
            returned = generate_error_result(message="Invalid API operation specified.", code=418)

        return returned

    @property
    def token_value(self) -> str:
        """Return the current token value."""
        return self.token

    @property
    def log(self) -> Logger:
        """Return the logger from our log facility."""
        returned = None
        if self.log_facility:
            returned = self.log_facility.log
        return returned

    @property
    def log_facility(self) -> LogFacility:
        """Return the entire log facility."""
        return self._log

    @property
    def debug(self) -> bool:
        """Return a boolean if we are in a debug mode."""
        return bool(self.log)

    @property
    def pythonic(self) -> bool:
        """Return a boolean if we are in a pythonic mode."""
        return self._pythonic

    @pythonic.setter
    def pythonic(self, value: bool):
        """Enable or disable pythonic mode."""
        self._pythonic = value

    @property
    def debug_record_count(self) -> int:
        """Return the current debug record count setting."""
        returned = 100
        if self.log_facility:
            returned = self.log_facility.debug_record_count
        return returned

    @debug_record_count.setter
    def debug_record_count(self, value: int):
        if self.log_facility:
            self.log_facility.debug_record_count = value

    @property
    def sanitize_log(self) -> bool:
        """Return the current log sanitization."""
        returned = True
        if self.log_facility:
            returned = self.log_facility.sanitize_log
        return returned

    @sanitize_log.setter
    def sanitize_log(self, value):
        if self.log_facility:
            self.log_facility.sanitize_log = value
