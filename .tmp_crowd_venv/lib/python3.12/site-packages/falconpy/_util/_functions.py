"""Internal utilities library.

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
from __future__ import annotations
import base64
import functools
from warnings import warn
from json import loads
try:
    from simplejson import JSONDecodeError
except (ImportError, ModuleNotFoundError):  # Support import as a module
    from json.decoder import JSONDecodeError
from typing import Dict, Any, Union, Optional, List, TYPE_CHECKING
from copy import deepcopy
from logging import Logger
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from .._api_request import APIRequest
from .._endpoint import operation_deprecation_mapping
from .._enum import BaseURL, ContainerBaseURL
from .._constant import (
    PREFER_NONETYPE,
    MOCK_OPERATIONS,
    ALLOWED_METHODS as _ALLOWED_METHODS,
    USER_AGENT as _USER_AGENT,
    MAX_DEBUG_RECORDS,
    GLOBAL_API_MAX_RETURN
)
from .._error import (
    RegionSelectError,
    SDKError,
    InvalidMethod,
    KeywordsOnly,
    APIError,
    NoContentWarning,
    PayloadValidationError,
    InvalidBaseURL,
    SSLDisabledWarning,
    UnnecessaryEncodingUsed,
    DeprecatedOperation,
    DeprecatedClass
    )
from .._result import Result
from .._version import version
if TYPE_CHECKING:  # pragma: no cover
    from .._auth_object import FalconInterface
    from .._service_class import ServiceClass
    from ..api_complete import APIHarness, APIHarnessV2
    from ..oauth2 import OAuth2

urllib3.disable_warnings(InsecureRequestWarning)


def validate_payload(validator: Dict[str, Any],
                     payload: Dict[str, Union[str, int, dict, list, bytes]],
                     required: Optional[List[str]] = None
                     ) -> bool:
    """Validate parameters and body payloads sent to the API."""
    # Repurposed with permission from
    # https://github.com/yaleman/crowdstrike_api
    #         __
    #        ( (\
    #         \ =\
    #        __\_ `--\
    #       (____))(  \-----
    #       (____)) _     Thanks
    #       (____))       James!
    #       (____))____/----
    #
    if required:
        for key in required:
            if key not in payload:
                raise PayloadValidationError(code=400, msg=f"Argument {key} must be specified.")

    for key in payload:
        if key not in validator:
            raise PayloadValidationError(code=400, msg=f"{key} is not a valid argument.")
        if not isinstance(payload[key], validator[key]):
            should = validator[key]
            was = type(payload[key])
            raise PayloadValidationError(code=400, msg=f"{key} is not the valid type. Should be: {should}, was {was}")

    return True


def generate_b64cred(client_id: str, client_secret: str) -> str:
    """base64 encodes passed client_id and client_secret for authorization headers."""
    cred = f"{client_id}:{client_secret}"
    b64_byt = base64.b64encode(cred.encode("ascii"))
    encoded = b64_byt.decode("ascii")

    return encoded


def handle_single_argument(passed_arguments: tuple,
                           passed_keywords: Optional[dict] = None,
                           search_key: Optional[str] = None
                           ) -> dict:
    """Handle a single argument that is provided without keywords.

    Reviews arguments passed to a method and injects them into the keyword dictionary if they
    match the search string.
    """
    if not passed_keywords:
        passed_keywords: dict = {}
    if len(passed_arguments) > 0 and search_key:
        passed_keywords[search_key] = passed_arguments[0]

    return passed_keywords


def force_default(defaults: List[str], default_types: List[str] = None):
    """Force default values.

    Intended to decorate other functions.

    Keyword arguments:
    defaults = list of values to default
    default_types = list of types to default the values to

    Example: @force_default(defaults=["parameters"], default_types=["dict"])
    """
    if not default_types:
        default_types = []

    def wrapper(func):
        """Inner wrapper."""
        @functools.wraps(func)
        def factory(*args, **kwargs):
            """Parameter factory.

            This method is a factory and runs through keywords passed to the called function,
            setting defaults on values within the **kwargs dictionary when necessary
            as specified in our "defaults" list that is passed to the parent wrapper.
            It also wraps the protected method with an error handler.
            """
            element_count = 0   # Tracker so we can retrieve matching data types
            # Loop through every element specified in our defaults list
            for element in defaults:
                if element in kwargs:
                    # It exists but it's a NoneType
                    if kwargs.get(element) is None:
                        kwargs[element] = get_default(default_types, element_count)
                else:
                    # Not present whatsoever
                    kwargs[element] = get_default(default_types, element_count)
                # Increment our tracker for our sibling default_types list
                element_count += 1

            try:
                # created = func(*args, **kwargs)
                try:
                    created = func(*args, **kwargs)
                except TypeError as keywords_only:
                    # They passed us an argument but did not specify
                    # what it was (non-keyword) [Issue #263]
                    raise KeywordsOnly from keywords_only
            except KeywordsOnly as bad_keywords:
                created = bad_keywords.result
            except NoContentWarning as no_content_received:
                created = no_content_received.result
            except APIError as api_error:
                # Should only receive this in pythonic mode
                raise api_error
            except (SDKError, InvalidMethod) as bad_sdk_command:
                created = bad_sdk_command.result
            return created
        return factory
    return wrapper


def service_request(caller: ServiceClass = None, **kwargs) -> Union[Dict[str, Union[int, dict, list]], bytes]:
    """Prepare and then perform the request (Service Classes only).

    Inbound caller argument should be a ServiceClass class or derivative.
    """
    if caller:
        # EAFP
        try:
            proxy: Optional[Dict[str, str]] = caller.proxy
        except AttributeError:
            proxy = None

        try:
            timeout: Optional[int] = caller.timeout
        except AttributeError:
            timeout = None

        try:
            user_agent: Optional[str] = caller.user_agent
        except AttributeError:
            user_agent = None

        try:
            log_utility: Optional[Logger] = caller.log
        except AttributeError:
            log_utility = None

        try:
            debug_count: Optional[int] = caller.debug_record_count
        except AttributeError:
            debug_count = None
        try:
            do_sanitize: Optional[bool] = caller.sanitize_log
        except AttributeError:
            do_sanitize = None
        try:
            # Allow pythonic behaviors to be enabled / disabled per request
            do_pythonic: Optional[bool] = kwargs.get("pythonic", None)
            if not isinstance(do_pythonic, bool):
                kwargs["pythonic"] = caller.pythonic
            # do_pythonic: Optional[bool] = caller.pythonic
        except AttributeError:
            kwargs["pythonic"] = None
    # pylint: disable=E0606
    return perform_request(proxy=proxy,
                           timeout=timeout,
                           user_agent=user_agent,
                           log_util=log_utility,
                           debug_record_count=debug_count,
                           sanitize=do_sanitize,
                           **kwargs
                           )


# pylint: disable=R0912  # I don't disagree, but this will work for now.
def calc_content_return(resp: requests.Response,
                        contain: bool,
                        auth: bool,
                        log: Logger,
                        pythonic_mode: bool,
                        api_method: str
                        ) -> Union[dict, bytes]:
    """Calculate the returned content based upon the results from the call to requests."""
    returned = {}
    returned_content_type = resp.headers.get('content-type', None)
    if not returned_content_type:
        returned_content_type = resp.headers.get("Content-Type", "Binary")
    if log:
        log.debug("RECEIVED: Content returned in %s format", returned_content_type)
    if returned_content_type.startswith("application/json"):  # Issue 708
        json_resp: Union[dict, Result] = {}
        try:
            json_resp = resp.json()
        except JSONDecodeError:
            if api_method != "HEAD":
                # It says JSON in the headers but it came back to us as a binary string.
                json_resp = loads(resp.content.decode("ascii"))
        finally:
            # Default behavior is to return results as a standardized dictionary.
            returned = Result(status_code=resp.status_code,
                              headers=resp.headers,
                              body=json_resp,
                              head_request=bool(api_method == "HEAD")
                              ).full_return
    elif returned_content_type.startswith("text/plain"):
        # Assuming UTF-8 for now
        returned = Result(resp.status_code,
                          resp.headers,
                          loads(resp.content.decode("utf-8"))
                          ).full_return
    elif contain:
        returned = Result(resp.status_code, resp.headers, resp.json()).full_return
    else:
        # Binary response
        if not resp.content:
            if auth:
                # Issue 433 - GovCloud autodiscovery is not supported
                raise RegionSelectError(headers=resp.headers)

            # Nothing was returned, so give them back the blank binary object
            # Emulates < v1.3 functionality
            returned = resp.content
        else:
            # returned = resp.content
            returned = Result(resp.status_code, resp.headers, resp.content).full_return

    # Catch and log API response errors
    try:
        if resp.status_code >= 400:
            _message = None
            _errors = returned.get("body", {}).get("errors", [])
            if _errors:
                _message = f"ERROR: {_errors[0]['message']}"
            raise APIError(code=resp.status_code, message=_message, headers=resp.headers)
    except APIError as api_error:
        # Still return the payload unless we're in pythonic mode
        if log:
            log.error(api_error.message)
        if pythonic_mode:
            raise api_error

    return returned, returned_content_type


# pylint: disable=R0915
@force_default(defaults=["headers"], default_types=["dict"])
def perform_request(endpoint: str = "",  # noqa: C901
                    headers: dict = None,
                    **kwargs      # May return dict or binary data types
                    ) -> Union[Dict[str, Union[int, Dict[str, str], Dict[str, Dict]]], bytes]:
    """Leverage the requests library to perform the requested CrowdStrike OAuth2 API operation.

    Keyword arguments:
    method: str - HTTP method to use when communicating with the API
        - Example: GET, POST, PATCH, DELETE or UPDATE
    endpoint: str - API endpoint, including the URL base
        - Example: https://api.crowdstrike.com/oauth2/revoke
    headers: dict - HTTP headers to send to the API
        - Example: {"AdditionalHeader": "AdditionalValue"}
    params: dict - HTTP query string parameters to send to the API
        - Example: {"limit": 1, "sort": "state.asc"}
    body: dict - HTTP body payload to send to the API
        - Example: {"ids": ["123456789abcdefg", "987654321zyxwvutsr"]}
    verify: bool - Enable / Disable SSL certificate checks
        - Example: True
    data - Encoded data to send to the API
        - Example: PAYLOAD = open(FILENAME, 'rb').read()
    files: list - List of files to upload
        - Example: [('file',('testfile2.jpg',open('testfile2.jpg','rb'),'image/jpeg'))]
    body_validator: dict - Dictionary containing payload to be validated for the requested operation (key / datatype)
        - Example: { "limit": int, "offset": int, "filter": str}
    body_required: list - List of payload parameters required by the requested operation
        - Example: ["ids"]
    proxy: dict - Dictionary containing a list of proxies to use for requests
        - Example: {"https": "https://myproxy.com:4000", "http": "http://myhttpproxy:80"}
    timeout: float or tuple
        Float representing the global timeout for requests or a tuple containing the connect / read timeouts.
        - Example: 30
        - Example: (5.05, 25)
    user_agent: string
        - Example: companyname-integrationname/version
    expand_result: bool - Enable expanded results output
        - Example: True
    container: bool - Is this request being sent to a Falcon Container registry endpoint
        - Example: False
    log_util: Logger - Logging utility
    debug_record_count: int - Maximum number of records to log in debug logs
    authenticating: bool - This request is driving a token request
    stream: bool - Enabling streaming download.
    """
    # Shortcut for now
    pythonic = kwargs.get("pythonic", False)
    api: APIRequest = APIRequest(endpoint, kwargs)
    if not api.verify:
        ssl_disabled = SSLDisabledWarning()
        if pythonic:
            warn(ssl_disabled.message, SSLDisabledWarning, stacklevel=2)
        else:
            api.log_warning(msg=ssl_disabled.message)

    if api.method.upper() in _ALLOWED_METHODS:
        # Validate body payload
        if api.body_validator:
            try:
                validate_payload(api.body_validator, api.body_payload, api.body_required)
            except PayloadValidationError as err:
                api.log_error(400, err.message, err.result)
                returned = err.result
                api.perform = False

        # Perform the request
        if api.perform:
            if api.user_agent:
                headers["User-Agent"] = api.user_agent
            else:
                # Force all requests to pass the User-Agent identifier
                headers["User-Agent"] = _USER_AGENT
            headers["CrowdStrike-SDK"] = _USER_AGENT
            # Clean up query string booleans - Issue #1129
            if api.param_payload:
                for param, param_value in api.param_payload.items():
                    if isinstance(param_value, bool):
                        api.param_payload[param] = str(param_value).lower()
            try:
                allow_redirects = False
                # Allow redirections during token authentication and revocation
                for check_point in ["/oauth2/revoke", "/oauth2/token"]:
                    if check_point in api.endpoint:
                        allow_redirects = True
                # Log our payloads if debugging is enabled
                log_api_payloads(api, headers)
                response = requests.request(api.method.upper(), endpoint, params=api.param_payload,
                                            headers=headers, json=api.body_payload, data=api.data_payload,
                                            files=api.files, verify=api.verify, allow_redirects=allow_redirects,
                                            proxies=api.proxy, timeout=api.timeout, stream=api.stream
                                            )

                api.debug_headers = response.headers

                if api.stream:
                    if api.log_util:
                        api.log_util.debug("STREAM: Download requested")
                        api.log_util.debug(f"STREAM: {api.debug_headers}")
                    # Return the requests.Response object instead of a FalconPy Result object
                    return response

                content_return, returning_content_type = calc_content_return(response,
                                                                             api.container,
                                                                             api.authenticating,
                                                                             api.log_util,
                                                                             pythonic,
                                                                             api.method
                                                                             )
                # Expanded results allow for status code and
                # header checks on binary returns.
                # Maintained for < v1.3 syntax compatibility
                if api.expand_result:
                    returned = Result(response.status_code, response.headers, content_return).tupled
                else:
                    returned = content_return

                # Log our response if debugging is enabled
                log_api_activity(content_return, returning_content_type, api)

                # !!! EXPERIMENTAL !!!
                # This functionality is new in v1.3.0 and still experimental, mileage may vary.
                if pythonic:
                    if isinstance(returned, bytes):
                        returned = Result(response.status_code, response.headers, returned)
                    else:
                        returned = Result(full=returned, head_request=bool(api.method == "HEAD"))

            except RegionSelectError as bad_region:
                # More than likely they tried to autoselect to GovCloud
                returned = bad_region.result
                api.log_error(returned.get("status_code"), bad_region.message, returned)

            except JSONDecodeError as json_decode_error:
                # No response content, but a successful request was made
                if "/identity-protection/combined/graphql/v1" in api.endpoint:  # pragma: no cover
                    raise SDKError(message=f"{str(json_decode_error)}",
                                   headers=api.debug_headers
                                   ) from json_decode_error

                api.log_warning("WARNING: No content was received for this request.")
                raise NoContentWarning(headers=response.headers,
                                       code=response.status_code
                                       ) from json_decode_error

            except Exception as havoc:  # pylint: disable=W0703
                # General catch-all for anything coming          ____ ____ _ _      \\       o   o
                # out of requests or the library itself.         |___ |--<  Y        ||      |\O/|
                # Pass this error up to the parent try/catch                          \\      \Y/
                # block residing within our decorator        _  _ ____ _  _ ____ ____         /W\
                # (force_default) for handling.              |--| |--|  \/  [__] |___  !!   _|WWW|_
                if pythonic:
                    # Oh wait, we're pythonic, lets generate
                    # a regular python error condition instead.
                    raise havoc

                raise SDKError(message=f"{str(havoc)}", headers=api.debug_headers) from havoc
    else:
        raise InvalidMethod

    return returned


def log_api_payloads(api: APIRequest, headers: dict):
    """Log the payloads and API response to the debug log."""
    if api.log_util:
        _headers = headers
        _param_payload = api.param_payload
        _body_payload = api.body_payload
        _data_payload = api.data_payload
        if api.sanitize_log:
            _headers = sanitize_dictionary(deepcopy(headers))
            _param_payload = sanitize_dictionary(deepcopy(api.param_payload))
            _body_payload = sanitize_dictionary(deepcopy(api.body_payload))
            _data_payload = sanitize_dictionary(deepcopy(api.data_payload))
        api.log_util.debug("ENDPOINT: %s (%s)", api.endpoint, api.method)
        api.log_util.debug("HEADERS: %s", _headers)
        api.log_util.debug("PARAMETERS: %s", _param_payload)
        api.log_util.debug("BODY: %s", _body_payload)
        api.log_util.debug("DATA: %s", _data_payload)
        if api.stream:
            api.log_util.debug("STREAM: %s", api.stream)


def log_api_activity(content_return: Union[dict, bytes], content_type: str, api: APIRequest):
    """Log the payloads and API response to the debug log."""
    if api.log_util:
        if isinstance(content_return, dict):
            _status_code = content_return.get("status_code", None)
            if _status_code:
                api.log_util.debug("STATUS CODE: %i", _status_code)

        if content_type.startswith("application/json"):
            if api.sanitize_log:
                api.log_util.debug("RESULT: %s", sanitize_dictionary(deepcopy(content_return), api.max_debug))
            else:
                api.log_util.debug("RESULT: %s", content_return)
        elif content_type.startswith("text/plain"):
            api.log_util.debug("RESULT: %s", content_return)
        else:
            api.log_util.debug("RESULT: binary response received from API")


def generate_error_result(
        message: str = "An error has occurred. Check your payloads and try again.",
        code: int = 500,
        **kwargs
        ) -> dict:
    """Normalize error messages."""
    return_headers = kwargs.get("headers", {})
    caller: ServiceClass = kwargs.get("caller", None)
    if caller:
        pythonic_handling = caller.pythonic
        log_handler: Logger = caller.log
        if log_handler:
            log_handler.error("ERROR: [%i] %s", code, message)
        if pythonic_handling:
            raise SDKError(code=code, message=message, headers=return_headers)

    return Result()(status_code=code, headers=return_headers, body={"errors": [{"message": f"{message}"}], "resources": []})


def generate_ok_result(message: str = "Request returned with success", code: int = 200, **kwargs) -> dict:
    """Normalize OK messages."""
    return_headers = kwargs.get("headers", {})
    return Result()(status_code=code, headers=return_headers, body={"message": message, "resources": []})


def get_default(types: list, position: int) -> Union[list, str, int, dict, bool]:
    """I determine the requested default data type and return it."""
    default_value_names = ["list", "str", "int", "dict", "bool"]
    default_value_types = [[], "", 0, {}, False]
    value_count = 0
    retval = {}  # Default to dictionary data type as that is our most often used
    for type_ in default_value_names:
        try:
            if type_ in types[position]:
                retval = default_value_types[value_count]
        except IndexError:
            # Data type not specified, fall back to dictionary
            pass
        value_count += 1

    return retval


def args_to_params(payload: dict,
                   passed_arguments: dict,
                   endpoints: list,
                   epname: str,
                   log_utl: Logger = None,
                   pyth: bool = None
                   ) -> dict:
    """Query String parameter abstraction handler.

    This function reviews arguments passed to the function against arguments accepted by the
    endpoint. If a valid argument is passed, it is added and returned as part of the QueryString
    payload dictionary.

    This function will convert passed comma-delimited strings to list data types when necessary.

    The method only handles QueryString parameters, and will skip any Body payload parameters it
    encounters.

    When using override functionality via the Uber class, this method skips processing. (Override
    functionality does not support QueryString parameter abstraction.)

    Keyword arguments:
    payload -- Existing QueryString parameter payload. Dictionary.
    passed_arguments -- Keywords provided to the calling method.
    endpoints -- List of API endpoints available to the calling method.
    epname -- Operation ID to be retrieved from the endpoints list.
    log_utl -- Logger used when warnings are issued.
    pyth -- Boolean indicating if pythonic responses are enabled.

    Returns: dictionary representing QueryString parameters.
    """
    returned_payload = {}
    if epname != "Manual":  # pylint: disable=R1702
        if epname in operation_deprecation_mapping:
            deprecated_operation(pyth, log_utl, epname, operation_deprecation_mapping[epname])
        for arg in passed_arguments:
            eps = [ep[5] for ep in endpoints if epname == ep[0]][0]
            try:
                argument = [param for param in eps if param["name"] == arg][0]
                if argument:
                    arg_name = argument["name"]
                    if "type" in argument:  # Body payload parameters do not have a type field
                        if argument["type"] == "array":
                            if isinstance(passed_arguments[arg_name], (str)):
                                passed_arguments[arg_name] = passed_arguments[arg_name].split(",")
                        # Check for unnecessarily URLEncoded strings by finding an encoded ":", Issue #850
                        if isinstance(passed_arguments[arg_name], str):
                            if "%3A" in passed_arguments[arg_name]:
                                msg = " ".join([arg_name,
                                                "argument contains potentially urlencoded string of",
                                                f"'{passed_arguments[arg_name]}'."
                                                ])
                                if pyth:
                                    warn(msg, UnnecessaryEncodingUsed, stacklevel=5)
                                else:
                                    if log_utl:
                                        log_utl.warning(msg)

                        # More data type validation can go here
                        payload[arg_name] = passed_arguments[arg_name]
            except IndexError:
                # Unrecognized argument
                pass

    # Clean up reserved word conversions when passing in an invalid raw payload
    if payload:
        for element in payload:
            if not isinstance(element, str):
                returned_payload[element.__name__] = payload[element]
            else:
                returned_payload[element] = payload[element]

    return returned_payload


def process_service_request(calling_object: ServiceClass,  # pylint: disable=R0914 # (19/15)
                            endpoints: List[List[Union[str, List[Dict[str, Any]]]]],
                            operation_id: str,
                            **kwargs
                            ) -> dict:
    """Perform a request originating from a service class module.

    Calculate the target_url based upon the provided operation ID and endpoint list.

    Keyword arguments:
    endpoints -- list - List of service class endpoints, defined as Endpoints in a service class. [required]
    operation_id -- The name of the operation ID. Normally this is also the function name from the service class. [required]
    method -- HTTP method to execute. GET, POST, PATCH, DELETE, PUT accepted. Defaults to GET.
    keywords -- Dictionary of kwargs that were passed to the function within the service class.
    params -- Dictionary of parameters passed to the service class function.
    headers -- Dictionary of headers passed to and calculated by the service class function.
    body -- Dictionary representing the body payload passed to the service class function.
    data -- Dictionary representing the data payload passed to the service class function.
    files -- List of files to be uploaded.
    partition -- ID of the partition to open [PATH] (Event Streams API)
    distinct_field -- Field name to retrieve distinct values for [PATH] (Sensor Update Policies API)
    image_id -- Image ID to be deleted [PATH] (Falcon Container API)
    body_validator -- Dictionary containing details regarding body payload validation
    body_required -- List of required body payload parameters
    expand_result -- Request expanded results output
    pythonic -- Pythonic responses
    collection_name -- Repository collection name [PATH] (Custom Objects API)
    collection_version -- Repository version [PATH] (Custom Objects API)
    object_key -- Object Key [PATH] (Custom Objects API)
    path_id -- ASPM ID path variable [PATH] (ASPM API)
    stream -- Enabling streaming download.
    """
    # Log the operation ID if we have logging enabled.
    if calling_object.log:
        calling_object.log.debug("OPERATION: %s", operation_id)
    # We have to create our headers dictionary first, as authentication happens here.
    # For scenarios where cloud region autodiscovery is leveraged, we cannot create
    # the target URL for our call to requests until we know our correct base_url.
    passed_headers = kwargs.get("headers", None) if kwargs.get("headers", None) else {}
    joined_headers = {
        ** calling_object.headers,
        ** passed_headers
    }
    target_endpoint = [ep for ep in endpoints if operation_id == ep[0]][0]
    base_url = calling_object.base_url
    container = False
    # Check if this operation requires the custom container base URL.
    if operation_id in MOCK_OPERATIONS:
        for base in [burl for burl in dir(BaseURL) if "__" not in burl]:
            if BaseURL[base].value == calling_object.base_url.replace("https://", ""):
                base_url = f"https://{ContainerBaseURL[base].value}"
                container = True
    # Handle any provided PATH variables, should happen before query string argument abstraction.
    target_url = handle_path_variables(passed=kwargs, route_url=f"{base_url}{target_endpoint[2]}")
    # Retrieve our keyword arguments
    passed_keywords = kwargs.get("keywords", {})  # Changed from None in v1.3.3
    passed_params = kwargs.get("params", None)
    # Starting in v1.3.3, Service Classes will pass an empty parameters dictionary
    # instead of a NoneType when no query string arguments are specified.
    parameter_payload = args_to_params(passed_params,
                                       passed_keywords,
                                       endpoints,
                                       operation_id,
                                       calling_object.log,
                                       calling_object.pythonic
                                       )
    expand_result = passed_keywords.get("expand_result", False) if passed_keywords else kwargs.get("expand_result", False)
    do_pythonic = calling_object.pythonic
    if passed_keywords.get("pythonic", None) is not None:
        do_pythonic = passed_keywords.get("pythonic")
    new_keywords = {
        "caller": calling_object,
        "method": target_endpoint[1],
        "endpoint": target_url,
        "verify": calling_object.ssl_verify,
        "headers": joined_headers,
        "params": parameter_payload,
        "body": kwargs.get("body", None),
        "data": kwargs.get("data", None),
        "files": kwargs.get("files", None),
        "body_validator": kwargs.get("body_validator", None),
        "body_required": kwargs.get("body_required", None),
        "expand_result": expand_result,
        "container": container,
        "pythonic": do_pythonic,
        "perform": True,
        "stream": kwargs.get("stream", False)
    }

    return service_request(**new_keywords)


def handle_path_variables(passed: dict, route_url: str):
    """Review passed arguments and perform any necessary replacements to our operation route."""
    passed_partition = passed.get("partition", None)
    if passed_partition or isinstance(passed_partition, int):
        route_url = route_url.format(str(passed_partition))
    passed_distinct_field = passed.get("distinct_field", None)
    if passed_distinct_field:
        route_url = route_url.format(str(passed_distinct_field))
    passed_image_id = passed.get("image_id", None)
    if passed_image_id:
        route_url = route_url.format(str(passed_image_id))
    passed_collection_name = passed.get("collection_name", None)
    if passed_collection_name:
        collect_args = {"collection_name": str(passed_collection_name)}
        passed_object_key = passed.get("object_key", None)
        if passed_object_key:
            collect_args["object_key"] = str(passed_object_key)
        passed_collection_version = passed.get("collection_version", None)
        if passed_collection_version:
            collect_args["collection_version"] = str(passed_collection_version)
        passed_schema_version = passed.get("schema_version", None)
        if passed_schema_version:
            collect_args["schema_version"] = str(passed_schema_version)
        route_url = route_url.format(**collect_args)
    passed_vertex_type = passed.get("vertex_type", None)
    if passed_vertex_type:
        route_url = route_url.format(str(passed_vertex_type))
    passed_id = passed.get("path_id", None)
    if "aspm-api-gateway" in route_url and passed_id:
        route_url = route_url.format(passed.get("path_id"))
    # Falcon Container
    passed_uuid = passed.get("uuid", None)
    if passed_uuid:
        route_url = route_url.format(str(passed_uuid))
    # NGSIEM
    passed_repository = passed.get("repository", None)
    if passed_repository:
        repo_args = {"repository": str(passed_repository)}
        passed_filename = passed.get("filename", None)
        if passed_filename:
            repo_args["filename"] = str(passed_filename)
        passed_package = passed.get("package", None)
        if passed_package:
            repo_args["package"] = passed_package
        passed_namespace = passed.get("namespace", None)
        if passed_namespace:
            repo_args["namespace"] = passed_namespace
        passed_id = passed.get("search_id", None)
        if passed_id:
            repo_args["id"] = passed_id
        route_url = route_url.format(**repo_args)

    return route_url


def confirm_base_url(provided_base: Optional[str] = "https://api.crowdstrike.com") -> str:
    """Confirm the passed base_url value matches URL syntax.

    If it does not, it is looked up in the BaseURL enum. If the value is not found
    within the enum, https:// is prepended to the value and then it is used for API requests.
    """
    # Assume they passed a full URL
    returned_base = provided_base
    try:
        if "://" not in provided_base:
            # They're passing the name instead of the URL
            dashed_bases = ["US-1", "US-2", "EU-1", "US-GOV-1", "US-GOV-2"]
            if provided_base.upper() in dashed_bases:
                provided_base = provided_base.replace("-", "")  # Strip the dash
            try:
                returned_base = f"https://{BaseURL[provided_base.upper()].value}"
            except KeyError:
                # Invalid base URL name, fall back to assuming they didn't give us https
                returned_base = f"https://{provided_base}"

        if returned_base[-1] == "/":  # Issue 558
            returned_base = returned_base[:-1]
    except (AttributeError, TypeError) as bad_base_url:
        raise InvalidBaseURL from bad_base_url

    return returned_base


def confirm_base_region(provided_base_url: str = "https://api.crowdstrike.com") -> str:
    """Retrieve the base url shortname based upon the provided base url value."""
    try:
        shortname = BaseURL(provided_base_url.replace("https://", "").lower()).name
    except (KeyError, ValueError):
        shortname = "US1"  # Fall back to US-1

    return shortname


def return_preferred_default(method_name: str = None, keyword_type: str = "dict"):
    """Use the PREFER_NONETYPE list lookup to determine the default to use for empty payloads."""
    default_return = {}
    if method_name:
        if keyword_type.lower() == "list":
            default_return = []
        if method_name in PREFER_NONETYPE:
            default_return = None

    return default_return


def base_url_regions():
    """Return a list of available Base URL regions."""
    return [bu.name for bu in BaseURL]


def autodiscover_region(provided_base_url: str, auth_result: dict):
    """Autodiscovers the correct region for the token response."""
    new_base_url = confirm_base_url(provided_base_url)
    # Swap to the correct region if they've provided the incorrect one
    if "X-Cs-Region" not in auth_result["headers"]:  # pragma: no cover
        # Starting in v1.2.4, us-gov-1 headers are returned
        # but autoselection is still unsupported
        token_region = confirm_base_region(confirm_base_url(provided_base_url))
    else:
        token_region = auth_result["headers"]["X-Cs-Region"].replace("-", "")
    if token_region.upper() in base_url_regions():
        requested_region = confirm_base_region(confirm_base_url(provided_base_url))
        if token_region != requested_region:
            new_base_url = confirm_base_url(token_region.upper())

    return new_base_url


def sanitize_dictionary(dirty: Any, record_max: int = MAX_DEBUG_RECORDS) -> dict:
    """Strip confidential data from logged dictionaries."""
    cleaned = dirty
    if isinstance(dirty, dict):  # pylint: disable=R1702
        # cleaned = deepcopy(dict(dirty))
        redacted = ["access_token", "client_id", "client_secret", "member_cid", "token"]
        for redact in redacted:
            if redact in cleaned:
                cleaned[redact] = "REDACTED"
            if "body" in cleaned:
                if redact in cleaned["body"]:
                    cleaned["body"][redact] = "REDACTED"
                if "resources" in cleaned["body"]:
                    # Log results are limited to MAX_DEBUG_RECORDS
                    # number of items within the resources list
                    if cleaned["body"]["resources"]:
                        if isinstance(cleaned["body"]["resources"], list):
                            del cleaned["body"]["resources"][max(1, min(record_max,
                                                                        GLOBAL_API_MAX_RETURN
                                                                        )):]
        if "Authorization" in cleaned:
            cleaned["Authorization"] = "Bearer REDACTED"

    return cleaned


def log_class_startup(interface: Union[FalconInterface, ServiceClass, APIHarness, APIHarnessV2, OAuth2],
                      log_device: Logger
                      ):
    """Log the startup of one of our interface or Service Classes."""
    log_device.debug("CREATED: %s interface class", interface.__class__.__name__)
    log_device.debug("AUTH: Configured for %s Authentication", interface.auth_style.title())
    log_device.debug("CONFIG: Base URL set to %s", interface.base_url)
    log_device.debug("CONFIG: SSL verification is set to %s", str(interface.ssl_verify))
    log_device.debug("CONFIG: Timeout set to %s seconds", str(interface.timeout))
    log_device.debug("CONFIG: Proxy dictionary: %s", str(interface.proxy))
    log_device.debug("CONFIG: User-Agent string set to: %s", interface.user_agent)
    log_device.debug("CONFIG: Token renewal window set to %s seconds",
                     str(interface.renew_window)
                     )
    log_device.debug("CONFIG: Maximum number of records to log: %s",
                     interface.debug_record_count
                     )
    log_device.debug(
        "CONFIG: Log sanitization is %s", "enabled" if interface.sanitize_log else "disabled"
        )
    log_device.debug(
        "CONFIG: Pythonic responses are %s", "enabled" if interface.pythonic else "disabled"
        )
    log_device.debug("VERSION: Currently running FalconPy v%s", version())


def deprecated_operation(pythonic: bool, log: Logger, old: str, new: str):
    """Provide a warning that the requested operation has been deprecated."""
    if pythonic:
        warn(DeprecatedOperation(operation=old, new_operation=new), FutureWarning)
    else:
        if log:
            log.warning(DeprecatedOperation(operation=old, new_operation=new))


def deprecated_class(pythonic: bool, log: Logger, old: str, new: str):
    """Provide a warning that the constructed class has been deprecated."""
    if pythonic:
        warn(DeprecatedClass(class_name=old, new_class_name=new), FutureWarning)
    else:
        if log:
            log.warning(DeprecatedClass(class_name=old, new_class_name=new))


def params_to_keywords(arg_list: list, param_dict: dict, keyword_dict: dict):
    """Craft a properly formatted kwargs dictionary from the parameters dictionary contents."""
    for kwa in arg_list:
        if param_dict.get(kwa, None):
            if not keyword_dict.get(kwa, None):
                keyword_dict[kwa] = param_dict.get(kwa)
                param_dict.pop(kwa)

    return keyword_dict
