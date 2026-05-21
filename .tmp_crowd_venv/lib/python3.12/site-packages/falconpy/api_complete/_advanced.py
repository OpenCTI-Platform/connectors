"""All-in-one CrowdStrike Falcon OAuth2 API harness.

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
import functools
from typing import Dict, Union, Callable
from requests import Response
from .._constant import ALLOWED_METHODS
from .._util import (
    perform_request
    )
from .._auth_object import UberInterface
from .._result import Result
from .._util import (
    handle_body_payload_ids,
    scrub_target,
    handle_container_operations,
    uber_request_keywords
    )
from .._error import (
    InvalidOperation,
    InvalidMethod,
    TokenNotSpecified,
    SDKError,
    APIError
    )


def command_error_handler(func: Callable):
    """Uber class error handling wrapper.

    This method wraps the Uber Class command method and catches errors
    during processing of the selected operation. If logging is enabled
    then the error or warning log will be updated accordingly. Regardless
    of log settings, this method will craft the error response returned
    based upon the result property of the SDKError derivative.

    Defined here to prevent weirdness in the wrapper behavior.
    """
    @functools.wraps(func)
    def wrapper(caller, *args, **kwargs) -> Union[Dict[str, Union[str, int, dict]], bytes, Result, Response]:
        """Inner wrapper."""
        def log_failure(msg, code: int, res: dict = None):
            if caller.log:
                caller.log.error(msg)
                # Warnings shouldn't generate result payloads
                caller.log.debug("STATUS CODE: %i", code)
                caller.log.debug("RESULT: %s", res)
        try:
            result = func(caller, *args, **kwargs)
        except APIError as api_error:
            # Should only receive this in pythonic mode
            raise api_error
        except (SDKError, InvalidMethod, InvalidOperation) as bad_sdk:
            result = bad_sdk.result
            log_failure(bad_sdk.message, bad_sdk.code, result)
        return result
    return wrapper


class APIHarnessV2(UberInterface):
    """The FalconPy Uber Class, enhanced version.

    The Uber Class inherits from the UberInterface class, which is a stand alone
    class that encapsulates the FalconAuth class. This allows the Uber Class to
    inherit all the functionality from the FalconAuth class while maintaining
    additional functionality only provided by the Uber Class.

    This means the Uber Class does not include an auth_object, as it is one.
    As of FalconPy v1.3.0, Object Authentication is still unssupported for
    Uber Class usage scenarios.

    This one does it all. It's like the One Ring with significantly fewer orcs.
    """

    #                                 `-.
    #                     -._ `. `-.`-. `-.
    #                     _._ `-._`.   .--.  `.
    #                  .-'   '-.  `-|\/    \|   `-.
    #                .'         '-._\   (o)O) `-.
    #               /         /         _.--.) '. `-. `-.
    #              /|    (    |  /  -. ( -._( -._ '. '.
    #             /  \    \-.__\ \_.-'`.`.__' .  `-, '. .'
    #             |  /\    |  / \ \     `--'  /  .-'.'.'
    #          .._/  /  /  /  / / \ \          .' . .' .'
    #         /  ___/  |  /   \ \  \ \__       '.'. . .
    #         \  \___  \ (     \ \  `._ `.     .' . ' .'
    #          \ `-._\ (  `-.__ | \    )//   .'  .' .-'
    #           \_-._\  \  `-._\)//    ""_.-' .-' .' .'
    #             `-'    \ -._\ ""_..--''  .-' .'
    #                     \/    .' .-'.-'  .-' .-'
    #                         .-'.' .'  .' .-
    # pylint: disable=R0912
    @command_error_handler
    def command(self, *args, **kwargs) -> Union[Dict[str, Union[str, int, dict]], bytes, Result, Response]:
        """Uber Class API command method.

        Performs the specified API operation. The token will be generated
        if it is not present or expired before the request is made.

        HTTP Method: Any

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html

        Keyword arguments
        ----
        api_operation : str (Default: None)
            API Operation ID to perform
            Please note: The keyword "action" will also be accepted but
            may collide with operation parameters and is not recommended.
        parameters : dict (Default: {})
            Parameter payload (Query string)
        body : dict (Default: {})
            Body payload (Body)
        data : dict (Default: {})
            Data payload (Data)
        headers : dict (Default: {})
            Headers dictionary (HTTP Headers)
        ids : list or str (Default: None)
            ID list (IDs to handle)
        partition : int or str (Default: None)
            Partition number (Event Streams only)
        distinct_field : str (Default: None)
            Distinct Field (Sensor Update Policy only)
        override : str (Default: None)
            Override method and endpoint. Example: 'METHOD,ENDPOINT'
        action_name : str (Default: None)
            Action to perform (API specific)
        files : list (Default: [])
            List of files to upload
        file_name : str (Default: None)
            Name of the file to upload
        content_type : str (Default: None)
            Content_Type HTTP header
        expand_result : bool (Default: False)
            Request expanded results (returns a tuple)
        image_id : str (Default: None)
            Container image ID (Falcon Container only)
        stream : bool (Default: False)
            Enable streaming download

        Arguments
        ----
        The first argument passed to this method is assumed to be 'api_operation'. All others are ignored.

        Returns
        ----
        dict or bytes
            Dictionary or binary object containing API response depending on requested operation.
        """
        # Issue #1161 - operation is specified using the action keyword
        if kwargs.get("action", None) and not kwargs.get("api_operation", None):
            kwargs["api_operation"] = kwargs.get("action")
        try:
            if not kwargs.get("api_operation", None):
                # Assume they're passing it in as the first argument.
                kwargs["api_operation"] = args[0]
        except IndexError:
            pass  # They didn't specify an action, try for an override instead.
        uber_command = [a for a in self.commands if a[0] == kwargs.get("api_operation", None)]
        if kwargs.get("override", None):
            uber_command = [["Manual"] + kwargs["override"].split(",")]
        if uber_command:
            # Which API operation to perform.
            operation = uber_command[0][0]
            # Which HTTP method to execute
            method = uber_command[0][1].upper()
            # Check the headers. If we've not logged in yet, this will force our base_url
            # to point to the correct cloud region.
            _ = self.auth_headers
            # Retrieve our base URL and alter keywords if we are performing a container operation.
            kwargs, url_base, container = handle_container_operations(kwargs, self.base_url)
            # Retrieve the endpoint from the command list and append to our base URL and
            # then perform any outstanding string replacements on the target endpoint URL.
            target = scrub_target(operation, f"{url_base}{uber_command[0][2]}", kwargs)
            # Handle any IDs that are in the wrong payload
            kwargs = handle_body_payload_ids(kwargs)
            # Enable streaming if requested
            stream = kwargs.get("stream", False)
            # Only accept allowed HTTP methods
            if method in ALLOWED_METHODS:
                if operation == "oauth2AccessToken":
                    # Calling the token generation operation directly from the
                    # Uber Class does not change the underlying auth_object state.
                    returned = self._login_handler(stateful=False)  # .             CrowdStrike
                elif operation == "oauth2RevokeToken":              # .                  O   Rocks
                    # Calling the token revocation operation directly requires a        <|\
                    # token_value. Doing so in this manner from the Uber Class          (o-"=
                    # does not change the underlying authentication state.              / \
                    token_value = kwargs.get("token_value", None)
                    if not token_value:
                        raise TokenNotSpecified
                    returned = self._logout_handler(token_value=token_value, stateful=False)
                else:
                    # Craft our keyword payload for perform_request.
                    keyword_payload = uber_request_keywords(
                        self, method, operation, target, kwargs, container, stream
                        )
                    # Log the operation we're performing if enabled.
                    if self.log:
                        self.log.debug("OPERATION: %s", operation)
                    # Process the API request normally.
                    returned = perform_request(**keyword_payload)
            else:
                # Bad HTTP method.
                raise InvalidMethod
        else:
            # That command doesn't exist, have a cup of tea instead.
            raise InvalidOperation

        return returned
