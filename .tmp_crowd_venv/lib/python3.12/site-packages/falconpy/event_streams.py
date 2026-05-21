"""CrowdStrike Falcon Event Stream API interface class.

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
from typing import Dict, Union
from ._util import force_default, process_service_request
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._event_streams import _event_streams_endpoints as Endpoints


class EventStreams(ServiceClass):
    """The only requirement to instantiate an instance of this class is one of the following.

    - a valid client_id and client_secret provided as keywords.
    - a credential dictionary with client_id and client_secret containing valid API credentials
      {
          "client_id": "CLIENT_ID_HERE",
          "client_secret": "CLIENT_SECRET_HERE"
      }
    - a previously-authenticated instance of the authentication service class (oauth2.py)
    - a valid token provided by the authentication service class (OAuth2.token())
    """

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def refresh_active_stream(self: object,
                              partition: int = 0,
                              parameters: dict = None,
                              body: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Refresh an active event stream.

        Use the URL shown in a listAvailableStreamsOAuth2 response.

        Keyword arguments:
        action_name -- Action to perform. Only allowed value is "refresh_active_stream_session".
        app_id -- Label that identifies your connection. Will also accept `appId`.
                  32 character alphanumeric.
        body -- accepted but not used.
        parameters -- full parameters payload, not required if using other keywords.
        partition -- Instance partition to request data for.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/event-streams/refreshActiveStreamSession
        """
        if not kwargs.get("action_name", None):
            parameters["action_name"] = "refresh_active_stream_session"
        if kwargs.get("app_id", None):
            parameters["appId"] = kwargs.get("app_id", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="refreshActiveStreamSession",
            body=body,  # Issue 247 - BODY is passed here even though it is empty
            keywords=kwargs,
            params=parameters,
            partition=partition
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_available_streams(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Discover all event streams in your environment.

        Keyword arguments:
        app_id -- Label that identifies your connection. Will also accept `appId`.
                  32 character alphanumeric.
        format -- format for streaming events. Either 'json' or 'flatjson'.
        parameters -- full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/event-streams/listAvailableStreamsOAuth2
        """
        if kwargs.get("app_id", None):
            parameters["appId"] = kwargs.get("app_id", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="listAvailableStreamsOAuth2",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    refreshActiveStreamSession = refresh_active_stream
    listAvailableStreamsOAuth2 = list_available_streams


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Event_Streams = EventStreams  # pylint: disable=C0103
