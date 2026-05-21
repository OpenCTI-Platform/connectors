"""CrowdStrike Falcon Deployments API interface class.

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
from ._util import force_default, process_service_request, handle_single_argument
from ._payload import generic_payload_list
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._deployments import _deployments_endpoints as Endpoints


class Deployments(ServiceClass):
    """The only requirement to instantiate an instance of this class is one of the following.

    - a valid client_id and client_secret provided as keywords.
    - a credential dictionary with client_id and client_secret containing valid API credentials
      {
          "client_id": "CLIENT_ID_HERE",
          "client_secret": "CLIENT_SECRET_HERE"
      }
    - a previously-authenticated instance of the authentication service class (oauth2.py)
    - a valid token provided by the authentication service class (oauth2.py)
    """

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_release_notes(self: object,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for release-notes resources and returns details.

        Keyword arguments:
        filter -- FQL query specifying filter parameters. String.
        limit -- Maximum number of records to return. Integer.
        offset -- Starting pagination offset of records to return. Integer.
        sort -- Sort items by providing a comma separated list of property and direction (eg name.desc,time.asc). String.
                If direction is omitted, defaults to descending.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/release-notes/CombinedReleaseNotesV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedReleaseNotesV1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_deployments(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get deployment resources by IDs.

        Keyword arguments:
        ids -- Release version IDs to retrieve deployment details. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/deployments/GetDeploymentsExternalV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetDeploymentsExternalV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_releases(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for releases resources and returns details.

        Keyword arguments:
        filter -- FQL query specifying filter parameters. String.
        limit -- Maximum number of records to return. Integer.
        offset -- Starting pagination offset of records to return. Integer.
        sort -- Sort items by providing a comma separated list of property and direction (eg name.desc,time.asc).
                If direction is omitted, defaults to descending. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/releases/CombinedReleasesV1Mixin0
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedReleasesV1Mixin0",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_release_notes_v1(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the release notes for the IDs in the request.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required when using other keywords.
                {
                    "IDs": [
                        "string"
                    ]
                }
        ids -- Release note IDs to be retrieve. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/release-notes/GetEntityIDsByQueryPOST
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
            body["IDs"] = body["ids"]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetEntityIDsByQueryPOST",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_release_notes(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the release notes for the IDs in the request.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required when using other keywords.
                {
                    "IDs": [
                        "string"
                    ]
                }
        ids -- Release note IDs to be retrieve. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/release-notes/GetEntityIDsByQueryPOSTV2
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
            body["IDs"] = body["ids"]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetEntityIDsByQueryPOSTV2",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_release_note_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for release-notes resources and returns IDs.

        Keyword arguments:
        filter -- FQL query specifying filter parameters. String.
        limit -- Maximum number of records to return. Integer.
        offset -- Starting pagination offset of records to return. Integer.
        sort -- Sort items by providing a comma separated list of property and direction (eg name.desc,time.asc). String.
                If direction is omitted, defaults to descending.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/release-notes/QueryReleaseNotesV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryReleaseNotesV1",
            keywords=kwargs,
            params=parameters
            )

    CombinedReleaseNotesV1 = query_release_notes
    GetDeploymentsExternalV1 = get_deployments
    CombinedReleasesV1Mixin0 = query_releases
    GetEntityIDsByQueryPOST = get_release_notes_v1
    GetEntityIDsByQueryPOSTV1 = get_release_notes_v1
    GetEntityIDsByQueryPOSTV2 = get_release_notes
    QueryReleaseNotesV1 = query_release_note_ids
