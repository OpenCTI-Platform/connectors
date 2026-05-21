"""Falcon Machine Learning Exclusions API Interface Class.

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
from ._payload import exclusion_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._ml_exclusions import _ml_exclusions_endpoints as Endpoints


class MLExclusions(ServiceClass):
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

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_exclusions(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a set of ML Exclusions by specifying their IDs.

        Keyword arguments:
        ids -- List of exclusion IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions/getMLExclusionsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getMLExclusionsV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_exclusions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create the ML exclusions.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
                {
                    "comment": "string",
                    "excluded_from": [
                        "string"
                    ],
                    "groups": [
                        "string"
                    ],
                    "value": "string"
                }
        comment -- String comment describing why the exclusion is entered.
        excluded_from --
        groups -- Group IDs to exclude. List of strings.
        value -- Value to exclude. String

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions/createMLExclusionsV1
        """
        if not body:
            body = exclusion_payload(passed_keywords=kwargs)
        # Issue 1233
        if not body.get("groups"):
            body["groups"] = ["all"]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createMLExclusionsV1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_exclusions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete the ML Exclusions by ID.

        Keyword arguments:
        comment -- Explains why this exclusions was deleted. String.
        ids -- List of exclusion IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions/deleteMLExclusionsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteMLExclusionsV1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def update_exclusions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update the ML Exclusions.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
                {
                    "comment": "string",
                    "groups": [
                        "string"
                    ],
                    "id": "string",
                    "is_descendant_process": boolean,
                    "value": "string"
                }
        comment -- String comment describing why the exclusion is entered.
        groups -- Group IDs to exclude. List of strings.
        id -- Exclusion ID to update. String.
        is_descendant_process -- Flag indicating if this is a descendant process. Boolean.
        value -- Value to exclude. String

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions/updateMLExclusionsV1
        """
        if not body:
            body = exclusion_payload(passed_keywords=kwargs)
        if kwargs.get("id", None):
            body["id"] = kwargs.get("id", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateMLExclusionsV1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_exclusions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for ML Exclusions.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  An asterisk wildcard '*' includes all results.
                  AVAILABLE FILTERS
                  applied_globally            last_modified
                  created_by                  modified_by
                  created_on                  value
        limit -- The maximum number of detections to return in this response.
                 [Integer, default: 100; max: 500]
                 Use with the offset parameter to manage pagination of results.
        offset -- The first detection to return, where 0 is the latest detection.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. last_behavior|asc).
                Available sort fields:
                applied_globally            last_modified
                created_by                  modified_by
                created_on                  value

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions/queryMLExclusionsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryMLExclusionsV1",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    getMLExclusionsV1 = get_exclusions
    createMLExclusionsV1 = create_exclusions
    deleteMLExclusionsV1 = delete_exclusions
    updateMLExclusionsV1 = update_exclusions
    queryMLExclusionsV1 = query_exclusions


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
ML_Exclusions = MLExclusions  # pylint: disable=C0103
