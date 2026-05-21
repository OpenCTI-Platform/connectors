"""Falcon IOA Exclusions API Interface Class.

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
from ._util import force_default, handle_single_argument, process_service_request
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._ioa_exclusions import _ioa_exclusions_endpoints as Endpoints
from ._payload import ioa_exclusion_payload


class IOAExclusions(ServiceClass):
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
        """Get a set of IOA Exclusions by specifying their IDs.

        Keyword arguments:
        ids -- List of exclusion IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions/getIOAExclusionsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getIOAExclusionsV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_exclusions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create the IOA exclusions.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
            {
                "cl_regex": "string",
                "comment": "string",
                "description": "string",
                "detection_json": "string",
                "groups": [
                    "string"
                ],
                "ifn_regex": "string",
                "name": "string",
                "pattern_id": "string",
                "pattern_name": "string"
            }
        cl_regex -- string
        comment -- String comment describing why the exclusion is entered.
        description --
        detection_json --
        groups -- Group IDs to exclude. List of strings.
        ifn_regex --
        name --
        pattern_id --
        pattern_name --

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions/createIOAExclusionsV1
        """
        if not body:
            body = ioa_exclusion_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createIOAExclusionsV1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_exclusions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete the IOA Exclusions by ID.

        Keyword arguments:
        comment -- Explains why this exclusions was deleted. String.
        ids -- List of exclusion IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions/deleteIOAExclusionsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteIOAExclusionsV1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_exclusions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update the IOA Exclusions.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
            {
                "cl_regex": "string",
                "comment": "string",
                "description": "string",
                "detection_json": "string",
                "groups": [
                    "string"
                ],
                "id": "string",
                "ifn_regex": "string",
                "name": "string",
                "pattern_id": "string",
                "pattern_name": "string"
            }
        cl_regex -- string
        comment -- String comment describing why the exclusion is entered.
        description --
        detection_json --
        groups -- Group IDs to exclude. List of strings.
        id --
        ifn_regex --
        name --
        pattern_id --
        pattern_name --

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions/updateIOAExclusionsV1

        """
        if not body:
            body = ioa_exclusion_payload(passed_keywords=kwargs)
            if kwargs.get("id", None):
                body["id"] = kwargs.get("id", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateIOAExclusionsV1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_exclusions(self: object,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for IOA Exclusions.

        Keyword arguments:
        cl_regex -- The cl_regex expression to filter exclusions by, used alongside expressions
                    specified in the filter query parameter.
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  The filter expression that should be used to limit the results.
                  Filtered queries involving regex fields should specify their expressions in the
                  'ifn_regex' and 'cl_regex' parameters.
                  An asterisk wildcard '*' includes all results.
                  AVAILABLE FILTERS
                  applied_globally            last_modified
                  created_by                  modified_by
                  created_on                  value
                  name                        pattern
        ifn_regex -- The ifn_regex expression to filter exclusions by, used alongside expressions
                     specified in the filter query parameter. String.
        limit -- The maximum number of exclusions to return in this response.
                 [Integer, default: 100; max: 500]
                 Use with the offset parameter to manage pagination of results.
        offset -- The first exclusion to return, where 0 is the latest exclusion.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. last_behavior|asc).
                Available sort fields:
                applied_globally            last_modified
                created_by                  modified_by
                created_on                  value
                name                        pattern

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions/queryIOAExclusionsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryIOAExclusionsV1",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    getIOAExclusionsV1 = get_exclusions
    createIOAExclusionsV1 = create_exclusions
    deleteIOAExclusionsV1 = delete_exclusions
    updateIOAExclusionsV1 = update_exclusions
    queryIOAExclusionsV1 = query_exclusions


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
IOA_Exclusions = IOAExclusions  # pylint: disable=C0103
