"""CrowdStrike Falcon Host Groups API interface class.

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
from ._util import generate_error_result, force_default, args_to_params
from ._util import handle_single_argument, process_service_request
from ._payload import host_group_create_payload, host_group_update_payload
from ._payload import generic_payload_list
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._host_group import _host_group_endpoints as Endpoints


class HostGroup(ServiceClass):
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
    def query_combined_group_members(self: object,
                                     parameters: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for members of a Host Group in your environment.

        Provide a FQL filter and paging details.

        Returns a set of host details which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  An asterisk wildcard '*' includes all results.

        id -- The ID of the Host Group to search for members of. String
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. name|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/queryCombinedGroupMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedGroupMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_combined_host_groups(self: object,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Host Groups in your environment by providing an FQL filter and paging details.

        Returns a set of Host Groups which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  An asterisk wildcard '*' includes all results.
                  Available filter fields:
                  created_by                      modified_by
                  created_timestamp               modified_timestamp
                  group_type                      name
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. created_timestamp|asc).
                Available sort fields:
                created_by                      modified_by
                created_timestamp               modified_timestamp
                group_type                      name

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/queryCombinedHostGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedHostGroups",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def perform_group_action(self: object,
                             body: dict = None,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform the specified action on the Host Groups specified in the request.

        Keyword arguments:
        action_name -- Action to perform on the host group. String.
                       Allowed values: 'add-hosts' or 'remove-hosts'.
        action_parameters - List of dictionaries containing action specific parameter settings.
        body -- full body payload, not required when using other keywords.
                {
                    "action_parameters": [
                        {
                            "name": "filter",
                            "value": "string"
                        }
                    ],
                    "ids": [
                        "string"
                    ]
                }
        disable_hostname_check -- Disables hostname checking before the action. Boolean.
        filter -- Filter to use to specify hosts to apply this action to. FQL formatted string.
                  Overridden if action_parameters is specified.
        ids -- List of host group IDs to perform an action against. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/performGroupAction
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )
            if kwargs.get("filter", None):
                body["action_parameters"] = [{
                    "name": "filter",
                    "value": kwargs.get("filter", None)
                }]
            # Passing an action_parameters list will override the filter keyword
            if kwargs.get("action_parameters", None):
                body["action_parameters"] = kwargs.get("action_parameters", None)

        _allowed_actions = ['add-hosts', 'remove-hosts']
        operation_id = "performGroupAction"
        parameter_payload = args_to_params(parameters, kwargs, Endpoints, operation_id)
        if parameter_payload.get("action_name", "Not Specified").lower() in _allowed_actions:
            returned = process_service_request(
                            calling_object=self,
                            endpoints=Endpoints,
                            operation_id=operation_id,
                            body=body,
                            keywords=kwargs,
                            params=parameters
                            )
        else:
            returned = generate_error_result("Invalid value specified for action_name parameter.")

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_host_groups(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a set of Host Groups by specifying their IDs.

        Keyword arguments:
        ids -- List of host group IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/getHostGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getHostGroups",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_host_groups(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Host Groups by specifying details about the group to create.

        Keyword arguments:
        assignment_rule -- Assignment rule to apply. String.
        body -- full body payload, not required when using other keywords.
                {
                    "resources": [
                        {
                            "assignment_rule": "string",
                            "description": "string",
                            "group_type": "static",
                            "name": "string"
                        }
                    ]
                }
        description -- Description of the host group. String.
        group_type -- Type of Host Group to create. String.
        name -- The Host Group name. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/createHostGroups
        """
        if not body:
            body = host_group_create_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createHostGroups",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_host_groups(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a set of Host Groups by specifying their IDs.

        Keyword arguments:
        ids -- List of host group IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/deleteHostGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteHostGroups",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_host_groups(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Host Groups by specifying the ID of the group and details to update.

        Keyword arguments:
        assignment_rule -- Assignment rule to apply. String.
        body -- full body payload, not required when using other keywords.
                {
                    "resources": [
                        {
                            "assignment_rule": "string",
                            "description": "string",
                            "id": "string",
                            "name": "string"
                        }
                    ]
                }
        description -- Description of the host group. String.
        id -- Host Group ID to be updated. String.
        name -- The Host Group name. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/updateHostGroups
        """
        if not body:
            body = host_group_update_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateHostGroups",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_group_members(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for members of a Host Group in your environment.

        Provide a FQL filter and paging details.

        Returns a set of Agent IDs which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  An asterisk wildcard '*' includes all results.
        id -- The ID of the Host Group to search for members of. String.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. name|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/queryGroupMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryGroupMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_host_groups(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Host Groups in your environment by providing an FQL filter and paging details.

        Returns a set of Host Group IDs which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  An asterisk wildcard '*' includes all results.
                  Available filter fields:
                  created_by                      modified_by
                  created_timestamp               modified_timestamp
                  group_type                      name
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. created_timestamp|asc).
                Available sort fields:
                created_by                      modified_by
                created_timestamp               modified_timestamp
                group_type                      name

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group/queryHostGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryHostGroups",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    queryCombinedGroupMembers = query_combined_group_members
    queryCombinedHostGroups = query_combined_host_groups
    performGroupAction = perform_group_action
    getHostGroups = get_host_groups
    createHostGroups = create_host_groups
    deleteHostGroups = delete_host_groups
    updateHostGroups = update_host_groups
    queryGroupMembers = query_group_members
    queryHostGroups = query_host_groups


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Host_Group = HostGroup  # pylint: disable=C0103
