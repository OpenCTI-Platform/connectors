"""CrowdStrike Falcon Firewall Policy API interface class.

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
from ._util import process_service_request, generate_error_result, force_default
from ._util import args_to_params, handle_single_argument
from ._payload import generic_payload_list, firewall_policy_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._firewall_policies import _firewall_policies_endpoints as Endpoints


class FirewallPolicies(ServiceClass):
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
    def query_combined_policy_members(self: object,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for members of a Firewall Policy in your environment by providing an FQL filter and paging details.

        Returns a set of host details which match the filter criteria.

        Keyword arguments:
        id -- The ID of the Firewall Policy to search for members of
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/queryCombinedFirewallPolicyMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedFirewallPolicyMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_combined_policies(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Firewall Policies in your environment by providing an FQL filter and paging details.

        Returns a set of Firewall Policies which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (value.asc, value.desc)
                Available values:
                created_by              modified_timestamp
                created_timestamp       name
                enabled                 platform_name
                modified_by             precedence

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/queryCombinedFirewallPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedFirewallPolicies",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def perform_action(self: object,
                       body: dict = None,
                       parameters: dict = None,
                       **kwargs
                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform the specified action on the Firewall Policies specified in the request.

        Keyword arguments:
        action_name -- action to perform: 'add-host-group', 'disable', 'enable',
                       'add-rule-group', 'remove-rule-group' or 'remove-host-group'.
        action_parameters -- Action specific parameter options. List of dictionaries.
                             {
                                 "name": "string",
                                 "value": "string"
                             }
        body -- full body payload, not required if keywords are used.
                {
                    "action_parameters": [
                        {
                            "name": "string",
                            "value": "string"
                        }
                    ],
                    "ids": [
                        "string"
                    ]
                }
        group_id -- Host Group ID to apply the policy to. String.
                    Overridden if action_parameters is specified.
        ids -- Firewall policy ID(s) to perform actions against. String or list of strings.
        parameters - full parameters payload, not required if action_name is provided as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/performFirewallPoliciesAction
        """
        _allowed_actions = ['add-host-group', 'disable', 'enable', 'remove-host-group',
                            'add-rule-group', 'remove-rule-group'
                            ]
        operation_id = "performFirewallPoliciesAction"
        parameter_payload = args_to_params(parameters, kwargs, Endpoints, operation_id)
        action_name = parameter_payload.get("action_name", "Not Specified")
        if action_name.lower() in _allowed_actions:
            if not body:
                body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
                if kwargs.get("group_id", None):
                    body["action_parameters"] = [{
                        "name": "group_id",
                        "value": kwargs.get("group_id", None)
                    }]
                # Passing an action_parameters list will override the group_id keyword
                if kwargs.get("action_parameters", None):
                    body["action_parameters"] = kwargs.get("action_parameters", None)

            returned = process_service_request(
                            calling_object=self,
                            endpoints=Endpoints,
                            operation_id=operation_id,
                            keywords=kwargs,
                            params=parameters,
                            body=body
                            )
        else:
            returned = generate_error_result("Invalid value specified for action_name parameter.")

        return returned

    @force_default(defaults=["body"], default_types=["dict"])
    def set_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Set the precedence of Firewall Policies based on the order of IDs specified in the request.

        The first ID specified will have the highest precedence and the last ID specified
        will have the lowest. You must specify all non-Default Policies for a platform when
        updating precedence.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "ids": [
                        "string"
                    ],
                    "platform_name": "Windows"
                }
        ids -- Firewall policy ID(s) to perform actions against. String or list of strings.
        platform_name -- OS platform name.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/setFirewallPoliciesPrecedence
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
            if kwargs.get("platform_name", None):
                body["platform_name"] = kwargs.get("platform_name", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="setFirewallPoliciesPrecedence",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a set of Firewall Policies by specifying their IDs.

        Keyword arguments:
        ids -- List of Firewall Policy IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/getFirewallPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getFirewallPolicies",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def create_policies(self: object,
                        body: dict = None,
                        parameters: dict = None,
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Firewall Policies by specifying details about the policy to create.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "resources": [
                        {
                            "clone_id": "string",
                            "description": "string",
                            "name": "string",
                            "platform_name": "Windows",
                        }
                    ]
                }
        clone_id -- ID of the Firewall Policy to clone. String.
        description -- Firewall Policy description. String.
        name -- Firewall Policy name. String.
        platform_name -- Name of the operating system platform. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/createFirewallPolicies
        """
        if not body:
            body = firewall_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createFirewallPolicies",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a set of Firewall Policies by specifying their IDs.

        Keyword arguments:
        ids -- List of Firewall Policy IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/deleteFirewallPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteFirewallPolicies",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Firewall Policies by specifying the ID of the policy and details to update.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                "resources": [
                    {
                        "id": "string",
                        "description": "string",
                        "name": "string"
                    }
                ]
            }
        id -- ID of the Device Control Policy to update. String.
        description -- Device Control Policy description. String.
        name -- Device Control Policy name. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/updateFirewallPolicies
        """
        if not body:
            body = firewall_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateFirewallPolicies",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policy_members(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for members of a Firewall Policy in your environment by providing an FQL filter and paging details.

        Returns a set of Agent IDs which match the filter criteria.

        Keyword arguments:
        id -- The ID of the Device Control Policy to search for members of
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/queryFirewallPolicyMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryFirewallPolicyMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Firewall Policies in your environment by providing an FQL filter and paging details.

        Returns a set of Firewall Policy IDs which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax.
                created_by                      modified_timestamp
                created_timestamp               name
                enabled                         platform_name
                modified_by                     precedence

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies/queryFirewallPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryFirewallPolicies",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    queryCombinedFirewallPolicyMembers = query_combined_policy_members
    queryCombinedFirewallPolicies = query_combined_policies
    performFirewallPoliciesAction = perform_action
    perform_policies_action = perform_action
    setFirewallPoliciesPrecedence = set_policies
    set_policies_precedence = set_policies
    getFirewallPolicies = get_policies
    createFirewallPolicies = create_policies
    deleteFirewallPolicies = delete_policies
    updateFirewallPolicies = update_policies
    queryFirewallPolicyMembers = query_policy_members
    queryFirewallPolicies = query_policies


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Firewall_Policies = FirewallPolicies  # pylint: disable=C0103
