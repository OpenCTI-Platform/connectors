"""CrowdStrike Falcon ContentUpdatePolicies API interface class.

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
from ._payload import content_update_policy_action_payload, generic_payload_list, content_update_policy_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._content_update_policies import _content_update_policies_endpoints as Endpoints


class ContentUpdatePolicies(ServiceClass):
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
    def query_policy_members_combined(self: object,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for members of a Content Update Policy in your environment by providing an FQL filter and paging details.

        Returns a set of host details which match the filter criteria.

        Keyword arguments:
        id -- The ID of the Content Update Policy to search for members of. String.
        filter -- The filter expression that should be used to limit the results. String.
        offset -- The offset to start retrieving records from. Integer.
        limit -- The maximum records to return. Integer. [1-5000]
        sort -- The property to sort by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /content-update-policies/queryCombinedContentUpdatePolicyMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedContentUpdatePolicyMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policies_combined(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Content Update Policies in your environment by providing an FQL filter and paging details.

        Returns a set of Content Update Policies which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
        offset -- The offset to start retrieving records from. Integer.
        limit -- The maximum records to return. Integer. [1-5000]
        sort -- The property to sort by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /content-update-policies/queryCombinedContentUpdatePolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedContentUpdatePolicies",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def perform_action(self: object,
                       body: dict = None,
                       parameters: dict = None,
                       **kwargs
                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform the specified action on the Content Update Policies specified in the request.

        Keyword arguments:
        action_name -- The action to perform. String.
                       Allowed actions:
                        add-host-group      override-revert
                        disable             remove-host-group
                        enable              remove-pinned-content-version
                        override-allow      set-pinned-content-version
                        override-pause
        action_parameters -- Action specific parameter options. Dictionary or list of dictionaries.
                             {
                                 "name": "string",
                                 "value": "string"
                             }
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
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
        ids -- Content Update policy IDs to perform action against. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /content-update-policies/performContentUpdatePoliciesAction
        """
        if not body:
            body = content_update_policy_action_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="performContentUpdatePoliciesAction",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def set_precedence(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Set the precedence of Content Update Policies based on the order of IDs specified in the request.

        The first ID specified will have the highest precedence and the last ID specified will have the lowest.
        You must specify all non-Default Policies when updating precedence.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
        ids -- ID list in precedence order. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /content-update-policies/setContentUpdatePoliciesPrecedence
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="setContentUpdatePoliciesPrecedence",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a set of Content Update Policies by specifying their IDs.

        Keyword arguments:
        ids -- The IDs of the Content Update Policies to return. String or list of dictionaries.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/content-update-policies/getContentUpdatePolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getContentUpdatePolicies",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Content Update Policies by specifying details about the policy to create.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "description": "string",
                            "name": "string",
                            "settings": {
                                "ring_assignment_settings": [
                                    {
                                        "delay_hours": "string",
                                        "id": "string",
                                        "ring_assignment": "string"
                                    }
                                ]
                            }
                        }
                    ]
                }
        description -- Content update policy description. String.
        name -- Content update policy name. String.
        settings -- Content update policy settings. Dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/content-update-policies/createContentUpdatePolicies
        """
        if not body:
            body = content_update_policy_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createContentUpdatePolicies",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Content Update Policies by specifying the ID of the policy and details to update.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "description": "string",
                            "id": "string",
                            "name": "string",
                            "settings": {
                                "ring_assignment_settings": [
                                    {
                                        "delay_hours": "string",
                                        "id": "string",
                                        "ring_assignment": "string"
                                    }
                                ]
                            }
                        }
                    ]
                }
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/content-update-policies/updateContentUpdatePolicies
        """
        if not body:
            body = content_update_policy_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateContentUpdatePolicies",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a set of Content Update Policies by specifying their IDs.

        Keyword arguments:
        ids -- The IDs of the Content Update Policies to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/content-update-policies/deleteContentUpdatePolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteContentUpdatePolicies",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policy_members(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for members of a Content Update Policy in your environment by providing an FQL filter and paging details.

        Returns a set of Agent IDs which match the filter criteria.

        Keyword arguments:
        id -- The ID of the Content Update Policy to search for members of. String.
        filter -- The filter expression that should be used to limit the results. String.
        offset -- The offset to start retrieving records from. Integer.
        limit -- The maximum records to return. Integer. [1-5000]
        sort -- The property to sort by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /content-update-policies/queryContentUpdatePolicyMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryContentUpdatePolicyMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_pinnable_content_versions(self: object,
                                        parameters: dict = None,
                                        **kwargs
                                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for content versions available for pinning given the category.

        Keyword arguments:
        category -- Content category. String.
                    Allowed values:
                        rapid_response_al_bl_listing    system_critical
                        sensor_operations               vulnerability_management
        sort -- Value to sort returned content versions by.
                Allowed values: deployed_timestamp
                Default: deployed_timestamp.desc
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/content-update-policies/queryPinnableContentVersions
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryPinnableContentVersions",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Content Update Policies in your environment by providing an FQL filter and paging details.

        Returns a set of Content Update Policy IDs which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
        offset -- The offset to start retrieving records from. Integer.
        limit -- The maximum records to return. Integer. [1-5000]
        sort -- The property to sort by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/content-update-policies/queryContentUpdatePolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryContentUpdatePolicies",
            keywords=kwargs,
            params=parameters
            )

    queryCombinedContentUpdatePolicyMembers = query_policy_members_combined
    queryCombinedContentUpdatePolicies = query_policies_combined
    performContentUpdatePoliciesAction = perform_action
    setContentUpdatePoliciesPrecedence = set_precedence
    getContentUpdatePolicies = get_policies
    createContentUpdatePolicies = create_policies
    updateContentUpdatePolicies = update_policies
    deleteContentUpdatePolicies = delete_policies
    queryContentUpdatePolicyMembers = query_policy_members
    queryPinnableContentVersions = query_pinnable_content_versions
    queryContentUpdatePolicies = query_policies
