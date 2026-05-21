"""CrowdStrike Falcon Image Assessment Policies API interface class.

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
from ._payload import image_policy_payload, image_exclusions_payload, image_group_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._image_assessment_policies import _image_assessment_policies_endpoints as Endpoints


class ImageAssessmentPolicies(ServiceClass):
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

    def read_policies(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get all Image Assessment policies.

        This method does not accept keyword arguments.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/ReadPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPolicies"
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Image Assessment policies.

        Keyword arguments:
        body -- Full body payload, not required when using other arguments.
                {
                    "description": "string",
                    "name": "string"
                }
        description -- Policy description. String.
        name -- Policy name. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/CreatePolicies
        """
        if not body:
            body = image_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreatePolicies",
            body=body
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_policies(self: object,
                        body: dict = None,
                        parameters: dict = None,
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Image Assessment Policy entities.

        Keyword arguments:
        id -- Image Assessment Policy entity UUID
        body -- Full body payload in JSON format. Not required when using other keywords.
        {
            "description": "string",
            "is_enabled": boolean,
            "name": "string",
            "policy_data": {
                "rules": [
                    {
                        "action": "string",
                        "policy_rules_data": {
                            "conditions": [
                                {}
                            ]
                        }
                    }
                ]
            }
        }
        description -- Policy description. String.
        is_enabled -- Flag indicating if the policy is enabled. Boolean.
        name -- Policy name. String.
        policy_data -- Policy detail in JSON format. Dictionary.
        rules -- List of rules for the policy. List of dictionaries or a single dictionary.
                 Overridden if policy_data is supplied.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/UpdatePolicies
        """
        if not body:
            body = image_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdatePolicies",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policy(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete Image Assessment Policy by policy UUID.

        Keyword arguments:
        id -- Image Assessment Policy entity UUID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/DeletePolicy
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeletePolicy",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    def read_policy_exclusions(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Image Assessment Policy Exclusion entities.

        This method does not accept keyword arguments.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/ReadPolicyExclusions
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPolicyExclusions"
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policy_exclusions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Image Assessment Policy Exclusion entities.

        Keyword arguments:
        body -- Full body payload in JSON format, not required if using other keywords.
        {
            "conditions": [
                {
                    "description": "string",
                    "prop": "string",
                    "ttl": 0,
                    "value": [
                        "string"
                    ]
                }
            ]
        }
        conditions -- List of conditions to apply to the exclusion policy. List of dictionaries.
        description -- Condition description. Ignored if conditions list is provided. String.
        prop -- Condition property. Ignored if conditions list is provided. String.
        ttl -- Condition time to live. Ignored if conditions list is provided. Integer.
        value -- Condition values. Ignored if conditions list is provided. List of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/UpdatePolicyExclusions
        """
        if not body:
            body = image_exclusions_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdatePolicyExclusions",
            body=body
            )

    def read_policy_groups(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Image Assessment Policy Group entities.

        This method does not accept keyword arguments.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/ReadPolicyGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPolicyGroups"
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policy_groups(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Image Assessment Policy Group entities.

        Keyword arguments:
        body -- Full body payload in JSON format, not required whe using other keywords.
                {
                    "description": "string",
                    "name": "string",
                    "policy_group_data": {
                        "conditions": [
                            {}
                        ]
                    },
                    "policy_id": "string"
                }
        conditions -- List of policy conditions to apply. Dictionary or list of dictionaries.
                      Overridden if policy_group_data is supplied.
        description -- Policy group description. String.
        name -- Policy group name. String.
        policy_group_data -- Policy group conditions. Dictionary.
        policy_id -- Policy ID to update. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/CreatePolicyGroups
        """
        if not body:
            body = image_group_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreatePolicyGroups",
            body=body
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_policy_groups(self: object,
                             body: dict = None,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Image Assessment Policy Group entities.

        Keyword arguments:
        body -- Full body payload in JSON format, not required when using other keywords.
                {
                    "description": "string",
                    "name": "string",
                    "policy_group_data": {
                        "conditions": [
                            {}
                        ]
                    }
                }
        conditions -- List of policy conditions to apply. Dictionary or list of dictionaries.
                      Overridden if policy_group_data is supplied.
        description -- Policy group description. String.
        id -- Policy Image Group entity UUID. String.
        name -- Policy group name. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        policy_group_data -- List of policy conditions. Dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/UpdatePolicyGroups
        """
        if not body:
            body = image_group_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdatePolicyGroups",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policy_group(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete Image Assessment Policy Group entities.

        Keyword arguments:
        id -- Policy Image Group entity UUID
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/DeletePolicyGroup
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeletePolicyGroup",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policy_precedence(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Image Assessment Policy precedence.

        Keyword arguments:
        body -- Full body payload in JSON format, not required when using other keywords.
                {
                    "precedence": [
                        "string"
                    ]
                }
        precedence -- List of policy IDs in precedence order. String or List of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/image-assessment-policies/UpdatePolicyPrecedence
        """
        if not body:
            prec = kwargs.get("precedence", None)
            if isinstance(prec, str):
                prec = prec.split(",")
            if prec:
                body["precedence"] = prec

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdatePolicyPrecedence",
            body=body
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here
    # for backwards compatibility / ease of use purposes
    ReadPolicies = read_policies
    CreatePolicies = create_policies
    UpdatePolicies = update_policies
    DeletePolicy = delete_policy
    ReadPolicyExclusions = read_policy_exclusions
    UpdatePolicyExclusions = update_policy_exclusions
    ReadPolicyGroups = read_policy_groups
    CreatePolicyGroups = create_policy_groups
    UpdatePolicyGroups = update_policy_groups
    DeletePolicyGroup = delete_policy_group
    UpdatePolicyPrecedence = update_policy_precedence
