"""CrowdStrike Falcon CloudPolicies API interface class.

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
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._cloud_policies import _cloud_policies_endpoints as Endpoints
from ._payload._cloud_policies import (
    cloud_policies_rule_assign_payload,
    cloud_policies_compliance_control_payload,
    cloud_policies_evaluation_payload,
    cloud_policies_rule_override_payload,
    cloud_policies_rule_create_payload,
    cloud_policies_rule_update_payload
    )


class CloudPolicies(ServiceClass):
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
    def get_rule_input_schema(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get rule input schema for given resource type.

        Keyword arguments:
        domain -- domain. String.
        subdomain -- subdomain. String.
        cloud_provider -- Cloud service provider for the resource type. String.
        resource_type -- Selects the resource type for which to retrieve the rule input schema. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/GetRuleInputSchema
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetRuleInputSchema",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def replace_control_rules(self: object,
                              body: dict = None,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Assign rules to a compliance control (full replace).

        Keyword arguments:
        ids -- The UUID of the compliance control to assign rules to. String or list of strings.
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "rule_ids": [
                        "string"
                    ]
                }
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        rule_ids -- The ids of the rules to replace. List of strings.
        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PUT

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/ReplaceControlRules
        """
        if not body:
            body = cloud_policies_rule_assign_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReplaceControlRules",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_compliance_controls(self: object,
                                *args,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get compliance controls by ID.

        Keyword arguments:
        ids -- The uuids of compliance controls to retrieve. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/GetComplianceControls
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetComplianceControls",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_compliance_control(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new custom compliance control.

        Keyword arguments:
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "description": "string",
                    "framework_id": "string",
                    "name": "string",
                    "section_name": "string"
                }
        description -- The description of hte custom compliance control. String.
        framework_id -- The framework ID of the custom compliance control. String.
        name -- The name of the custom compliance control. String.
        section_name -- The section name of the custom compliance control. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/CreateComplianceControl
        """
        if not body:
            body = cloud_policies_compliance_control_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateComplianceControl",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_compliance_control(self: object,
                                  body: dict = None,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a custom compliance control.

        Keyword arguments:
        ids -- The uuid of compliance control to update. String or list of strings.
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "description": "string",
                    "name": "string"
                }
        description -- The description of hte custom compliance control. String.
        name -- The name of the custom compliance control. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/UpdateComplianceControl
        """
        if not body:
            body = cloud_policies_compliance_control_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateComplianceControl",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_compliance_control(self: object,
                                  *args,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete custom compliance controls.

        Keyword arguments:
        ids -- The uuids of compliance control to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/DeleteComplianceControl
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteComplianceControl",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def rename_section_compliance_framework(self: object,
                                            body: dict = None,
                                            parameters: dict = None,
                                            **kwargs
                                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Rename a section in a custom compliance framework.

        Keyword arguments:
        ids -- The uuid of compliance framework containing the section to rename. String or list of strings.
        sectionName -- The current name of the section to rename. String.
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "section_name": "string"
                }
        section_name -- The new section name of the custom compliance control. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/RenameSectionComplianceFramework
        """
        if not body:
            body = cloud_policies_compliance_control_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RenameSectionComplianceFramework",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_compliance_frameworks(self: object,
                                  *args,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get compliance frameworks by ID.

        Keyword arguments:
        ids -- The uuids of compliance frameworks to retrieve. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/GetComplianceFrameworks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetComplianceFrameworks",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_compliance_framework(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new custom compliance framework.

        Keyword arguments:
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "active": true,
                    "description": "string",
                    "name": "string"
                }
        active -- Value to determine if the compliance framework will be active. Boolean.
        description -- The description of the new compliance framework. String.
        name -- The name of the new compliance framework. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/CreateComplianceFramework
        """
        if not body:
            body = cloud_policies_compliance_control_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateComplianceFramework",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_compliance_framework(self: object,
                                    body: dict = None,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a custom compliance framework.

        Keyword arguments:
        ids -- The uuids of compliance framework to update. String or list of strings.
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "active": true,
                    "description": "string",
                    "name": "string"
                }
        active -- Value to determine if the compliance framework will be active. Boolean.
        description -- The description of the new compliance framework. String.
        name -- The name of the new compliance framework. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/UpdateComplianceFramework
        """
        if not body:
            body = cloud_policies_compliance_control_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateComplianceFramework",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_compliance_framework(self: object,
                                    *args,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a custom compliance framework and all associated controls and rule assignments.

        Keyword arguments:
        ids -- The uuids of compliance framework to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/DeleteComplianceFramework
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteComplianceFramework",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_enriched_asset(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get enriched assets that combine a primary resource with all its related resources.

        Keyword arguments:
        ids -- List of asset IDs (maximum 100 IDs allowed). String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/GetEnrichedAsset
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetEnrichedAsset",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def get_evaluation_result(self: object,
                              body: dict = None,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get evaluation results based on the provided rule.

        Keyword arguments:
        cloud_provider -- Cloud Service Provider of the provided IDs. String.
        resource_type -- Resource Type of the provided IDs. String.
        ids -- List of assets to evaluate (maximum 100 IDs allowed). String or list of strings.
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "input": {},
                    "logic": "string"
                }
        input -- The input for the provided rule. Dictionary.
        logic - The logic of the provided rule. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/GetEvaluationResult
        """
        if not body:
            body = cloud_policies_evaluation_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetEvaluationResult",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rule_override(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a rule override.

        Keyword arguments:
        ids -- The uuids of rule overrides to retrieve. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/GetRuleOverride
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetRuleOverride",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_rule_override(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new rule override.

        Keyword arguments:
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "overrides": [
                        {
                            "comment": "string",
                            "crn": "string",
                            "expires_at": "2025-11-10T21:16:14.315Z",
                            "override_type": "string",
                            "overrides_details": "string",
                            "reason": "string",
                            "rule_id": "string",
                            "target_region": "string"
                        }
                    ]
                }
        overrides -- The new rule override. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/CreateRuleOverride
        """
        if not body:
            body = cloud_policies_rule_override_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateRuleOverride",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_rule_override(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a rule override.

        Keyword arguments:
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "overrides": [
                        {
                            "comment": "string",
                            "crn": "string",
                            "expires_at": "2025-11-10T21:16:14.315Z",
                            "override_type": "string",
                            "overrides_details": "string",
                            "reason": "string",
                            "rule_id": "string",
                            "target_region": "string"
                        }
                    ]
                }
        overrides -- The new rule override. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/UpdateRuleOverride
        """
        if not body:
            body = cloud_policies_rule_override_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateRuleOverride",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_rule_override(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a rule override.

        Keyword arguments:
        ids -- The uuids of rule overrides to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/DeleteRuleOverride
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteRuleOverride",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rule(self: object,
                 *args,
                 parameters: dict = None,
                 **kwargs
                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a rule by id.

        Keyword arguments:
        ids -- The uuids of rules to retrieve. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/GetRule
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetRule",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_rule(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new rule.

        Keyword arguments:
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                For Custom Rule, logic is mandatory and parent_rule_id should not be specified.
                For Managed Rule duplication, parent_rule_id is mandatory and logic should be not specified.
                {
                    "alert_info": "string",
                    "attack_types": "string",
                    "controls": [
                        {
                            "Authority": "string",
                            "Code": "string"
                        }
                    ],
                    "description": "string",
                    "domain": "string",
                    "logic": "string",
                    "name": "string",
                    "parent_rule_id": "string",
                    "platform": "string",
                    "provider": "string",
                    "remediation_info": "string",
                    "remediation_url": "string",
                    "resource_type": "string",
                    "severity": 0,
                    "subdomain": "string"
                }
        alert_info -- The info of the alert. String.
        attack_types -- The type of attacks. String.
        controls -- The authority and code of the rule. List of dictionaries.
        description -- The description of the rule. String.
        domain -- The domain of the rule. String.
        logic -- The logic for the rule. String.
        name -- The name of the rule. String.
        parent_rule_id -- The id of the parent. String.
        platform -- The platform covered by the rule. String.
        provider -- The provider for the rule. String.
        remediation_info -- The remediation info provided by the rule. String.
        remediation_url -- The URL providing the remediation. String.
        resource_type -- The type of the resource. String.
        severity -- The severity level. Integer.
        subdomain -- The subdomain for the rule. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/CreateRuleMixin0
        """
        if not body:
            body = cloud_policies_rule_create_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateRuleMixin0",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_rule(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a rule.

        Keyword arguments:
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "alert_info": "string",
                    "attack_types": [
                            "string"
                    ],
                    "category": "string",
                    "controls": [
                        {
                            "authority": "string",
                            "code": "string"
                        }
                    ],
                    "description": "string",
                    "name": "string",
                    "rule_logic_list": [
                        {
                            "logic": "string",
                            "platform": "string",
                            "remediation_info": "string",
                            "remediation_url": "string"
                        }
                    ],
                    "severity": 0,
                    "uuid": "string"
                }
        alert_info -- The info of the alert. String.
        attack_types -- The type of attacks. List of strings.
        controls -- The authority and code of the rule. List of dictionaries.
        description -- The description of the rule. String.
        name -- The name of the rule. String.
        rule_logic_list -- The logic list data. List of dictionaries.
        severity -- The severity level. Integer.
        uuid -- The uuid of the rule to update. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/UpdateRule
        """
        if not body:
            body = cloud_policies_rule_update_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateRule",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_rule(self: object,
                    *args,
                    parameters: dict = None,
                    **kwargs
                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a rule.

        Keyword arguments:
        ids -- The uuids of rules to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/DeleteRuleMixin0
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteRuleMixin0",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_compliance_controls(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for compliance controls by various parameters.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    compliance_control_name                 compliance_control_authority
                    compliance_control_type 	            compliance_control_section
                    compliance_control_requirement	        compliance_control_benchmark_name
                    compliance_control_benchmark_version
        limit -- The maximum number of resources to return. The maximum allowed is 500. Integer.
        offset -- The number of results to skip before starting to return results. Integer.
        sort -- The sort expression that should be used to sort the results. String.
                Use the '|asc' or '|desc' suffix to specify sort direction.
                Sortable fields:
                    compliance_control_authority	        compliance_control_type
                    compliance_control_section              compliance_control_requirement
                    compliance_control_benchmark_name	    compliance_control_benchmark_version
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/QueryComplianceControls
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryComplianceControls",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_compliance_frameworks(self: object,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for compliance frameworks by various parameters.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    compliance_framework_name       compliance_framework_version
                    compliance_framework_authority
        limit -- The maximum number of resources to return. The maximum allowed is 500.
        offset -- The number of results to skip before starting to return results.
        sort -- The sort expression that should be used to sort the results. String.
                Use the '|asc' or '|desc' suffix to specify sort direction.
                Sortable fields:
                    compliance_framework_name       compliance_framework_version
                    compliance_framework_authority
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/QueryComplianceFrameworks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryComplianceFrameworks",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_rule(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for rules by various parameters.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    rule_origin                         rule_parent_uuid                    rule_name
                    rule_description                    rule_domain                         rule_status
                    rule_severity                       rule_short_code                     rule_service
                    rule_resource_type                  rule_provider                       rule_subdomain
                    rule_auto_remediable                rule_control_requirement            rule_control_section
                    rule_compliance_benchmark           rule_compliance_framework           rule_mitre_tactic
                    rule_mitre_technique                rule_created_at                     rule_updated_at
                    rule_updated_by
        limit -- The maximum number of resources to return. The maximum allowed is 500.
        offset -- The number of results to skip before starting to return results.
        sort -- The sort expression that should be used to sort the results. String.
                Use the '|asc' or '|desc' suffix to specify sort direction.
                Sortable fields:
                  rule_origin                         rule_parent_uuid                    rule_name
                  rule_description                    rule_domain                         rule_status
                  rule_severity                       rule_short_code                     rule_service
                  rule_resource_type                  rule_provider                       rule_subdomain
                  rule_auto_remediable                rule_control_requirement            rule_control_section
                  rule_compliance_benchmark           rule_compliance_framework           rule_mitre_tactic
                  rule_mitre_technique                rule_created_at                     rule_updated_at
                  rule_updated_by
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-policies/QueryRule
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryRule",
            keywords=kwargs,
            params=parameters
            )

    ReplaceControlRules = replace_control_rules
    GetComplianceControls = get_compliance_controls
    CreateComplianceControl = create_compliance_control
    UpdateComplianceControl = update_compliance_control
    DeleteComplianceControl = delete_compliance_control
    RenameSectionComplianceFramework = rename_section_compliance_framework
    GetComplianceFrameworks = get_compliance_frameworks
    CreateComplianceFramework = create_compliance_framework
    UpdateComplianceFramework = update_compliance_framework
    DeleteComplianceFramework = delete_compliance_framework
    GetEvaluationResult = get_evaluation_result
    GetRuleOverride = get_rule_override
    CreateRuleOverride = create_rule_override
    UpdateRuleOverride = update_rule_override
    DeleteRuleOverride = delete_rule_override
    GetRule = get_rule
    CreateRuleMixin0 = create_rule
    UpdateRule = update_rule
    DeleteRuleMixin0 = delete_rule
    QueryComplianceControls = query_compliance_controls
    QueryComplianceFrameworks = query_compliance_frameworks
    QueryRule = query_rule
    GetRuleInputSchema = get_rule_input_schema
    GetEnrichedAsset = get_enriched_asset
