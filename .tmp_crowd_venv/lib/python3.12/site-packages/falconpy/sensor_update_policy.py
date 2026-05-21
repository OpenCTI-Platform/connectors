"""CrowdStrike Falcon Sensor Policy Management API interface class.

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
from ._util import generate_error_result, args_to_params, force_default
from ._util import handle_single_argument, process_service_request
from ._payload import generic_payload_list, sensor_policy_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._sensor_update_policies import _sensor_update_policies_endpoints as Endpoints


class SensorUpdatePolicy(ServiceClass):
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

    @force_default(defaults=["body"], default_types=["dict"])
    def reveal_uninstall_token(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Reveals an uninstall token for a specific device.

        To retrieve the bulk maintenance token pass the value
        'MAINTENANCE' as the value for 'device_id'.

        Keyword arguments:
        audit_message -- Message to list in the audit log for this action. String.
        body -- full body payload, not required if keywords are used.
                {
                    "audit_message": "string",
                    "device_id": "string"
                }
        device_id -- Device ID to retrieve the uninstall token for. Pass the value "MAINTENANCE"
                     to retrieve the bulk maintenance token.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-update-policies/revealUninstallToken
        """
        if not body:
            body = {}
            body["audit_message"] = kwargs.get("audit_message", None)
            body["device_id"] = kwargs.get("device_id", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="revealUninstallToken",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_combined_builds(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve available builds for use with Sensor Update Policies.

        Keyword arguments:
        platform -- The platform to return builds for. String.
                    Allowed values: "linux", "linuxarm64", "mac", "windows", "zlinux"
        parameters -- full parameters payload, not required if platform is provided as a keyword.
        stage -- The stages to return builds for. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'platform'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/queryCombinedSensorUpdateBuilds
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedSensorUpdateBuilds",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "platform")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_combined_kernels(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve kernel compatibility info for Sensor Update Builds.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters -- full parameters payload, not required if platform is provided as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/queryCombinedSensorUpdateKernels
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedSensorUpdateKernels",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_combined_policy_members(self: object,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for members of a Sensor Update Policy by providing a FQL filter and paging detail.

        Returns a set of host details which match the filter criteria.

        Keyword arguments:
        id -- The ID of the Sensor Update Policy to search for members of
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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/queryCombinedSensorUpdatePolicyMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedSensorUpdatePolicyMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_combined_policies(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Sensor Update Policies by providing an FQL filter and paging details.

        Returns a set of Sensor Update Policies which match the filter criteria.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/queryCombinedSensorUpdatePolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedSensorUpdatePolicies",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_combined_policies_v2(self: object,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Sensor Update Policies by providing an FQL filter and paging details.

        Provides additional support for uninstall protection.
        Returns a set of Sensor Update Policies which match the filter criteria.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/queryCombinedSensorUpdatePoliciesV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedSensorUpdatePoliciesV2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def perform_policies_action(self: object,
                                body: dict = None,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform the specified action on the Sensor Update Policies specified in the request.

        Keyword arguments:
        action_name -- action to perform: 'add-host-group', 'add-rule-group', 'disable', 'enable',
                       'remove-rule-group' or 'remove-host-group'.
        action_parameters -- Action specific parameter options. List of dictionaries.
                             {
                                 "name": "string",
                                 "value": "string"
                             }
        body -- full body payload, not required if keywords are used.
                {
                    "action_parameters": [
                        {
                            "name": "group_id",
                            "value": "string"
                        }
                    ],
                    "ids": [
                        "string"
                    ]
                }
        group_id -- Host Group ID to apply the policy to. String.
                    Overridden if action_parameters is specified.
        ids -- Sensor Update policy ID(s) to perform actions against. String or list of strings.
        parameters - full parameters payload, not required if action_name is provided as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/performSensorUpdatePoliciesAction
        """
        _allowed_actions = ['add-host-group', 'disable', 'enable', 'remove-host-group']
        operation_id = "performSensorUpdatePoliciesAction"
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
                            body=body,
                            keywords=kwargs,
                            params=parameters
                            )
        else:
            returned = generate_error_result("Invalid value specified for action_name parameter.")

        return returned

    @force_default(defaults=["body"], default_types=["dict"])
    def set_policies_precedence(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Set the precedence of Sensor Update Policies based on the order of IDs in the request.

        The first ID specified will have the highest precedence and the last ID specified will have
        the lowest. You must specify all non-Default Policies for a platform when updating
        precedence.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "ids": [
                        "string"
                    ],
                    "platform_name": "Windows"
                }
        ids -- Sensor Update policy ID(s) to perform actions against. String or list of strings.
        platform_name -- OS platform name.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/setSensorUpdatePoliciesPrecedence
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
            if kwargs.get("platform_name", None):
                body["platform_name"] = kwargs.get("platform_name", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="setSensorUpdatePoliciesPrecedence",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a set of Sensor Update Policies by specifying their IDs.

        Keyword arguments:
        ids -- List of Sensor Update Policy IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-update-policies/getSensorUpdatePolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getSensorUpdatePolicies",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Sensor Update Policies by specifying details about the policy to create.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "resources": [
                        {
                            "description": "string",
                            "name": "string",
                            "platform_name": "Windows",
                            "settings": {
                                    "build": "string"
                            }
                        }
                    ]
                }
        build -- Build policy applies to. String.
        description -- Sensor Update Policy description. String.
        name -- Sensor Update Policy name. String.
        platform_name -- Name of the operating system platform. String.
        settings -- Sensor update policy specific settings. Dictionary.
                    OVERRIDES the value of the "build" keyword if provided.
                    {
                        "build": "string"
                    }

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/createSensorUpdatePolicies
        """
        if not body:
            body = sensor_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createSensorUpdatePolicies",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a set of Sensor Update Policies by specifying their IDs.

        Keyword arguments:
        ids -- List of Sensor Update Policy IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/deleteSensorUpdatePolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteSensorUpdatePolicies",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Sensor Update Policies by specifying the ID of the policy and details to update.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "resources": [
                        {
                            "description": "string",
                            "id": "string",
                            "name": "string",
                            "settings": {
                                    "build": "string"
                            }
                        }
                    ]
                }
        build -- Build policy applies to . String.
        description -- Sensor Update Policy description. String.
        id -- Sensor Update Policy ID to update. String.
        name -- Sensor Update Policy name. String.
        settings -- Sensor Update policy specific settings. Dictionary.
                    OVERRIDES the value of the "build" keyword if provided.
                    {
                        "build": "string"
                    }

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/updateSensorUpdatePolicies
        """
        if not body:
            body = sensor_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateSensorUpdatePolicies",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policies_v2(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a set of Sensor Update Policies by specifying their IDs.

        Provides additional support for uninstall protection.

        Keyword arguments:
        ids -- List of Sensor Update Policy IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/getSensorUpdatePoliciesV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getSensorUpdatePoliciesV2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policies_v2(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Sensor Update Policies by specifying details about the policy.

        Provides additional support for uninstall protection.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "resources": [
                        {
                            "description": "string",
                            "name": "string",
                            "platform_name": "Windows",
                            "settings": {
                                "build": "string",
                                "scheduler": {
                                    "enabled": true,
                                    "schedules": [
                                        {
                                            "days": [
                                                0
                                            ],
                                            "end": "string",
                                            "start": "string"
                                        }
                                    ],
                                    "timezone": "string"
                                },
                                "show_early_adopter_builds": true,
                                "uninstall_protection": "ENABLED",
                                "variants": [
                                    {
                                        "build": "string",
                                        "platform": "string"
                                    }
                                ]
                            }
                        }
                    ]
                }
        build -- Build policy applies to. String.
        description -- Sensor Update Policy description. String.
        name -- Sensor Update Policy name. String.
        platform_name -- Name of the operating system platform. String.
        scheduler -- Scheduler settings. Dictionary.
        settings -- Sensor update policy specific settings. Dictionary.
                    OVERRIDES the value of the "build" and "uninstall_protection"
                    keywords if provided.
                    {
                        "build": "string",
                        "scheduler": {
                            "enabled": true,
                            "schedules": [
                                {
                                    "days": [
                                        0
                                    ],
                                    "end": "string",
                                    "start": "string"
                                }
                            ],
                            "timezone": "string"
                        },
                        "show_early_adopter_builds": true,
                        "uninstall_protection": "ENABLED",
                        "variants": [
                            {
                                "build": "string",
                                "platform": "string"
                            }
                        ]
                    }
        show_early_adopter_builds -- Enable early adopter builds. Boolean.
        uninstall_protection -- Boolean indicating if uninstall protection should be enabled.
                                String. Allowed values: "ENABLED", "DISABLED"
        variants -- List of variants. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/createSensorUpdatePoliciesV2
        """
        if not body:
            body = sensor_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createSensorUpdatePoliciesV2",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policies_v2(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Sensor Update Policies by specifying the ID of the policy and update details.

        Provides additional support for uninstall protection.
        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "resources": [
                        {
                            "description": "string",
                            "id": "string",
                            "name": "string",
                            "settings": {
                                "build": "string",
                                "scheduler": {
                                    "enabled": true,
                                    "schedules": [
                                        {
                                            "days": [
                                                0
                                            ],
                                            "end": "string",
                                            "start": "string"
                                        }
                                    ],
                                    "timezone": "string"
                                },
                                "show_early_adopter_builds": true,
                                "uninstall_protection": "ENABLED",
                                "variants": [
                                    {
                                        "build": "string",
                                        "platform": "string"
                                    }
                                ]
                            }
                        }
                    ]
                }
        build -- Build policy applies to . String.
        description -- Sensor Update Policy description. String.
        id -- Sensor Update Policy ID to update. String.
        name -- Sensor Update Policy name. String.
        scheduler -- Schedule settings. Dictionary.
        settings -- Sensor Update policy specific settings. Dictionary.
                    OVERRIDES the value of the "build" keyword if provided.
                    {
                        "build": "string",
                        "uninstall_protection": "ENABLED"
                    }
        show_early_adopter_builds -- Display early adopter builds. Boolean.
        uninstall_protection -- Boolean indicating if uninstall protection should be enabled.
                                String. Allowed values: "ENABLED", "DISABLED"
        variants -- Allowed variants list. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/updateSensorUpdatePoliciesV2
        """
        if not body:
            body = sensor_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateSensorUpdatePoliciesV2",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_kernels(self: object,
                      distinct_field: str = "id",
                      parameters: dict = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve kernel compatibility info for Sensor Update Builds.

        Keyword arguments:
        distinct_field -- The field name to get distinct values for. If you do not
                          specify a value for this field it will default to `id`.
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/querySensorUpdateKernelsDistinct
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="querySensorUpdateKernelsDistinct",
            keywords=kwargs,
            params=parameters,
            distinct_field=distinct_field
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policy_members(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for members of a Sensor Update Policy by providing a FQL filter and paging detail.

        Returns a set of Agent IDs which match the filter criteria.

        Keyword arguments:
        id -- The ID of the Sensor Update Policy to search for members of
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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/querySensorUpdatePolicyMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="querySensorUpdatePolicyMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Sensor Update Policies by providing a FQL filter and paging details.

        Returns a set of Sensor Update Policy IDs which match the filter criteria.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                        /sensor-update-policies/querySensorUpdatePolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="querySensorUpdatePolicies",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    revealUninstallToken = reveal_uninstall_token
    queryCombinedSensorUpdateBuilds = query_combined_builds
    queryCombinedSensorUpdateKernels = query_combined_kernels
    queryCombinedSensorUpdatePolicyMembers = query_combined_policy_members
    queryCombinedSensorUpdatePolicies = query_combined_policies
    queryCombinedSensorUpdatePoliciesV2 = query_combined_policies_v2
    performSensorUpdatePoliciesAction = perform_policies_action
    setSensorUpdatePoliciesPrecedence = set_policies_precedence
    getSensorUpdatePolicies = get_policies
    createSensorUpdatePolicies = create_policies
    deleteSensorUpdatePolicies = delete_policies
    updateSensorUpdatePolicies = update_policies
    getSensorUpdatePoliciesV2 = get_policies_v2
    createSensorUpdatePoliciesV2 = create_policies_v2
    updateSensorUpdatePoliciesV2 = update_policies_v2
    querySensorUpdateKernelsDistinct = query_kernels
    querySensorUpdatePolicyMembers = query_policy_members
    querySensorUpdatePolicies = query_policies


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Sensor_Update_Policy = SensorUpdatePolicy  # pylint: disable=C0103
# Service collection name mapping typo fix
SensorUpdatePolicies = SensorUpdatePolicy
