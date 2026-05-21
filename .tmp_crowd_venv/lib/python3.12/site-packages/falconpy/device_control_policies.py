"""CrowdStrike Falcon Device Control Policies API interface class.

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
# pylint: disable=C0302
from typing import Dict, Union
from ._util import generate_error_result, force_default, args_to_params
from ._util import process_service_request, handle_single_argument
from ._payload import (
    generic_payload_list,
    device_policy_payload,
    default_device_policy_config_payload,
    device_classes_policy_payload,
    device_policy_bluetooth_config_payload,
    device_control_policy_payload_v2
    )
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._device_control_policies import _device_control_policies_endpoints as Endpoints


class DeviceControlPolicies(ServiceClass):
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
        """Search for a Device Control Policy members and return full detail.

        Search for members of a Device Control Policy in your environment by
        providing an FQL filter and paging details. Returns a set of host details
        which match the filter criteria.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/queryCombinedDeviceControlPolicyMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedDeviceControlPolicyMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_combined_policies(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for a Device Control Policies and return full detail.

        Search for Device Control Policies in your environment by providing an FQL filter and
        paging details. Returns a set of Device Control Policies which match the filter criteria.

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
                    /device-control-policies/queryCombinedDeviceControlPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCombinedDeviceControlPolicies",
            keywords=kwargs,
            params=parameters
            )

    def get_default_policies(self: object) -> dict:
        """Retrieve the configuration for a Default Device Control Policy.

        Keyword arguments:
        This method does not accept keyword arguments.

        Arguments: This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/getDefaultDeviceControlPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getDefaultDeviceControlPolicies"
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_default_policies(self: object, body: dict = None, **kwargs) -> dict:
        """Update Device Control Policies by specifying the ID of the policy and details to update.

        Keyword arguments:
        blocked_notification -- dictionary containing the custom message and enablement status
                                for the blocked notification. Dictionary.
                                {
                                    "custom_message": "string",
                                    "use_custom": true
                                }
        blocked_custom_message -- Message to use for blocked notifications. Using this keyword will
                                  automatically generate the necessary blocked_notification dictionary.
                                  String.
        body -- full body payload, not required if using other keywords.
                {
                    "custom_notifications": {
                        "blocked_notification": {
                            "custom_message": "string",
                            "use_custom": true
                        },
                        "restricted_notification": {
                            "custom_message": "string",
                            "use_custom": true
                        }
                    }
                }
        restricted_custom_message -- message to use for restricted notifications. Using this keyword will
                                  automatically generate the necessary restricted_notification dictionary.
                                  String.
        restricted_notification -- dictionary containing the custom message and enablement status
                                   for the restricted notification. Dictionary.
                                   {
                                       "custom_message": "string",
                                       "use_custom": true
                                   }

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/updateDefaultDeviceControlPolicies
        """
        if not body:
            body = default_device_policy_config_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateDefaultDeviceControlPolicies",
            body=body
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def perform_action(self: object,
                       body: dict = None,
                       parameters: dict = None,
                       **kwargs
                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform a Device Control Policy action.

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
        ids -- Device Control policy ID(s) to perform actions against. String or list of strings.
        parameters - full parameters payload, not required if action_name is provided as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/performDeviceControlPoliciesAction
        """
        _allowed_actions = ['add-host-group', 'disable', 'enable', 'remove-host-group']
        operation_id = "performDeviceControlPoliciesAction"
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
    def update_policy_classes(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update device control policy's classes (USB and Bluetooth).

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "policies": [
                        {
                            "bluetooth_classes": {
                                "classes": [
                                    {
                                        "action": "string",
                                        "class": "string",
                                        "minor_classes": [
                                            {
                                                "action": "string",
                                                "minor_class": "string"
                                            }
                                        ]
                                    }
                                ],
                                "delete_exceptions": [
                                    "string"
                                ],
                                "upsert_exceptions": [
                                    {
                                        "action": "string",
                                        "class": "string",
                                        "description": "string",
                                        "expiration_time": "UTC date string",
                                        "id": "string",
                                        "minor_classes": [
                                            "string"
                                        ],
                                        "product_id": "string",
                                        "product_name": "string",
                                        "vendor_id": "string",
                                        "vendor_id_source": "string",
                                        "vendor_name": "string"
                                    }
                                ]
                            },
                            "id": "string",
                            "usb_classes": {
                                "classes": [
                                    {
                                        "action": "string",
                                        "class": "string"
                                    }
                                ],
                                "delete_exceptions": [
                                    "string"
                                ],
                                "upsert_exceptions": [
                                    {
                                        "action": "string",
                                        "class": "string",
                                        "combined_id": "string",
                                        "description": "string",
                                        "expiration_time": "UTC date string",
                                        "id": "string",
                                        "product_id": "string",
                                        "product_name": "string",
                                        "serial_number": "string",
                                        "use_wildcard": boolean,
                                        "vendor_id": "string",
                                        "vendor_name": "string"
                                    }
                                ]
                            }
                        }
                    ]
                }
        bluetooth_classes -- Bluetooth device control policy. Dictionary.
        id -- Device control policy ID. String.
        usb_classes -- USB device control policy. Dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /device-control-with-bluetooth/patchDeviceControlPoliciesClassesV1
        """
        if not body:
            body = device_classes_policy_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="patchDeviceControlPoliciesClassesV1",
            body=body
            )

    def get_default_settings(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get default device control settings (USB and Bluetooth).

        Keyword arguments:
        This method does not accept keyword arguments.

        Arguments:
        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /device-control-with-bluetooth/getDefaultDeviceControlSettings
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getDefaultDeviceControlSettings"
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_default_settings(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update the configuration for Default Device Control Settings.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "bluetooth_custom_notifications": {
                        "blocked_notification": {
                            "custom_message": "string",
                            "use_custom": boolean
                        }
                    },
                    "usb_custom_notifications": {
                        "blocked_notification": {
                            "custom_message": "string",
                            "use_custom": boolean
                        },
                        "restricted_notification": {
                            "custom_message": "string",
                            "use_custom": boolean
                        }
                    },
                    "usb_exceptions": [
                        {
                            "delete_exceptions": [
                                "string"
                            ],
                            "platform_name": "string",
                            "upsert_exceptions": [
                                {
                                    "action": "string",
                                    "class": "string",
                                    "combined_id": "string",
                                    "description": "string",
                                    "id": "string",
                                    "product_id": "string",
                                    "product_name": "string",
                                    "serial_number": "string",
                                    "vendor_id": "string",
                                    "vendor_name": "string"
                                }
                            ]
                        }
                    ]
                }
        bluetooth_custom_notifications -- Custom bluetooth notifications. Dictionary.
        usb_custom_notifications -- Custom USB notifications. Dictionary.
        usb_exceptions -- USB exceptions. Dictionary or list of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /device-control-with-bluetooth/patchDeviceControlPoliciesClassesV1
        """
        if not body:
            body = device_policy_bluetooth_config_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateDefaultDeviceControlSettings",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def set_precedence(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Set Device Control Policy precedence.

        Sets the precedence of Device Control Policies based on the order of IDs specified in
        the request. The first ID specified will have the highest precedence and the last ID
        specified will have the lowest. You must specify all non-Default Policies for a platform
        when updating precedence.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "ids": [
                        "string"
                    ],
                    "platform_name": "Windows"
                }
        ids -- Device Control policy ID(s) to perform actions against. String or list of strings.
        platform_name -- OS platform name.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/performDeviceControlPoliciesAction
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
            if kwargs.get("platform_name", None):
                body["platform_name"] = kwargs.get("platform_name", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="setDeviceControlPoliciesPrecedence",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a set of Device Control Policies by specifying their IDs.

        Keyword arguments:
        ids -- List of Device Control Policy IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/getDeviceControlPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getDeviceControlPolicies",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Device Control Policies by specifying details about the policy to create.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "resources": [
                        {
                            "clone_id": "string",
                            "description": "string",
                            "name": "string",
                            "platform_name": "Windows",
                            "settings": {
                                "classes": [
                                    {
                                        "action": "FULL_ACCESS",
                                        "exceptions": [
                                            {
                                                "action": "string",
                                                "combined_id": "string",
                                                "description": "string",
                                                "expiration_time": "2023-06-08T06:04:53.563Z",
                                                "id": "string",
                                                "product_id": "string",
                                                "product_id_decimal": "string",
                                                "product_name": "string",
                                                "serial_number": "string",
                                                "use_wildcard": true,
                                                "vendor_id": "string",
                                                "vendor_id_decimal": "string",
                                                "vendor_name": "string"
                                            }
                                        ],
                                        "id": "string"
                                    }
                                ],
                                "custom_notifications": {
                                    "blocked_notification": {
                                        "custom_message": "string",
                                        "use_custom": true
                                    },
                                    "restricted_notification": {
                                        "custom_message": "string",
                                        "use_custom": true
                                    }
                                },
                                "delete_exceptions": [
                                    "string"
                                ],
                                "end_user_notification": "SILENT",
                                "enforcement_mode": "MONITOR_ONLY",
                                "enhanced_file_metadata": true
                            }
                        }
                    ]
                }
        clone_id -- ID of the Device Control Policy to clone. String.
        description -- Device Control Policy description. String.
        name -- Device Control Policy name. String.
        platform_name -- Name of the operating system platform. String.
        settings -- Device Control policy specific settings. Dictionary.
                    See above for JSON dictionary format example.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/createDeviceControlPolicies
        """
        if not body:
            body = device_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createDeviceControlPolicies",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a set of Device Control Policies by specifying their IDs.

        Keyword arguments:
        ids -- List of Device Control Policy IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/createDeviceControlPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteDeviceControlPolicies",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policies_v2(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get device control policies for the given filter criteria. Supports USB and Bluetooth.

        Keyword arguments:
        ids -- List of Device Control Policy IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /device-control-with-bluetooth/getDeviceControlPoliciesV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getDeviceControlPoliciesV2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policies_v2(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Device Control Policies by specifying details about the policy to create.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "policies": [
                        {
                            "bluetooth_settings": {
                                "custom_end_user_notifications": {
                                    "blocked_notification": {
                                        "custom_message": "string",
                                        "use_custom": boolean
                                    }
                                },
                                "end_user_notification": "string",
                                "enforcement_mode": "string"
                            },
                            "clone_id": "string",
                            "description": "string",
                            "name": "string",
                            "platform_name": "string",
                            "usb_settings": {
                                "custom_notifications": {
                                    "blocked_notification": {
                                        "custom_message": "string",
                                        "use_custom": boolean
                                    },
                                    "restricted_notification": {
                                        "custom_message": "string",
                                        "use_custom": boolean
                                    }
                                },
                                "end_user_notification": "string",
                                "enforcement_mode": "string",
                                "enhanced_file_metadata": boolean,
                                "whitelist_mode": "string"
                            }
                        }
                    ]
                }
        bluetooth_settings -- Device Control policy USB specific settings. Dictionary.
                              See above for JSON dictionary format example.
        clone_id -- ID of the Device Control Policy to clone. String.
        description -- Device Control Policy description. String.
        name -- Device Control Policy name. String.
        platform_name -- Name of the operating system platform. String.
        usb_settings -- Device Control policy USB specific settings. Dictionary.
                        See above for JSON dictionary format example.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/createDeviceControlPolicies
        """
        if not body:
            body = device_control_policy_payload_v2(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="postDeviceControlPoliciesV2",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policies_v2(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Device Control Policies by specifying details about the policy to create.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "policies": [
                        {
                            "bluetooth_settings": {
                                "custom_end_user_notifications": {
                                    "blocked_notification": {
                                        "custom_message": "string",
                                        "use_custom": boolean
                                    }
                                },
                                "end_user_notification": "string",
                                "enforcement_mode": "string"
                            },
                            "description": "string",
                            "id": "string",
                            "name": "string",
                            "platform_name": "string",
                            "usb_settings": {
                                "custom_notifications": {
                                    "blocked_notification": {
                                        "custom_message": "string",
                                        "use_custom": boolean
                                    },
                                    "restricted_notification": {
                                        "custom_message": "string",
                                        "use_custom": boolean
                                    }
                                },
                                "end_user_notification": "string",
                                "enforcement_mode": "string",
                                "enhanced_file_metadata": boolean,
                                "whitelist_mode": "string"
                            }
                        }
                    ]
                }
        bluetooth_settings -- Device Control policy USB specific settings. Dictionary.
                              See above for JSON dictionary format example.
        description -- Device Control Policy description. String.
        id -- ID of the Device Control Policy to update. String.
        name -- Device Control Policy name. String.
        platform_name -- Name of the operating system platform. String.
        usb_settings -- Device Control policy USB specific settings. Dictionary.
                        See above for JSON dictionary format example.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /device-control-with-bluetooth/patchDeviceControlPoliciesV2
        """
        if not body:
            body = device_control_policy_payload_v2(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="patchDeviceControlPoliciesV2",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Device Control Policies by specifying the ID of the policy and details to update.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "resources": [
                        {
                            "description": "string",
                            "id": "string",
                            "name": "string",
                            "settings": {
                                "classes": [
                                    {
                                        "action": "FULL_ACCESS",
                                        "exceptions": [
                                            {
                                                "action": "string",
                                                "combined_id": "string",
                                                "description": "string",
                                                "expiration_time": "2023-06-08T06:10:39.965Z",
                                                "id": "string",
                                                "product_id": "string",
                                                "product_id_decimal": "string",
                                                "product_name": "string",
                                                "serial_number": "string",
                                                "use_wildcard": true,
                                                "vendor_id": "string",
                                                "vendor_id_decimal": "string",
                                                "vendor_name": "string"
                                            }
                                        ],
                                        "id": "string"
                                    }
                                ],
                                "custom_notifications": {
                                    "blocked_notification": {
                                        "custom_message": "string",
                                        "use_custom": true
                                    },
                                    "restricted_notification": {
                                        "custom_message": "string",
                                        "use_custom": true
                                    }
                                },
                                "delete_exceptions": [
                                    "string"
                                ],
                                "end_user_notification": "SILENT",
                                "enforcement_mode": "MONITOR_ONLY",
                                "enhanced_file_metadata": true
                            }
                        }
                    ]
                }
        id -- ID of the Device Control Policy to update. String.
        description -- Device Control Policy description. String.
        name -- Device Control Policy name. String.
        settings -- Device Control policy specific settings. Dictionary.
                    See above for JSON dictionary format example.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/updateDeviceControlPolicies
        """
        if not body:
            body = device_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateDeviceControlPolicies",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policy_members(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for a Device Control Policy members and return their IDs.

        Search for members of a Device Control Policy in your environment by providing
        an FQL filter and paging details. Returns a set of Agent IDs which match the filter
        criteria.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /device-control-policies/queryDeviceControlPolicyMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryDeviceControlPolicyMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for a Device Control Policies and return their IDs.

        Search for Device Control Policies in your environment by providing an
        FQL filter and paging details. Returns a set of Device Control Policy IDs
        which match the filter criteria.

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
                    /device-control-policies/queryDeviceControlPolicyMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryDeviceControlPolicies",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    queryCombinedDeviceControlPolicyMembers = query_combined_policy_members
    queryCombinedDeviceControlPolicies = query_combined_policies
    getDefaultDeviceControlPolicies = get_default_policies
    updateDefaultDeviceControlPolicies = update_default_policies
    performDeviceControlPoliciesAction = perform_action
    patchDeviceControlPoliciesClassesV1 = update_policy_classes
    getDefaultDeviceControlSettings = get_default_settings
    updateDefaultDeviceControlSettings = update_default_settings
    setDeviceControlPoliciesPrecedence = set_precedence
    getDeviceControlPolicies = get_policies
    createDeviceControlPolicies = create_policies
    deleteDeviceControlPolicies = delete_policies
    getDeviceControlPoliciesV2 = get_policies_v2
    postDeviceControlPoliciesV2 = create_policies_v2
    patchDeviceControlPoliciesV2 = update_policies_v2
    updateDeviceControlPolicies = update_policies
    queryDeviceControlPolicyMembers = query_policy_members
    queryDeviceControlPolicies = query_policies


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Device_Control_Policies = DeviceControlPolicies  # pylint: disable=C0103
