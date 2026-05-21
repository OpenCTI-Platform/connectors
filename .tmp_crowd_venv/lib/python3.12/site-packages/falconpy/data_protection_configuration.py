"""CrowdStrike Falcon DataProtectionConfiguration API interface class.

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
from ._util import force_default, process_service_request, handle_single_argument
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._data_protection_configuration import _data_protection_configuration_endpoints as Endpoints
from ._payload._data_protection_configuration import (
    data_protection_classification_payload,
    data_protection_cloud_app_payload,
    data_protection_content_pattern_payload,
    data_protection_enterprise_account_payload,
    data_protection_sensitivity_label_payload,
    data_protection_policy_payload,
    data_protection_web_locations_payload
    )


# pylint: disable=R0904
class DataProtectionConfiguration(ServiceClass):
    """The only requirement to instantiate an instance of this class is one of the following.

    - a valid client_id and client_secret provided as keywords.
    - a credential dictionary with client_id and client_secret containing valid API credentials.
      {
          "client_id": "CLIENT_ID_HERE",
          "client_secret": "CLIENT_SECRET_HERE"
      }
    - a previously-authenticated instance of the authentication service class (oauth2.py).
    - a valid token provided by the authentication service class (oauth2.py).
    """

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_classification(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the classifications that match the provided ids.

        Keyword arguments:
        ids -- IDs of the classifications to get. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.classification.get.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_classification_get_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_classification(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create classifications.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                        "classification_properties": {
                            "content_patterns": [
                            "string"
                            ],
                            "evidence_duplication_enabled": true,
                            "file_types": [
                            "string"
                            ],
                            "protection_mode": "monitor",
                            "rules": [
                            {
                                "ad_groups": [
                                "string"
                                ],
                                "ad_users": [
                                "string"
                                ],
                                "created_time_stamp": "string",
                                "description": "string",
                                "detection_severity": "informational",
                                "enable_printer_egress": true,
                                "enable_usb_devices": true,
                                "enable_web_locations": true,
                                "id": "string",
                                "modified_time_stamp": "string",
                                "notify_end_user": true,
                                "response_action": "allow",
                                "trigger_detection": true,
                                "user_scope": "all",
                                "web_locations": [
                                "string"
                                ],
                                "web_locations_scope": "all"
                            }
                            ],
                            "sensitivity_labels": [
                            "string"
                            ],
                            "web_sources": [
                            "string"
                            ]
                        },
                        "name": "string"
                        }
                    ]
                }
        classification_properties -- The properties of the new classification. Dictionary.
        name -- The name of the new classification. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.classification.post.v2
        """
        if not body:
            body = data_protection_classification_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_classification_post_v2",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_classifications(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update classifications.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                        "classification_properties": {
                            "content_patterns": [
                            "string"
                            ],
                            "evidence_duplication_enabled": true,
                            "file_types": [
                            "string"
                            ],
                            "protection_mode": "monitor",
                            "rules": [
                            {
                                "ad_groups": [
                                "string"
                                ],
                                "ad_users": [
                                "string"
                                ],
                                "created_time_stamp": "string",
                                "description": "string",
                                "detection_severity": "informational",
                                "enable_printer_egress": true,
                                "enable_usb_devices": true,
                                "enable_web_locations": true,
                                "id": "string",
                                "modified_time_stamp": "string",
                                "notify_end_user": true,
                                "response_action": "allow",
                                "trigger_detection": true,
                                "user_scope": "all",
                                "web_locations": [
                                "string"
                                ],
                                "web_locations_scope": "all"
                            }
                            ],
                            "sensitivity_labels": [
                            "string"
                            ],
                            "web_sources": [
                            "string"
                            ]
                        },
                        "name": "string"
                        }
                    ]
                }
        classification_properties -- The properties of the new classification. Dictionary.
        name -- The name of the new classification. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.classification.patch.v2
        """
        if not body:
            body = data_protection_classification_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_classification_patch_v2",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_classification(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete classifications that match the provided ids.

        Keyword arguments:
        ids -- IDs of the classifications to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.classification.delete.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_classification_delete_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_cloud_application(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a particular cloud-application.

        Keyword arguments:
        ids -- The cloud application id(s) to get. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.cloud-application.get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_cloud_application_get",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_cloud_application(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Persist the given cloud application for the provided entity instance.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "description": "string",
                    "name": "string",
                    "urls": [
                        {
                        "fqdn": "string",
                        "path": "string"
                        }
                    ]
                }
        description -- The description of the cloud application. String.
        name -- The name of the cloud application. String.
        urls -- The fields contain the FQDN and the path. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.cloud-application.create
        """
        if not body:
            body = data_protection_cloud_app_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_cloud_application_create",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_cloud_application(self: object,
                                 body: dict = None,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a cloud application.

        Keyword arguments:
        id -- The cloud app id to update. String.
        body -- The new cloud-application definition.
                {
                    "description": "string",
                    "name": "string",
                    "urls": [
                        {
                        "fqdn": "string",
                        "path": "string"
                        }
                    ]
                }
        description -- The description of the cloud application. String.
        name -- The name of the cloud application. String.
        urls -- The fields contain the FQDN and the path. List of dictionaries.

        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.cloud-application.patch
        """
        if not body:
            body = data_protection_cloud_app_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_cloud_application_patch",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_cloud_application(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete cloud application.

        Keyword arguments:
        ids -- The id of the cloud application to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.cloud-application.delete
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_cloud_application_delete",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_content_pattern(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a particular content-pattern(s).

        Keyword arguments:
        ids -- The content-pattern id(s) to get. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.content-pattern.get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_content_pattern_get",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_content_pattern(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Persist the given content pattern for the provided entity instance.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "category": "string",
                    "description": "string",
                    "example": "string",
                    "min_match_threshold": 0,
                    "name": "string",
                    "regexes": [
                        "string"
                    ],
                    "region": "string"
                }
        category -- The content pattern category. String.
        description -- The description of the content pattern. String.
        example -- The new content pattern demonstration. String.
        min_match_threshold -- Integer.
        name -- The name of the new content pattern. String.
        regexes -- List of strings.
        region -- The region for the content pattern. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.content-pattern.create
        """
        if not body:
            body = data_protection_content_pattern_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_content_pattern_create",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_content_pattern(self: object,
                               body: dict = None,
                               parameters: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a content pattern.

        Keyword arguments:
        id -- The id of the content pattern to patch.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "category": "string",
                    "description": "string",
                    "example": "string",
                    "min_match_threshold": 0,
                    "name": "string",
                    "regexes": [
                        "string"
                    ],
                    "region": "string"
                }
        category -- The content pattern category. String.
        description -- The description of the content pattern. String.
        example -- The new content pattern demonstration. String.
        min_match_threshold -- Integer.
        name -- The name of the new content pattern. String.
        regexes -- List of strings.
        region -- The region for the content pattern. String.

        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.content-pattern.patch
        """
        if not body:
            body = data_protection_content_pattern_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_content_pattern_patch",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_content_pattern(self: object,
                               *args,
                               parameters: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete content pattern.

        Keyword arguments:
        ids -- The id(s) of the content pattern to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.content-pattern.delete
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_content_pattern_delete",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_enterprise_account(self: object,
                               *args,
                               parameters: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a particular enterprise-account(s).

        Keyword arguments:
        ids -- The enterprise-account id(s) to get. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.enterprise-account.get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_enterprise_account_get",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_enterprise_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Persist the given enterprise account for the provided entity instance.

        Keyword arguments:
        body -- Definition of enterprise-account to create.
                {
                    "application_group_id": "string",
                    "domains": [
                        "string"
                    ],
                    "name": "string",
                    "plugin_config_id": "string"
                }
        application_group_id -- String.
        domains -- List of strings.
        name -- The name of the enterprise account. String.
        plugin_config_id -- String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.enterprise-account.create
        """
        if not body:
            body = data_protection_enterprise_account_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_enterprise_account_create",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_enterprise_account(self: object,
                                  body: dict = None,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a enterprise account.

        Keyword arguments:
        id -- The id of the enterprise account to update.
        body -- Definition of enterprise-account to create.
                {
                    "application_group_id": "string",
                    "domains": [
                        "string"
                    ],
                    "id": "string",
                    "name": "string",
                    "plugin_config_id": "string"
                }
        application_group_id -- String.
        domains -- List of strings.
        name -- The name of the enterprise account. String.
        plugin_config_id -- String.

        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.enterprise-account.patch
        """
        if not body:
            body = data_protection_enterprise_account_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_enterprise_account_patch",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_enterprise_account(self: object,
                                  *args,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete enterprise account.

        Keyword arguments:
        ids -- The id of the enterprise account to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.enterprise-account.delete
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_enterprise_account_delete",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_file_type(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a particular file-type.

        Keyword arguments:
        ids -- The file-type id(s) to get. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.file-type.get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_file_type_get",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_sensitivity_label(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get sensitivity label matching the IDs (V2).

        Keyword arguments:
        ids -- The sensitivity label entity id(s) to get.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.file-type.get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_sensitivity_label_get_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_sensitivity_label(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create new sensitivity label (V2).

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "co_authoring": true,
                    "display_name": "string",
                    "external_id": "string",
                    "label_provider": "string",
                    "name": "string",
                    "plugins_configuration_id": "string",
                    "synced": true
                }
        co_authoring -- Boolean.
        display_name -- String.
        external_id -- String.
        label_provider -- String.
        name -- The name of the new sensitivity label. String.
        plugins_configuration_id -- String.
        synced -- Boolean.
        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.sensitivity-label.create-v2
        """
        if not body:
            body = data_protection_sensitivity_label_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_sensitivity_label_create_v2",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_sensitivity_label(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete sensitivity labels matching the IDs (V2).

        Keyword arguments:
        ids -- The sensitivity label entity id(s) to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.sensitivity-label.delete-v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_sensitivity_label_delete_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get policies that match the provided ids.

        Keyword arguments:
        ids -- IDs of the policies to get. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.policy.get.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_policy_get_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def create_policy(self: object,
                      body: dict = None,
                      parameters: dict = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create policies.

        Keyword arguments:
        platform_name -- platform name of the policies to update, either 'win' or 'mac'.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                        "description": "string",
                        "name": "string",
                        "policy_properties": {
                            "allow_notifications": "default",
                            "be_exclude_domains": "string",
                            "be_paste_clipboard_max_size": 0,
                            "be_paste_clipboard_max_size_unit": "Bytes",
                            "be_paste_clipboard_min_size": 0,
                            "be_paste_clipboard_min_size_unit": "Bytes",
                            "be_paste_clipboard_over_size_behaviour_block": true,
                            "be_paste_timeout_duration_milliseconds": 0,
                            "be_paste_timeout_response": "block",
                            "be_splash_custom_message": "string",
                            "be_splash_enabled": true,
                            "be_splash_message_source": "default",
                            "be_upload_timeout_duration_seconds": 0,
                            "be_upload_timeout_response": "block",
                            "block_all_data_access": true,
                            "block_notifications": "default",
                            "browsers_without_active_extension": "allow",
                            "classifications": [
                            "string"
                            ],
                            "custom_allow_notification": "string",
                            "custom_block_notification": "string",
                            "enable_clipboard_inspection": true,
                            "enable_content_inspection": true,
                            "enable_context_inspection": true,
                            "enable_end_user_notifications_unsupported_browser": true,
                            "enable_network_inspection": true,
                            "euj_dialog_box_logo": "string",
                            "euj_dialog_timeout": 0,
                            "euj_dropdown_options": {
                            "justifications": [
                                {
                                "default": true,
                                "id": "string",
                                "justification": "string",
                                "selected": true
                                }
                            ]
                            },
                            "euj_header_text": {
                            "headers": [
                                {
                                "default": true,
                                "header": "string",
                                "selected": true
                                }
                            ]
                            },
                            "euj_require_additional_details": true,
                            "euj_response_cache_timeout": 0,
                            "evidence_download_enabled": true,
                            "evidence_duplication_enabled_default": true,
                            "evidence_encrypted_enabled": true,
                            "evidence_storage_free_disk_perc": 0,
                            "evidence_storage_max_size": 0,
                            "inspection_depth": "balanced",
                            "max_file_size_to_inspect": 0,
                            "max_file_size_to_inspect_unit": "Bytes",
                            "min_confidence_level": "low",
                            "network_inspection_files_exceeding_size_limit": "block",
                            "similarity_detection": true,
                            "similarity_threshold": "10",
                            "unsupported_browsers_action": "allow"
                        },
                        "precedence": 0
                        }
                    ]
                }
        description -- The description of the new policy. String.
        name -- The name of the new policy. String.
        policy_properties -- The properties of the new policy. Dictionary.
        precedence -- The order of precedence. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.policy.post.v2
        """
        if not body:
            body = data_protection_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_policy_post_v2",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_policies(self: object,
                        body: dict = None,
                        parameters: dict = None,
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update policies.

        Keyword arguments:
        platform_name -- platform name of the policies to update, either 'win' or 'mac'.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                        "description": "string",
                        "name": "string",
                        "policy_properties": {
                            "allow_notifications": "default",
                            "be_exclude_domains": "string",
                            "be_paste_clipboard_max_size": 0,
                            "be_paste_clipboard_max_size_unit": "Bytes",
                            "be_paste_clipboard_min_size": 0,
                            "be_paste_clipboard_min_size_unit": "Bytes",
                            "be_paste_clipboard_over_size_behaviour_block": true,
                            "be_paste_timeout_duration_milliseconds": 0,
                            "be_paste_timeout_response": "block",
                            "be_splash_custom_message": "string",
                            "be_splash_enabled": true,
                            "be_splash_message_source": "default",
                            "be_upload_timeout_duration_seconds": 0,
                            "be_upload_timeout_response": "block",
                            "block_all_data_access": true,
                            "block_notifications": "default",
                            "browsers_without_active_extension": "allow",
                            "classifications": [
                            "string"
                            ],
                            "custom_allow_notification": "string",
                            "custom_block_notification": "string",
                            "enable_clipboard_inspection": true,
                            "enable_content_inspection": true,
                            "enable_context_inspection": true,
                            "enable_end_user_notifications_unsupported_browser": true,
                            "enable_network_inspection": true,
                            "euj_dialog_box_logo": "string",
                            "euj_dialog_timeout": 0,
                            "euj_dropdown_options": {
                            "justifications": [
                                {
                                "default": true,
                                "id": "string",
                                "justification": "string",
                                "selected": true
                                }
                            ]
                            },
                            "euj_header_text": {
                            "headers": [
                                {
                                "default": true,
                                "header": "string",
                                "selected": true
                                }
                            ]
                            },
                            "euj_require_additional_details": true,
                            "euj_response_cache_timeout": 0,
                            "evidence_download_enabled": true,
                            "evidence_duplication_enabled_default": true,
                            "evidence_encrypted_enabled": true,
                            "evidence_storage_free_disk_perc": 0,
                            "evidence_storage_max_size": 0,
                            "inspection_depth": "balanced",
                            "max_file_size_to_inspect": 0,
                            "max_file_size_to_inspect_unit": "Bytes",
                            "min_confidence_level": "low",
                            "network_inspection_files_exceeding_size_limit": "block",
                            "similarity_detection": true,
                            "similarity_threshold": "10",
                            "unsupported_browsers_action": "allow"
                        },
                        "precedence": 0
                        }
                    ]
                }
        description -- The description of the policy. String.
        name -- The name of the policy. String.
        policy_properties -- The properties of the policy. Dictionary.
        precedence -- The order of precedence. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.policy.patch.v2
        """
        if not body:
            body = data_protection_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_policy_patch_v2",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete policies that match the provided ids.

        Keyword arguments:
        ids -- IDs of the policies to delete. String or list of strings.
        platform_name -- platform name of the policies to update, either 'win' or 'mac'. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.policy.delete.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_policy_delete_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_web_location(self: object,
                         *args,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get web-location entities matching the provided ID(s).

        Keyword arguments:
        ids -- The web-location entity id(s) to get. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /data-protection-configuration/entities.web-location.get-v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_web_location_get_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_web_location(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Persist the given web-locations.

        Keyword arguments:
        application_id -- Associated application ID. String.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "web_locations": [
                        {
                            "application_id": "string",
                            "deleted": true,
                            "enterprise_account_id": "string",
                            "location_type": "string",
                            "name": "string",
                            "provider_location_id": "string",
                            "provider_location_name": "string",
                            "type": "string"
                        }
                    ]
                }
        application_id -- The ID of the application. String.
        deleted -- Flag indicating if this location is deleted. Boolean.
        enterprise_account_id -- Associated enterprise account ID. String.
        location_type -- Location type. String.
        name -- Location name. String.
        provider_location_id -- Provider location ID. String.
        provider_location_name -- Provider location name. String.
        type -- Type. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.web-location.create-v2
        """
        if not body:
            body = data_protection_web_locations_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_web_location_create_v2",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_web_location(self: object,
                            body: dict = None,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a web-location.

        Keyword arguments:
        application_id -- Application ID for the location. String.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "web_locations": [
                        {
                            "application_id": "string",
                            "deleted": true,
                            "enterprise_account_id": "string",
                            "location_type": "string",
                            "name": "string",
                            "provider_location_id": "string",
                            "provider_location_name": "string",
                            "type": "string"
                        }
                    ]
                }
        application_id -- The ID of the application. String.
        deleted -- Flag indicating if this location is deleted. Boolean.
        enterprise_account_id -- Associated enterprise account ID. String.
        location_type -- Location type. String.
        name -- Location name. String.
        provider_location_id -- Provider location ID. String.
        provider_location_name -- Provider location name. String.
        type -- Type. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.web-location.patch-v2
        """
        if not body:
            body = data_protection_web_locations_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_web_location_patch_v2",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_web_location(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete web-location.

        Keyword arguments:
        ids -- The IDs of the web-location to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/entities.web-location.delete-v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_web_location_delete_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_classifications(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for classifications that match the provided criteria.

        Keyword arguments:
        filter -- Filter results by specific attributes. String.
                  Allowed attributes are:
                    created_by                  modified_by
                    modified_at                 properties.content_patterns
                    properties.file_types       properties.evidence_duplication_enabled
                    properties.protection_mode  properties.sensitivity_labels
                    properties.web_sources      name
                    created_at
        offset -- The offset to start retrieving records from. Integer.
        limit -- The maximum records to return. Integer.
        sort -- The property to sort by. String.
                Allowed fields are:
                    name        created_at
                    modified_at
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/queries.classification.get.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_classification_get_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_cloud_applications(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get all cloud-application IDs matching the query with filter.

        Keyword arguments:
        filter -- Optional filter for searching cloud applications. String.
                  Allowed filters are:
                    name                    type
                    deleted                 supports_network_inspection
                    application_group_id
        sort -- The sort instructions to order by on. String.
                Allowed values are:
                    name                    type
                    deleted                 supports_network_inspection
                    application_group_id
        limit -- The number of items to return in this response (default: 100, max: 500). Integer.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/queries.cloud-application.get-v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_cloud_application_get_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_content_patterns(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get all content-pattern IDs matching the query with filter.

        Keyword arguments:
        filter -- The filter to use when finding content patterns. String.
                  Allowed filters are:
                    name          type
                    category      region
                    example       created_at
                    updated_at    deleted'
        sort -- The sort instructions to order by on. String.
                Allowed values are:
                  name          type
                  category      region
                  example       created_at
                  updated_at    deleted'
        limit -- The number of items to return in this response (default: 100, max: 500). Integer.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/queries.content-pattern.get-v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_content_pattern_get_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_enterprise_accounts(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get all enterprise-account IDs matching the query with filter.

        Keyword arguments:
        filter -- The filter to use when finding enterprise accounts. String.
                  Allowed filters are:
                    name          application_group_id
                    deleted       created_at
                    updated_at
        sort -- The sort instructions to order by on. Integer.
                Allowed values are:
                  name          application_group_id
                  deleted       created_at
                  updated_at
        limit -- The number of items to return in this response (default: 100, max: 500). Integer.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/queries.enterprise-account.get-v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_enterprise_account_get_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_file_type(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get all file-type IDs matching the query with filter.

        Keyword arguments:
        filter -- The filter to use when finding file types. String.
                  Allowed filters are:
                    name          created_at
                    updated_at
        sort -- The sort instructions to order by on. String.
                Allowed values are
                  name          created_at
                  updated_at
        limit -- The number of items to return in this response (default: 100, max: 500). Integer.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/queries.file-type.get-v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_file_type_get_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_sensitivity_label(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get all sensitivity label IDs matching the query with filter.

        Keyword arguments:
        filter -- The filter to use when finding sensitivity labels. String.
                  The only allowed filters are:
                    name          display_name
                    external_id   deleted
        sort -- The sort instructions to order by on. String.
                Allowed values are:
                  name          display_name
                  deleted       created_at
                  updated_at
        limit -- The number of items to return in this response (default: 100, max: 500). Integer.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/queries.sensitivity-label.get-v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_sensitivity_label_get_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for policies that match the provided criteria.

        Keyword arguments:
        platform_name -- platform name of the policies to search, either 'win' or 'mac'. String.
        filter -- Filter results by specific attributes. String.
                  Allowed attributes are:
                    properties.max_file_size_to_inspect                       description
                    is_default                                                properties.be_upload_timeout_duration_seconds
                    created_by                                                modified_at
                    properties.enable_content_inspection                      properties.similarity_threshold
                    properties.block_notifications                            properties.custom_allow_notification
                    properties.evidence_duplication_enabled_default           properties.be_paste_timeout_response
                    properties.inspection_depth                               properties.classifications
                    properties.be_paste_clipboard_max_size                    properties.min_confidence_level
                    properties.evidence_storage_free_disk_perc                properties.besplash_enabled
                    properties.browsers_without_active_extension              modified_by
                    created_at                                                properties.enable_network_inspection
                    properties.enable_context_inspection                      properties.besplash_custom_message
                    properties.besplash_message_source                        properties.be_paste_clipboard_max_size_unit
                    properties.be_paste_clipboard_min_size_unit               properties.max_file_size_to_inspect_unit
                    properties.network_inspection_files_exceeding_size_limit  properties.evidence_encrypted_enabled
                    properties.similarity_detection                           properties.enable_clipboard_inspection
                    properties.allow_notifications                            properties.evidence_download_enabled
                    properties.be_exclude_domains                             properties.be_upload_timeout_response
                    properties.unsupported_browsers_action                    precedence is_enabled
                    properties.custom_block_notification                      properties.evidence_storage_max_size
                    properties.be_paste_clipboard_min_size                    name
                    properties.block_all_data_access
                    properties.be_paste_clipboard_over_size_behaviour_block
                    properties.enable_end_user_notifications_unsupported_browser
                    properties.be_paste_timeout_duration_milliseconds
        offset -- The offset to start retrieving records from. Integer.
        limit -- The maximum records to return. Integer.
        sort -- The property to sort by. String.
                Allowed fields are:
                    name        precedence
                    created_at  modified_at
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/queries.policy.get.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_policy_get_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_web_locations(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get web-location IDs matching the query with filter.

        Keyword arguments:
        filter -- The filter to use when finding web locations. String.
                  Allowed filters:
                    name                      type
                    deleted                   application_id
                    provider_location_id      enterprise_account_id
        type -- The type of entity to query. String. Allowed values are:
                predefined  custom
        limit -- The number of items to return in this response (default: 100, max: 500).
        Use with the offset parameter to manage pagination of results. Integer.
        offset -- The offset to start retrieving records from. Integer.
        Use with the limit parameter to manage pagination of results. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/data-protection-configuration/queries.web-location.get-v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_web_location_get_v2",
            keywords=kwargs,
            params=parameters
            )

    entities_classification_get_v2 = get_classification
    entities_classification_post_v2 = create_classification
    entities_classification_patch_v2 = update_classifications
    entities_classification_delete_v2 = delete_classification
    entities_cloud_application_get = get_cloud_application
    entities_cloud_application_create = create_cloud_application
    entities_cloud_application_patch = update_cloud_application
    entities_cloud_application_delete = delete_cloud_application
    entities_content_pattern_get = get_content_pattern
    entities_content_pattern_create = create_content_pattern
    entities_content_pattern_patch = update_content_pattern
    entities_content_pattern_delete = delete_content_pattern
    entities_enterprise_account_get = get_enterprise_account
    entities_enterprise_account_create = create_enterprise_account
    entities_enterprise_account_patch = update_enterprise_account
    entities_enterprise_account_delete = delete_enterprise_account
    entities_file_type_get = get_file_type
    entities_sensitivity_label_get_v2 = get_sensitivity_label
    entities_sensitivity_label_create_v2 = create_sensitivity_label
    entities_sensitivity_label_delete_v2 = delete_sensitivity_label
    entities_policy_get_v2 = get_policies
    entities_policy_post_v2 = create_policy
    entities_policy_patch_v2 = update_policies
    entities_policy_delete_v2 = delete_policies
    entities_web_location_get_v2 = get_web_location
    entities_web_location_create_v2 = create_web_location
    entities_web_location_patch_v2 = update_web_location
    entities_web_location_delete_v2 = delete_web_location
    queries_classification_get_v2 = query_classifications
    queries_cloud_application_get_v2 = query_cloud_applications
    queries_content_pattern_get_v2 = query_content_patterns
    queries_enterprise_account_get_v2 = query_enterprise_accounts
    queries_file_type_get_v2 = query_file_type
    queries_sensitivity_label_get_v2 = query_sensitivity_label
    queries_policy_get_v2 = query_policies
    queries_web_location_get_v2 = query_web_locations
