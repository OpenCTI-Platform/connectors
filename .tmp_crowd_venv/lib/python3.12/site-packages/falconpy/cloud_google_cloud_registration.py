"""CrowdStrike Falcon CloudGoogleCloudRegistration API interface class.

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
from ._endpoint._cloud_google_cloud_registration import _cloud_google_cloud_registration_endpoints as Endpoints
from ._payload import cloud_google_registration_create_payload


class CloudGoogleCloudRegistration(ServiceClass):
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
    def trigger_health_check(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Trigger health check scan for GCP registrations.

        Keyword arguments:
        ids -- GCP Registration IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-google-cloud-registration/cloud-registration-gcp-trigger-health-check
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_gcp_trigger_health_check",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_registration(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a Google Cloud Registration.

        Keyword arguments:
        ids -- Google Cloud Registration ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-google-cloud-registration/cloud-registration-gcp-get-registration
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_gcp_get_registration",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_registration(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new Google Cloud Registration if one doesnt exist or update the existing Google Cloud Registration.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "deployment_method": "string",
                            "entity_id": [
                                "string"
                            ],
                            "excluded_project_patterns": [
                                "string"
                            ],
                            "falcon_client_key_id": "string",
                            "falcon_client_key_type": "string",
                            "infra_manager_region": "string",
                            "infra_project_id": "string",
                            "labels": {
                                "additionalProp1": "string",
                                "additionalProp2": "string",
                                "additionalProp3": "string"
                            },
                            "products": [
                                {
                                "features": [
                                    "string"
                                ],
                                "product": "string"
                                }
                            ],
                            "registration_name": "string",
                            "registration_scope": "string",
                            "resource_name_prefix": "string",
                            "resource_name_suffix": "string",
                            "tags": {
                                "additionalProp1": "string",
                                "additionalProp2": "string",
                                "additionalProp3": "string"
                            },
                            "wif_project_id": "string"
                        }
                    ]
                }
        deployment_method -- The method of deployment. String.
        entity_id -- The ID of the entity. String.
        excluded_project_patterns -- Project patterns that should be excluded. List of Strings.
        falcon_client_key_id -- API client key ID. String.
        falcon_client_key_type -- API client key type. String.
        infra_project_id -- Infrastructure project ID. String.
        labels -- Prop labels. Dictionary.
        products -- Products. List of dictionaries.
        registration_name -- Registration name. String.
        registration_scope -- Registration scope. String.
        resource_name_prefix -- Resource name prefix. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PUT

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-google-cloud-registration/cloud-registration-gcp-put-registration
        """
        if not body:
            body = cloud_google_registration_create_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_gcp_put_registration",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_registration(self: object,
                            body: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:  # noqa: E501, pylint: disable=C0301
        """Create a Google Cloud Registration.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "deployment_method": "string",
                            "entity_id": [
                                "string"
                            ],
                            "excluded_project_patterns": [
                                "string"
                            ],
                            "falcon_client_key_id": "string",
                            "falcon_client_key_type": "string",
                            "infra_manager_region": "string",
                            "infra_project_id": "string",
                            "labels": {
                                "additionalProp1": "string",
                                "additionalProp2": "string",
                                "additionalProp3": "string"
                            },
                            "products": [
                                {
                                "features": [
                                    "string"
                                ],
                                "product": "string"
                                }
                            ],
                            "registration_name": "string",
                            "registration_scope": "string",
                            "resource_name_prefix": "string",
                            "resource_name_suffix": "string",
                            "tags": {
                                "additionalProp1": "string",
                                "additionalProp2": "string",
                                "additionalProp3": "string"
                            },
                            "wif_project_id": "string"
                        }
                    ]
                }
        deployment_method -- The method of deployment. String.
        entity_id -- The ID of the entity. String.
        excluded_project_patterns -- Project patterns that should be excluded. List of Strings.
        falcon_client_key_id -- API client key ID. String.
        falcon_client_key_type -- API client key type. String.
        infra_project_id -- Infrastructure project ID. String.
        labels -- Prop labels. Dictionary.
        products -- Products. List of dictionaries.
        registration_name -- Registration name. String.
        registration_scope -- Registration scope. String.
        resource_name_prefix -- Resource name prefix. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-google-cloud-registration/cloud-registration-gcp-create-registration
        """
        if not body:
            body = cloud_google_registration_create_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_gcp_create_registration",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def cloud_registration_gcp_update_registration(self: object,
                                                   body: dict = None,
                                                   parameters: dict = None,
                                                   **kwargs
                                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a Google Cloud Registration.

        Keyword arguments:
        ids -- Google Cloud Registration ID. String.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "deployment_method": "string",
                            "entity_id": [
                                "string"
                            ],
                            "excluded_project_patterns": [
                                "string"
                            ],
                            "falcon_client_key_id": "string",
                            "falcon_client_key_type": "string",
                            "infra_manager_region": "string",
                            "infra_project_id": "string",
                            "labels": {
                                "additionalProp1": "string",
                                "additionalProp2": "string",
                                "additionalProp3": "string"
                            },
                            "products": [
                                {
                                "features": [
                                    "string"
                                ],
                                "product": "string"
                                }
                            ],
                            "registration_name": "string",
                            "registration_scope": "string",
                            "resource_name_prefix": "string",
                            "resource_name_suffix": "string",
                            "tags": {
                                "additionalProp1": "string",
                                "additionalProp2": "string",
                                "additionalProp3": "string"
                            },
                            "wif_project_id": "string"
                        }
                    ]
                }
        deployment_method -- The method of deployment. String.
        entity_id -- The ID of the entity. String.
        excluded_project_patterns -- Project patterns that should be excluded. List of Strings.
        falcon_client_key_id -- API client key ID. String.
        falcon_client_key_type -- API client key type. String.
        infra_project_id -- Infrastructure project ID. String.
        labels -- Prop labels. Dictionary.
        products -- Products. List of dictionaries.
        registration_name -- Registration name. String.
        registration_scope -- Registration scope. String.
        resource_name_prefix -- Resource name prefix. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-google-cloud-registration/cloud-registration-gcp-update-registration
        """
        if not body:
            body = cloud_google_registration_create_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_gcp_update_registration",
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_registration(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a Google Cloud Registration and return the deleted registration in the response body.

        Keyword arguments:
        ids -- Google Cloud Registration ID. String
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL

        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_gcp_delete_registration",
            keywords=kwargs,
            params=parameters
            )

    cloud_registration_gcp_trigger_health_check = trigger_health_check
    cloud_registration_gcp_get_registration = get_registration
    cloud_registration_gcp_put_registration = update_registration
    cloud_registration_gcp_create_registration = create_registration
    cloud_registration_gcp_update_registration = cloud_registration_gcp_update_registration
    cloud_registration_gcp_delete_registration = delete_registration
