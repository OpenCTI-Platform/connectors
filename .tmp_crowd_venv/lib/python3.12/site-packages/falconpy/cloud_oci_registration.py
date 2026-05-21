"""CrowdStrike Falcon CloudOCIRegistration API interface class.

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
from ._payload import cloud_oci_refresh_payload, cloud_oci_validate_payload, cloud_oci_create_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._cloud_oci_registration import _cloud_oci_registration_endpoints as Endpoints


class CloudOCIRegistration(ServiceClass):
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
    def get_account(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a list of OCI tenancies with support for FQL filtering, sorting, and pagination.

        Keyword arguments:
        filter -- FQL (Falcon Query Language) string for filtering results. String.
                  Allowed filters:
                    tenancy_name      created_at
                    home_region       updated_at
                    key_age           tenancy_ocid
                    overall_status
        sort -- Field and direction for sorting results. String.
                Allowed sort fields:
                    tenancy_name        created_at
                    home_region         updated_at
                    key_age             tenancy_ocid
                    overall_status
        next_token -- Token for cursor-based pagination. String. Currently unsupported.
        limit -- Maximum number of records to return. Integer. (default: 100, max: 10000)
        offset -- Starting index of result. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /cloud-oci-registration/cloud-security-registration-oci-get-account
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_security_registration_oci_get_account",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def rotate_key(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Refresh key for the OCI tenancy.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                          "tenancy_ocid": "string"
                        }
                    ]
                }
        tenancy_ocid -- OCI tenancy ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /cloud-oci-registration/cloud-security-registration-oci-rotate-key
        """
        if not body:
            body = cloud_oci_refresh_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_security_registration_oci_rotate_key",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def validate_tenancy(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Validate the OCI account in CSPM for a provided CID. For internal clients only.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "products": [
                                {
                                    "features": [
                                        "string"
                                    ],
                                    "product": "string"
                                }
                            ],
                            "tenancy_ocid": "string"
                        }
                    ]
                }
        products -- OCI products to validate. List of dictionaries.
        tenancy_ocid -- OCI tenancy ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /cloud-oci-registration/cloud-security-registration-oci-validate-tenancy
        """
        if not body:
            body = cloud_oci_validate_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_security_registration_oci_validate_tenancy",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create an OCI tenancy account.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "group_name": "string",
                            "home_region": "string",
                            "policy_name": "string",
                            "products": [
                                {
                                    "features": [
                                        {
                                            "deployment_method": "string",
                                            "feature": "string",
                                            "is_enabled": true,
                                            "persona": "string",
                                            "registration_detailed_status": "string"
                                        }
                                    ],
                                    "product": "string"
                                }
                            ],
                            "tenancy_ocid": "string",
                            "user_email": "string",
                            "user_name": "string"
                        }
                    ]
                }
        group_name -- OCI group name. String.
        home_region -- OCI home region. String.
        policy_name -- Policy name. String.
        products -- OCI products. List of dictionaries.
        tenancy_ocid -- OCI tenancy ID. String.
        user_email -- User email address. String.
        user_name -- OCI user name. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /cloud-oci-registration/cloud-security-registration-oci-create-account
        """
        if not body:
            body = cloud_oci_create_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_security_registration_oci_create_account",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update an existing OCI account.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "group_name": "string",
                            "home_region": "string",
                            "policy_name": "string",
                            "products": [
                                {
                                    "features": [
                                        {
                                            "deployment_method": "string",
                                            "feature": "string",
                                            "is_enabled": true,
                                            "persona": "string",
                                            "registration_detailed_status": "string"
                                        }
                                    ],
                                    "product": "string"
                                }
                            ],
                            "stack_ocid": "string",
                            "tenancy_ocid": "string",
                            "user_email": "string",
                            "user_name": "string",
                            "user_ocid": "string"
                        }
                    ]
                }
        group_name -- OCI group name. String.
        home_region -- OCI home region. String.
        policy_name -- Policy name. String.
        products -- OCI products. List of dictionaries.
        stack_ocid -- OCI stack ID. String.
        tenancy_ocid -- OCI tenancy ID. String.
        user_email -- User email address. String.
        user_name -- OCI user name. String.
        user_ocid -- OCI user ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /cloud-oci-registration/cloud-security-registration-oci-update-account
        """
        if not body:
            body = cloud_oci_create_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_security_registration_oci_update_account",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_account(self: object,
                       *args,
                       parameters: dict = None,
                       **kwargs
                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete an existing OCI tenancy.

        Keyword arguments:
        ids -- OCI tenancy OCIDs to remove.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /cloud-oci-registration/cloud-security-registration-oci-delete-account
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_security_registration_oci_delete_account",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def download_script(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve script to create resources in tenancy OCID.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "deployment_method": "string",
                            "is_download": boolean,
                            "tenancy_ocid": "string"
                        }
                    ]
                }
        deployment_method -- Deployment method. String.
        is_download -- Flag indicating if the script is intended for download. Boolean.
        tenancy_ocid -- OCI tenancy ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /cloud-oci-registration/cloud-security-registration-oci-download-script
        """
        if not body:
            body = cloud_oci_refresh_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_security_registration_oci_download_script",
            body=body
            )

    cloud_security_registration_oci_get_account = get_account
    cloud_security_registration_oci_rotate_key = rotate_key
    cloud_security_registration_oci_validate_tenancy = validate_tenancy
    cloud_security_registration_oci_create_account = create_account
    cloud_security_registration_oci_update_account = update_account
    cloud_security_registration_oci_delete_account = delete_account
    cloud_security_registration_oci_download_script = download_script
