"""Falcon Discover registration for Azure / GCP API Interface Class.

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
from ._payload import (
    azure_registration_payload,
    aws_d4c_registration_payload,
    gcp_registration_payload,
    cspm_service_account_validate_payload
    )
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._d4c_registration import _d4c_registration_endpoints as Endpoints


class D4CRegistration(ServiceClass):
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
    def get_aws_account(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return information about the current status of an AWS account.

        Keyword arguments:
        ids -- List of AWS Account IDs to retrieve. String or list of strings.
        limit -- The maximum records to return. Defaults to 100. Integer.
        migrated -- Only return migrated D4C accounts. Boolean.
        offset -- The offset to start retrieving records from. Integer.
        organization_ids -- List of AWS Organization IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.
        scan_type -- Type of scan, `dry` or `full`, to perform on selected accounts.
        status -- Account status to filter results by. String.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetD4CAwsAccount
        """
        if kwargs.get("scan_type", None):
            kwargs["scan-type"] = kwargs.get("scan_type", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetD4CAwsAccount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_aws_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Register a new AWS account.

        Creates a new account in our system for a customer and generates a
        script for them to run in their AWS cloud environment to grant us access.

        Keyword arguments:
        account_id -- AWS account ID. String.
        account_type -- AWS account type. String.
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                        {
                            "account_id": "string",
                            "account_type": "string",
                            "cloudtrail_region": "string",
                            "iam_role_arn": "string",
                            "is_master": true,
                            "organization_id": "string"
                        }
                    ]
                }
        cloudtrail_region -- AWS region for CloudTrail log access. String.
        iam_role_arn -- AWS IAM role ARN. String.
        is_master -- Flag indicating if this is the master account. Boolean.
        organization_id -- AWS organization ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/CreateD4CAwsAccount
        """
        if not body:
            body = aws_d4c_registration_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateD4CAwsAccount",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_aws_account(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete an existing AWS account or organization from the tenant.

        Keyword arguments:
        ids -- List of AWS Account IDs to retrieve. String or list of strings.
        organization_ids -- List of AWS Organization IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/DeleteD4CAwsAccount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteD4CAwsAccount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_aws_console_setup(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return a URL for customer to visit in their cloud environment to grant CrowdStrike access.

        Keyword arguments:
        region -- AWS region to generate the URL for. String.
        parameters -- full parameters payload, not required if region is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'region'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetD4CAwsConsoleSetupURLs
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetD4CAwsConsoleSetupURLs",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "region")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_aws_account_scripts(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return a script for customer to run in their cloud environment to grant CrowdStrike access.

        Keyword arguments:
        ids -- AWS account IDs. String.
        template -- Template to be rendered. String
        accounts -- The list of accounts to register. String or list of strings.
        behavior_assessment_enabled -- Available values: true, false. Boolean.
        sensor_management_enabled -- Available values: true, false. Boolean.
        dspm_enabled -- Available values: true, false. Boolean.
        dspm_regions -- DSPM Regions. String.
        dspm_host_account_id -- DSPM Host Account ID. String.
        dspm_host_integration_role_name -- DSPM Host Integration Role Name. String.
        dspm_host_scanner_role_name -- DSPM Host Scanner Role Name. String.
        dspm_role -- DSPM Role. String.
        vulnerability_scanning_enabled -- Enabled. Available values: true, false. Boolean.

        vulnerability_scanning_regions -- Regions. String or list of strings.
        vulnerability_scanning_host_account_id -- Account ID. String.
        vulnerability_scanning_host_integration_role_name -- Host Integration Role Name. String.
        vulnerability_scanning_host_scanner_role_name -- Host Scanner Role Name. String.
        vulnerability_scanning_role -- Role. String.
        use_existing_cloudtrail -- Use Existing CloudTrail. Available values: true, false. Boolean.
        organization_id -- The AWS organization ID to be registered. String.
        organizational_unit_ids -- The AWS Organizational Unit IDs to be registered. String or list of strings.
        aws_profile -- The AWS profile to be used during registration. String.
        aws_region -- The AWS region to be used during registration. String.
        iam_role_arn -- The custom IAM role to be used during registration. String.
        falcon_client_id -- The Falcon client ID used during registration. String.
        idp_enabled -- Set to true to enable Identity Protection feature. String.
        tags -- Base64 encoded JSON string to be used as AWS tags. String.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetD4CAWSAccountScriptsAttachment
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetD4CAWSAccountScriptsAttachment",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_azure_account(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return information about Azure account registration.

        Keyword arguments:
        ids -- List of Azure Account IDs to retrieve. If this is empty then all accounts are returned.
               String or list of strings.
        limit -- The maximum records to return. Defaults to 100. Integer.
        offset -- The offset to start retrieving records from. Integer.
        parameters -- full parameters payload, not required if ids is provided as a keyword.
        scan_type -- Type of scan, `dry` or `full`, to perform on selected accounts.
        status -- Account status to filter results by, 'provisioned' or 'operational'. String.
        tenant_ids -- Tenant ids to filter azure accounts returned. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetDiscoverCloudAzureAccount
        """
        if kwargs.get("scan_type", None):
            kwargs["scan-type"] = kwargs.get("scan_type", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetDiscoverCloudAzureAccount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_azure_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Register a new Azure account.

        Creates a new account in our system for a customer and generates a
        script for them to run in their cloud environment to grant us access.

        Keyword arguments:
        account_type -- Azure Account type. String.
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                        {
                            "account_type": "string",
                            "client_id": "string",
                            "default_subscription": true,
                            "subscription_id": "string",
                            "tenant_id": "string",
                            "years_valid": integer
                        }
                    ]
                }
        client_id -- Azure Client ID. String.
        default_subscription -- Is this the default subscription? Boolean.
        subscription_id -- Azure subscription ID. String.
        tenant_id -- Azure tenant ID. String.
        years_valid -- Years valid. Integer.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/CreateDiscoverCloudAzureAccount
        """
        if not body:
            body = azure_registration_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateDiscoverCloudAzureAccount",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def update_azure_account_client_id(self: object,
                                       *args,
                                       parameters: dict = None,
                                       **kwargs
                                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Azure account client ID.

        Update an Azure service account in our system by with the
        user-created client_id created with the public key we've provided.

        Keyword arguments:
        id -- ClientID to use for the Service Principal associated
              with the customer's Azure Account.
        object_id -- Object ID to use for the Service Principal associated
                     with the customer's Azure account. String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.
        tenant_id -- Tenant ID to update client ID for.
                     Required if multiple tenants are registered. String.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /d4c-registration/UpdateDiscoverCloudAzureAccountClientID
        """
        if kwargs.get("tenant_id", None):
            kwargs["tenant-id"] = kwargs.get("tenant_id", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateDiscoverCloudAzureAccountClientID",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_azure_user_scripts_attachment(self: object,
                                          parameters: dict = None,
                                          **kwargs
                                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Azure user script attachment.

        Return a script for customer to run in their cloud environment to
        grant us access to their Azure environment as a downloadable attachment.

        Keyword arguments:
        parameters -- full parameters payload, not required if using other keywords.
        azure_management_group - Use Azure Management Group. Boolean.
        subscription_ids -- Azure subscription IDs. String or list of strings.
        template -- Template to be rendered. String.
        tenant_id -- Azure tenant ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /d4c-registration/GetDiscoverCloudAzureUserScriptsAttachment
        """
        if kwargs.get("tenant_id", None):
            kwargs["tenant-id"] = kwargs.get("tenant_id", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetDiscoverCloudAzureUserScriptsAttachment",
            keywords=kwargs,
            params=parameters
            )

    def get_azure_user_scripts(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Azure user script.

        Return a script for customer to run in their cloud
        environment to grant us access to their Azure environment.

        This method does not accept arguments or keywords.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetDiscoverCloudAzureUserScripts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetDiscoverCloudAzureUserScripts"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_gcp_account(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return information about the current status of an GCP account.

        Keyword arguments:
        ids -- Hierarchical Resource IDs of accounts. String or list of strings.
        limit -- The maximum records to return. Defaults to 100. Integer.
        offset -- The offset to start retrieving records from. Integer.
        parameters -- full parameters payload, not required if ids is provided as a keyword.
        parent_type -- GCP Hierarchy Parent Type, organization/folder/project. String.
        scan_type -- Type of scan, `dry` or `full`, to perform on selected accounts.
        sort -- Order fields in ascending or descending order. Ex: parent_type|asc.
        status -- Account status to filter results by, 'operational' or 'provisioned'. String.

        This method does not accept arguments or keywords.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetD4CCGPAccount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetD4CCGPAccount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_gcp_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Register new GCP account.

        Creates a new account in our system for a customer and generates a new service
        account for them to add access to in their GCP environment to grant us access.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                        {
                            "parent_id": "string",
                            "parent_type": "string"
                        }
                    ]
                }
        parent_id -- GCP parent ID. String.
        parent_type -- GCP parent type. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/CreateD4CGCPAccount
        """
        if not body:
            body = gcp_registration_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateD4CGCPAccount",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_gcp_account(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a GCP account from the system.

        Keyword arguments:
        ids -- Hierarchical Resource IDs of accounts. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/DeleteD4CGCPAccount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteD4CGCPAccount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def connect_gcp_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Register new GCP account.

        Creates a new account in our system for a customer and generates a new service
        account for them to add access to in their GCP environment to grant us access.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                        {
                            "client_email": "string",
                            "client_id": "string",
                            "parent_id": "string",
                            "parent_type": "string",
                            "private_key": "string",
                            "private_key_id": "string",
                            "project_id": "string",
                            "service_account_id": 0
                        }
                    ]
                }
        client_email -- GCP account email. String.
        client_id -- GCP account client ID. String.
        parent_id -- GCP parent ID. String.
        parent_type -- GCP parent type. String.
        private_key -- GCP private key. String.
        private_key_id -- GCP private key ID. String.
        project_id -- GCP project ID. String.
        service_account_id -- GCP service account ID. Integer.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/ConnectD4CGCPAccount
        """
        if not body:
            body = gcp_registration_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ConnectD4CGCPAccount",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_gcp_service_account(self: object,
                                *args,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the service account id and client email for external clients.

        Keyword arguments:
        id -- Service Account ID. String.
        parameters -- full parameters payload, not required if id is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetD4CGCPServiceAccountsExt
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetD4CGCPServiceAccountsExt",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_gcp_service_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a GCP service account.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                        {
                            "client_email": "string",
                            "client_id": "string",
                            "private_key": "string",
                            "private_key_id": "string",
                            "project_id": "string",
                            "service_account_conditions": [
                                {
                                    "feature": "string",
                                    "is_visible": boolean,
                                    "last_transition": "UTC date string",
                                    "message": "string",
                                    "reason": "string",
                                    "status": "string",
                                    "type": "string"
                                }
                            ],
                            "service_account_id": 0
                        }
                    ]
                }
        client_email -- Client email associated with the service account. String.
        client_id -- GCP Client ID. String.
        private_key -- GCP private key. String.
        private_key_id -- GCP private key ID. String.
        project_id -- GCP project ID. String.
        resources -- List of GCP service accounts to validate. List of dictionaries.
                     Overrides other keywords except for body.
        service_account_conditions -- GCP service account conditions. List of dictionaries.
        service_account_id -- GCP service account ID. Integer.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/UpdateD4CGCPServiceAccountsExt
        """
        if not body:
            body = cspm_service_account_validate_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateD4CGCPServiceAccountsExt",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_gcp_user_scripts_attachment_v2(self: object,
                                           *args,
                                           parameters: dict = None,
                                           **kwargs
                                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve GCP user script attachment.

        Return a script for customer to run in their cloud environment to
        grant us access to their GCP environment as a downloadable attachment.

        Keyword arguments:
        ids -- Hierarchical Resource IDs of accounts. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.
        parent_type -- GCP Hierarchy Parent Type. String.
                       Allowed values: organization, folder, project
        status -- Account status to filter results by. String.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetD4CGCPUserScriptsAttachment
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetD4CGCPUserScriptsAttachment",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def azure_download_certificate(self: object,
                                   *args,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Download Azure Certificate.

        Returns JSON object(s) that contain the base64 encoded certificate for a service principal.

        Keyword arguments:
        tenant_id -- Azure Tenant ID to generate script for.
                     Defaults to the most recently registered tenant.
        parameters -- full parameters payload, not required if tenant-id keyword is used.
        refresh -- Force a refresh of the certificate. Boolean. Defaults to False.
        years_valid -- Years the certificate should be valid (only used when refresh=true). String.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'tenant_id'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/DiscoverCloudAzureDownloadCertificate
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DiscoverCloudAzureDownloadCertificate",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "tenant_id")
            )

    def get_azure_tenant_ids(self: object) -> dict:
        """Return all available Azure tenant ids.

        This method does not accept keywords or arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetDiscoverCloudAzureTenantIDs
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetDiscoverCloudAzureTenantIDs"
            )

    def get_gcp_user_scripts_attachment(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve GCP user script attachment.

        Return a script for customer to run in their cloud environment to
        grant us access to their GCP environment as a downloadable attachment.

        This method does not accept arguments or keywords.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetCSPMGCPUserScriptsAttachment
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetCSPMGCPUserScriptsAttachment"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_gcp_user_scripts(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve GCP user script.

        Return a script for customer to run in their cloud
        environment to grant us access to their GCP environment.

        Keyword arguments:
        parent_type -- GCP Hierarchy Parent Type, organization/folder/project. String.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'parent_type'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetD4CGCPUserScripts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetD4CGCPUserScripts",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "parent_type")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_aws_horizon_scripts(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return a script for customer to run in their cloud environment to grant CrowdStrike access.

        Keyword arguments:
        account_type -- Account type (commercial, gov). Only applicable when registering AWS
                        commercial accounts in a Gov environment. String.
        delete -- Generate a delete script. Boolean.
        organization_id -- AWS organization ID. String.
        parameters -- full parameters payload, not required if using other keywords.
        single_account -- Get static script for single account. Boolean.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response or a binary script.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration/GetHorizonD4CScripts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetHorizonD4CScripts",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    GetD4CAwsAccount = get_aws_account
    CreateD4CAwsAccount = create_aws_account
    DeleteD4CAwsAccount = delete_aws_account
    GetD4CAwsConsoleSetupURLs = get_aws_console_setup
    GetD4CAWSAccountScriptsAttachment = get_aws_account_scripts
    GetCSPMAzureAccount = get_azure_account
    GetDiscoverCloudAzureAccount = get_azure_account
    CreateCSPMAzureAccount = create_azure_account
    CreateDiscoverCloudAzureAccount = create_azure_account
    UpdateCSPMAzureAccountClientID = update_azure_account_client_id
    UpdateDiscoverCloudAzureAccountClientID = update_azure_account_client_id
    GetCSPMAzureUserScriptsAttachment = get_azure_user_scripts_attachment
    GetDiscoverCloudAzureUserScriptsAttachment = get_azure_user_scripts_attachment
    DiscoverCloudAzureDownloadCertificate = azure_download_certificate
    GetDiscoverCloudAzureTenantIDs = get_azure_tenant_ids
    GetCSPMAzureUserScripts = get_azure_user_scripts
    GetDiscoverCloudAzureUserScripts = get_azure_user_scripts
    GetCSPMGCPAccount = get_gcp_account   # Typo fix
    GetCSPMCGPAccount = get_gcp_account
    GetD4CGCPAccount = get_gcp_account  # Typo fix
    GetD4CCGPAccount = get_gcp_account
    CreateCSPMGCPAccount = create_gcp_account
    CreateD4CGCPAccount = create_gcp_account
    DeleteD4CGCPAccount = delete_gcp_account
    ConnectD4CGCPAccount = connect_gcp_account
    GetD4CGCPUserScriptsAttachment = get_gcp_user_scripts_attachment_v2
    GetD4CGCPServiceAccountsExt = get_gcp_service_account
    UpdateD4CGCPServiceAccountsExt = update_gcp_service_account
    GetCSPMGCPUserScriptsAttachment = get_gcp_user_scripts_attachment
    GetCSPMGCPUserScripts = get_gcp_user_scripts
    GetD4CGCPUserScripts = get_gcp_user_scripts
    GetHorizonD4CScripts = get_aws_horizon_scripts


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
D4C_Registration = D4CRegistration  # pylint: disable=C0103
