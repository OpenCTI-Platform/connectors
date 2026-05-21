"""CrowdStrike Falcon CloudAWSRegistration API interface class.

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
from ._payload import cloud_aws_registration_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._cloud_aws_registration import _cloud_aws_registration_endpoints as Endpoints


class CloudAWSRegistration(ServiceClass):
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
    def trigger_health_check(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Trigger health check scan for AWS accounts.

        Keyword arguments:
        account_ids -- AWS Account IDs. String or list of strings.
        organization_ids -- Organization IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-aws-registration/cloud-registration-aws-trigger-health-check
        """
        kwargs["organization-ids"] = kwargs.get("organization_ids", None)
        kwargs["account-ids"] = kwargs.get("account_ids", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_aws_trigger_health_check",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_accounts(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve existing AWS accounts by account IDs.

        Keyword arguments:
        ids -- AWS account IDs to filter. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-aws-registration/cloud-registration-aws-get-accounts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_aws_get_accounts",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new account.

        Keyword arguments:
        body -- Full body payload as a JSON dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                        "account_id": "string",
                        "account_type": "string",
                        "csp_events": true,
                        "is_master": true,
                        "organization_id": "string",
                        "products": [
                            {
                                "features": [
                                    "string"
                                ],
                                "product": "string"
                            }
                        ]
                        }
                    ]
                }
        account_id -- AWS account ID. String.
        account_type -- AWS account type. String.
        csp_events -- Flag indicating if CSP events should be included. Boolean.
        is_master -- Flag indicating if this is a master account. Boolean.
        organization_id -- AWS organization ID. String.
        products -- List of included products and features. List of dictionaries.
                    [
                        {
                            "features": [
                                "string"
                            ],
                            "product": "string"
                        }
                    ]

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-aws-registration/cloud-registration-aws-create-account
        """
        if not body:
            body = cloud_aws_registration_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_aws_create_account",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update an existing account.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "resources": [
                        {
                        "account_id": "string",
                        "account_type": "string",
                        "csp_events": true,
                        "is_master": true,
                        "organization_id": "string",
                        "products": [
                            {
                                "features": [
                                    "string"
                                ],
                                "product": "string"
                            }
                        ]
                        }
                    ]
                }
        account_id -- AWS account ID. String.
        account_type -- AWS account type. String.
        csp_events -- Flag indicating if CSP events should be included. Boolean.
        is_master -- Flag indicating if this is a master account. Boolean.
        organization_id -- AWS organization ID. String.
        products -- List of included products and features. List of dictionaries.
                    [
                        {
                            "features": [
                                "string"
                            ],
                            "product": "string"
                        }
                    ]

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-aws-registration/cloud-registration-aws-update-account
        """
        if not body:
            body = cloud_aws_registration_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_aws_update_account",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_account(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete an existing AWS account or organization.

        Keyword arguments:
        ids -- AWS account IDs to remove. String or list of strings.
        organization_ids -- AWS organization IDs to remove. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-aws-registration/cloud-registration-aws-delete-account
        """
        kwargs["organization-ids"] = kwargs.get("organization_ids", None)
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_aws_delete_account",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def validate_accounts(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Validate the AWS account registration status, and discover organization child accounts if organization is specified.

        Keyword arguments:
        account_id -- AWS Account ID. organization-id shouldn't be specified if this is specified. String.
        iam_role_arn -- IAM Role ARN. String.
        organization_id -- AWS organization ID to validate master account.
        account_id shouldn't be specified if this is specified. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-aws-registration/cloud-registration-aws-validate-accounts
        """
        kwargs["iam-role-arn"] = kwargs.get("iam_role_arn", None)
        kwargs["organization-id"] = kwargs.get("organization_id", None)
        kwargs["account-id"] = kwargs.get("account_id", None)
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_aws_validate_accounts",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_accounts(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve existing AWS accounts by account IDs.

        Keyword arguments:
        organization_ids -- Organization IDs used to filter accounts. String or list of string.
        products -- Products registered for an account. String or list of string. Required.
        features -- Features registered for an account. String or list of string. Required.
        account_status -- Account status to filter results by. String.
        limit -- The maximum number of items to return. When not specified or 0, 100 is used.
                 When larger than 500, 500 is used. Integer.
        offset -- The offset to start retrieving records from. Integer.
        group_by -- Field to group by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-aws-registration/cloud-registration-aws-query-accounts
        """
        kwargs["organization-ids"] = kwargs.get("organization_ids", None)
        kwargs["account-status"] = kwargs.get("account_status", None)
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_registration_aws_query_accounts",
            keywords=kwargs,
            params=parameters
            )

    cloud_registration_aws_trigger_health_check = trigger_health_check
    cloud_registration_aws_get_accounts = get_accounts
    cloud_registration_aws_create_account = create_account
    cloud_registration_aws_update_account = update_account
    cloud_registration_aws_delete_account = delete_account
    cloud_registration_aws_validate_accounts = validate_accounts
    cloud_registration_aws_query_accounts = query_accounts
