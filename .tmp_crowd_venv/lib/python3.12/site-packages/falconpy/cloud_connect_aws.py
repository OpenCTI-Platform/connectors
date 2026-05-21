"""CrowdStrike Falcon Discover for AWS API Interface Class.

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
from ._payload import aws_registration_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._cloud_connect_aws import _cloud_connect_aws_endpoints as Endpoints


class CloudConnectAWS(ServiceClass):
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
    def query_aws_accounts(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for provisioned AWS Accounts by providing an FQL filter and paging details.

        Returns a set of AWS accounts which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum records to return. [1-500]. Defaults to 100.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by (e.g. alias.desc or state.asc). FQL syntax.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws/QueryAWSAccounts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryAWSAccounts",
            keywords=kwargs,
            params=parameters
            )

    def get_aws_settings(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a set of Global Settings which are applicable to all provisioned AWS accounts.

        This method does not accept arguments or keywords.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws/GetAWSSettings
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAWSSettings"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_aws_accounts(self: object,
                         *args,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a set of AWS Accounts by specifying their IDs.

        Keyword arguments:
        ids -- List of AWS Account IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws/GetAWSAccounts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAWSAccounts",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def provision_aws_accounts(self: object,
                               body: dict,
                               parameters: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provision AWS Accounts by specifying details about the accounts to provision.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                            {
                                "cloudtrail_bucket_owner_id": "string",
                                "cloudtrail_bucket_region": "string",
                                "external_id": "string",
                                "iam_role_arn": "string",
                                "id": "string",
                                "rate_limit_reqs": integer,
                                "rate_limit_time": integer
                            }
                        ]
                    }
        cloudtrail_bucket_owner_id -- AWS IAM ID for bucket owner. String.
        cloudtrail_bucket_region -- AWS region for bucket. String.
        external_id -- AWS cross-account role secret. String.
        iam_role_arn -- ARN used for cross-account role. String.
        id -- AWS account ID. String.
        mode -- Mode for provisioning. Allowed values are `manual` or `cloudformation`.
                Defaults to `manual` if not defined.
        parameters -- full parameters payload, not required if mode is provided as a keyword.
        rate_limit_reqs -- Integer.
        rate_limit_time -- Integer.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws/ProvisionAWSAccounts
        """
        if not body:
            body = aws_registration_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ProvisionAWSAccounts",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_aws_accounts(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a set of AWS Accounts by specifying their IDs.

        Keyword arguments:
        ids -- List of AWS Account IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws/DeleteAWSAccounts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteAWSAccounts",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_aws_accounts(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update AWS Accounts by specifying the ID of the account and details to update.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                            {
                                "cloudtrail_bucket_owner_id": "string",
                                "cloudtrail_bucket_region": "string",
                                "external_id": "string",
                                "iam_role_arn": "string",
                                "id": "string",
                                "rate_limit_reqs": integer,
                                "rate_limit_time": integer
                            }
                    ]
                }
        cloudtrail_bucket_owner_id -- AWS IAM ID for bucket owner. String.
        cloudtrail_bucket_region -- AWS region for bucket. String.
        external_id -- AWS cross-account role secret. String.
        iam_role_arn -- ARN used for cross-account role. String.
        id -- AWS account ID. String.
        rate_limit_reqs -- Integer.
        rate_limit_time -- Integer.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws/UpdateAWSAccounts
        """
        if not body:
            body = aws_registration_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateAWSAccounts",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_or_update_aws_settings(self: object,
                                      body: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create or update Global Settings which are applicable to all provisioned AWS accounts.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                        {
                            "cloudtrail_bucket_owner_id": "string",
                            "static_external_id": "string"
                        }
                    ]
                }
        cloudtrail_bucket_owner_id -- AWS IAM ID for bucket owner. String.
        static_external_id -- AWS cross-account role secret. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws/CreateOrUpdateAWSSettings
        """
        if not body:
            body = aws_registration_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateOrUpdateAWSSettings",
            body=body
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict"])
    def verify_aws_account_access(self: object,
                                  *args,
                                  body: dict = None,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform an Access Verification check on the specified AWS Account IDs.

        Keyword arguments:
        body -- full body payload, ignored by API.
        ids -- List of AWS Account IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws/VerifyAWSAccountAccess
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="VerifyAWSAccountAccess",
            keywords=kwargs,
            body=body,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_aws_accounts_for_ids(self: object,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for provisioned AWS Accounts by providing an FQL filter and paging details.

        Returns a set of AWS account IDs which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum records to return. [1-500]. Defaults to 100.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by (e.g. alias.desc or state.asc). FQL syntax.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws/QueryAWSAccountsForIDs
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryAWSAccountsForIDs",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    QueryAWSAccounts = query_aws_accounts
    GetAWSSettings = get_aws_settings
    GetAWSAccounts = get_aws_accounts
    ProvisionAWSAccounts = provision_aws_accounts
    DeleteAWSAccounts = delete_aws_accounts
    UpdateAWSAccounts = update_aws_accounts
    CreateOrUpdateAWSSettings = create_or_update_aws_settings
    VerifyAWSAccountAccess = verify_aws_account_access
    QueryAWSAccountsForIDs = query_aws_accounts_for_ids


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Cloud_Connect_AWS = CloudConnectAWS  # pylint: disable=C0103
