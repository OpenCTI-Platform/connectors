"""Internal API endpoint constant library.

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

_cloud_connect_aws_endpoints = [
  [
    "QueryAWSAccounts",
    "GET",
    "/cloud-connect-aws/combined/accounts/v1",
    "Search for provisioned AWS Accounts by providing an FQL filter and paging details. Returns a set of AWS "
    "accounts which match the filter criteria",
    "cloud_connect_aws",
    [
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. [1-1000]. Defaults to 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The property to sort by (e.g. alias.desc or state.asc)",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "GetAWSSettings",
    "GET",
    "/cloud-connect-aws/combined/settings/v1",
    "Retrieve a set of Global Settings which are applicable to all provisioned AWS accounts",
    "cloud_connect_aws",
    []
  ],
  [
    "GetAWSAccounts",
    "GET",
    "/cloud-connect-aws/entities/accounts/v1",
    "Retrieve a set of AWS Accounts by specifying their IDs",
    "cloud_connect_aws",
    [
      {
        "maxItems": 5000,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of accounts to retrieve details",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ProvisionAWSAccounts",
    "POST",
    "/cloud-connect-aws/entities/accounts/v1",
    "Provision AWS Accounts by specifying details about the accounts to provision",
    "cloud_connect_aws",
    [
      {
        "enum": [
          "cloudformation",
          "manual"
        ],
        "type": "string",
        "default": "manual",
        "description": "Mode for provisioning. Allowed values are manual or cloudformation. Defaults to manual "
        "if not defined.",
        "name": "mode",
        "in": "query"
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateAWSAccounts",
    "PATCH",
    "/cloud-connect-aws/entities/accounts/v1",
    "Update AWS Accounts by specifying the ID of the account and details to update",
    "cloud_connect_aws",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteAWSAccounts",
    "DELETE",
    "/cloud-connect-aws/entities/accounts/v1",
    "Delete a set of AWS Accounts by specifying their IDs",
    "cloud_connect_aws",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of accounts to remove",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateOrUpdateAWSSettings",
    "POST",
    "/cloud-connect-aws/entities/settings/v1",
    "Create or update Global Settings which are applicable to all provisioned AWS accounts",
    "cloud_connect_aws",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "VerifyAWSAccountAccess",
    "POST",
    "/cloud-connect-aws/entities/verify-account-access/v1",
    "Performs an Access Verification check on the specified AWS Account IDs",
    "cloud_connect_aws",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of accounts to verify access on",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "QueryAWSAccountsForIDs",
    "GET",
    "/cloud-connect-aws/queries/accounts/v1",
    "Search for provisioned AWS Accounts by providing an FQL filter and paging details. Returns a set of AWS "
    "account IDs which match the filter criteria",
    "cloud_connect_aws",
    [
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. [1-1000]. Defaults to 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The property to sort by (e.g. alias.desc or state.asc)",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results",
        "name": "filter",
        "in": "query"
      }
    ]
  ]
]
