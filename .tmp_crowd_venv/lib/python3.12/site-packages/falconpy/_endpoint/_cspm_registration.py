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
# pylint: disable=C0302

_cspm_registration_endpoints = [
  [
    "GetCSPMAwsAccount",
    "GET",
    "/cloud-connect-cspm-aws/entities/account/v1",
    "Returns information about the current status of an AWS account.",
    "cspm_registration",
    [
      {
        "enum": [
          "dry",
          "full"
        ],
        "type": "string",
        "description": "Type of scan, dry or full, to perform on selected accounts",
        "name": "scan-type",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "AWS account IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "AWS IAM role ARNs",
        "name": "iam_role_arns",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "AWS organization IDs",
        "name": "organization-ids",
        "in": "query"
      },
      {
        "enum": [
          "provisioned",
          "operational"
        ],
        "type": "string",
        "description": "Account status to filter results by.",
        "name": "status",
        "in": "query"
      },
      {
        "maxLength": 3,
        "minLength": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Defaults to 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "true",
          "false"
        ],
        "type": "string",
        "description": "Only return CSPM Lite accounts",
        "name": "cspm_lite",
        "in": "query"
      },
      {
        "enum": [
          "true",
          "false"
        ],
        "type": "string",
        "description": "Only return migrated d4c accounts",
        "name": "migrated",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "enum": [
          "organization"
        ],
        "type": "string",
        "description": "Field to group by.",
        "name": "group_by",
        "in": "query"
      }
    ]
  ],
  [
    "CreateCSPMAwsAccount",
    "POST",
    "/cloud-connect-cspm-aws/entities/account/v1",
    "Creates a new account in our system for a customer and generates a script for them to run in their AWS "
    "cloud environment to grant us access.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PatchCSPMAwsAccount",
    "PATCH",
    "/cloud-connect-cspm-aws/entities/account/v1",
    "Patches a existing account in our system for a customer.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteCSPMAwsAccount",
    "DELETE",
    "/cloud-connect-cspm-aws/entities/account/v1",
    "Deletes an existing AWS account or organization in our system.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "AWS account IDs to remove",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "AWS organization IDs to remove",
        "name": "organization-ids",
        "in": "query"
      }
    ]
  ],
  [
    "GetCSPMAwsConsoleSetupURLs",
    "GET",
    "/cloud-connect-cspm-aws/entities/console-setup-urls/v1",
    "Return a URL for customer to visit in their cloud environment to grant us access to their AWS environment.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "AWS account IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "enum": [
          "true",
          "false"
        ],
        "type": "string",
        "name": "use_existing_cloudtrail",
        "in": "query"
      },
      {
        "pattern": "^[0-9a-z-]{2,}$",
        "type": "string",
        "description": "Region",
        "name": "region",
        "in": "query"
      },
      {
        "pattern": ".*",
        "type": "string",
        "description": "Base64 encoded JSON string to be used as AWS tags",
        "name": "tags",
        "in": "query"
      },
      {
        "enum": [
          "aws-url",
          "aws-iom-url",
          "aws-ioa-url",
          "aws-sensor-management-url",
          "aws-dspm-url",
          "aws-idp-url",
          "aws-modular-cft-url",
          "aws-modular-cft-gov-commercial-url"
        ],
        "type": "string",
        "description": "Template to be rendered",
        "name": "template",
        "in": "query"
      }
    ]
  ],
  [
    "GetCSPMAwsAccountScriptsAttachment",
    "GET",
    "/cloud-connect-cspm-aws/entities/user-scripts-download/v1",
    "Return a script for customer to run in their cloud environment to grant us access to their AWS "
    "environment as a downloadable attachment.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "AWS account IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "enum": [
          "aws-bash",
          "aws-terraform"
        ],
        "type": "string",
        "description": "Template to be rendered",
        "name": "template",
        "in": "query"
      },
      {
        "enum": [
          "commercial",
          "gov"
        ],
        "type": "string",
        "description": "Type of account, it can be commercial or gov",
        "name": "account_type",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The list of accounts to register, values should be in the form: account,profile",
        "name": "accounts",
        "in": "query"
      },
      {
        "enum": [
          "true",
          "false"
        ],
        "type": "string",
        "name": "behavior_assessment_enabled",
        "in": "query"
      },
      {
        "enum": [
          "true",
          "false"
        ],
        "type": "string",
        "name": "sensor_management_enabled",
        "in": "query"
      },
      {
        "enum": [
          "true",
          "false"
        ],
        "type": "string",
        "name": "dspm_enabled",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "name": "dspm_regions",
        "in": "query"
      },
      {
        "type": "string",
        "name": "dspm_role",
        "in": "query"
      },
      {
        "enum": [
          "true",
          "false"
        ],
        "type": "string",
        "name": "use_existing_cloudtrail",
        "in": "query"
      },
      {
        "pattern": ".*",
        "type": "string",
        "description": "The AWS organization ID to be registered",
        "name": "organization_id",
        "in": "query"
      },
      {
        "pattern": ".*",
        "type": "string",
        "description": "The AWS profile to be used during registration",
        "name": "aws_profile",
        "in": "query"
      },
      {
        "pattern": ".*",
        "type": "string",
        "description": "The custom IAM role to be used during registration",
        "name": "custom_role_name",
        "in": "query"
      }
    ]
  ],
  [
    "GetCSPMAzureAccount",
    "GET",
    "/cloud-connect-cspm-azure/entities/account/v1",
    "Return information about Azure account registration",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "SubscriptionIDs of accounts to select for this status operation. If this is empty then "
        "all accounts are returned.",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Tenant ids to filter azure accounts",
        "name": "tenant_ids",
        "in": "query"
      },
      {
        "maxLength": 4,
        "minLength": 3,
        "pattern": "^(full|dry)$",
        "type": "string",
        "description": "Type of scan, dry or full, to perform on selected accounts",
        "name": "scan-type",
        "in": "query"
      },
      {
        "pattern": "^(provisioned|operational)$",
        "type": "string",
        "description": "Account status to filter results by.",
        "name": "status",
        "in": "query"
      },
      {
        "pattern": "^(true|false)$",
        "enum": [
          "false",
          "true"
        ],
        "type": "string",
        "description": "Only return CSPM Lite accounts",
        "name": "cspm_lite",
        "in": "query"
      },
      {
        "maxLength": 3,
        "minLength": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Defaults to 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "CreateCSPMAzureAccount",
    "POST",
    "/cloud-connect-cspm-azure/entities/account/v1",
    "Creates a new account in our system for a customer and generates a script for them to run in their cloud "
    "environment to grant us access.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateCSPMAzureAccount",
    "PATCH",
    "/cloud-connect-cspm-azure/entities/account/v1",
    "Patches a existing account in our system for a customer.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteCSPMAzureAccount",
    "DELETE",
    "/cloud-connect-cspm-azure/entities/account/v1",
    "Deletes an Azure subscription from the system.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Azure subscription IDs to remove",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Tenant ids to remove",
        "name": "tenant_ids",
        "in": "query"
      },
      {
        "maxLength": 5,
        "minLength": 4,
        "pattern": "^(true|false)$",
        "type": "string",
        "name": "retain_tenant",
        "in": "query"
      }
    ]
  ],
  [
    "UpdateCSPMAzureAccountClientID",
    "PATCH",
    "/cloud-connect-cspm-azure/entities/client-id/v1",
    "Update an Azure service account in our system by with the user-created client_id created with the public "
    "key we've provided",
    "cspm_registration",
    [
      {
        "maxLength": 36,
        "minLength": 36,
        "pattern": "^[0-9a-z-]{36}$",
        "type": "string",
        "description": "ClientID to use for the Service Principal associated with the customer's Azure account",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "maxLength": 36,
        "minLength": 36,
        "pattern": "^[0-9a-z-]{36}$",
        "type": "string",
        "description": "Tenant ID to update client ID for. Required if multiple tenants are registered.",
        "name": "tenant-id",
        "in": "query"
      }
    ]
  ],
  [
    "UpdateCSPMAzureTenantDefaultSubscriptionID",
    "PATCH",
    "/cloud-connect-cspm-azure/entities/default-subscription-id/v1",
    "Update an Azure default subscription_id in our system for given tenant_id",
    "cspm_registration",
    [
      {
        "maxLength": 36,
        "minLength": 36,
        "pattern": "^[0-9a-z-]{36}$",
        "type": "string",
        "description": "Tenant ID to update client ID for. Required if multiple tenants are registered.",
        "name": "tenant-id",
        "in": "query"
      },
      {
        "maxLength": 36,
        "minLength": 36,
        "pattern": "^[0-9a-z-]{36}$",
        "type": "string",
        "description": "Default Subscription ID to patch for all subscriptions belonged to a tenant.",
        "name": "subscription_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "AzureDownloadCertificate",
    "GET",
    "/cloud-connect-cspm-azure/entities/download-certificate/v1",
    "Returns JSON object(s) that contain the base64 encoded certificate for a service principal.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Azure Tenant ID",
        "name": "tenant_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetCSPMAzureManagementGroup",
    "GET",
    "/cloud-connect-cspm-azure/entities/management-group/v1",
    "Return information about Azure management group registration",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Tenant ids to filter azure accounts",
        "name": "tenant_ids",
        "in": "query"
      },
      {
        "maxLength": 3,
        "minLength": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Defaults to 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "CreateCSPMAzureManagementGroup",
    "POST",
    "/cloud-connect-cspm-azure/entities/management-group/v1",
    "Creates a new management group in our system for a customer.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteCSPMAzureManagementGroup",
    "DELETE",
    "/cloud-connect-cspm-azure/entities/management-group/v1",
    "Deletes Azure management groups from the system.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Tenant ids to remove",
        "name": "tenant_ids",
        "in": "query"
      }
    ]
  ],
  [
    "AzureRefreshCertificate",
    "POST",
    "/cloud-connect-cspm-azure/entities/refresh-certificate/v1",
    "Refresh certificate and returns JSON object(s) that contain the base64 encoded certificate for a service principal.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Azure Tenant ID",
        "name": "tenant_id",
        "in": "query",
        "required": True
      },
      {
        "maxLength": 2,
        "minLength": 1,
        "pattern": "^[0-9]{1,2}$",
        "type": "string",
        "default": "1",
        "description": "Years the certificate should be valid. Max 2",
        "name": "years_valid",
        "in": "query"
      }
    ]
  ],
  [
    "GetCSPMAzureUserScriptsAttachment",
    "GET",
    "/cloud-connect-cspm-azure/entities/user-scripts-download/v1",
    "Return a script for customer to run in their cloud environment to grant us access to their Azure "
    "environment as a downloadable attachment",
    "cspm_registration",
    [
      {
        "maxLength": 36,
        "minLength": 36,
        "pattern": "^[0-9a-z-]{36}$",
        "type": "string",
        "description": "Tenant ID to generate script for. Defaults to most recently registered tenant.",
        "name": "tenant-id",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Subscription IDs to generate script for. Defaults to all.",
        "name": "subscription_ids",
        "in": "query"
      },
      {
        "pattern": "^(commercial|gov)$",
        "enum": [
          "commercial",
          "gov"
        ],
        "type": "string",
        "name": "account_type",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Template to be rendered",
        "name": "template",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Use Azure Management Group",
        "name": "azure_management_group",
        "in": "query"
      }
    ]
  ],
  [
    "GetCSPMCGPAccount",
    "GET",
    "/cloud-connect-cspm-gcp/entities/account/v1",
    "Returns information about the current status of an GCP account.",
    "cspm_registration",
    [
      {
        "enum": [
          "Folder",
          "Organization",
          "Project"
        ],
        "type": "string",
        "description": "GCP Hierarchy Parent Type, organization/folder/project",
        "name": "parent_type",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Hierarchical Resource IDs of accounts",
        "name": "ids",
        "in": "query"
      },
      {
        "enum": [
          "dry",
          "full"
        ],
        "type": "string",
        "description": "Type of scan, dry or full, to perform on selected accounts",
        "name": "scan-type",
        "in": "query"
      },
      {
        "enum": [
          "operational",
          "provisioned"
        ],
        "type": "string",
        "description": "Account status to filter results by.",
        "name": "status",
        "in": "query"
      },
      {
        "maxLength": 3,
        "minLength": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Defaults to 100.",
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
        "description": "Order fields in ascending or descending order. Ex: parent_type|asc.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "GetCSPMGCPAccount",
    "GET",
    "/cloud-connect-cspm-gcp/entities/account/v1",
    "Returns information about the current status of an GCP account.",
    "cspm_registration",
    [
      {
        "enum": [
          "Folder",
          "Organization",
          "Project"
        ],
        "type": "string",
        "description": "GCP Hierarchy Parent Type, organization/folder/project",
        "name": "parent_type",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Hierarchical Resource IDs of accounts",
        "name": "ids",
        "in": "query"
      },
      {
        "enum": [
          "dry",
          "full"
        ],
        "type": "string",
        "description": "Type of scan, dry or full, to perform on selected accounts",
        "name": "scan-type",
        "in": "query"
      },
      {
        "enum": [
          "operational",
          "provisioned"
        ],
        "type": "string",
        "description": "Account status to filter results by.",
        "name": "status",
        "in": "query"
      },
      {
        "maxLength": 3,
        "minLength": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Defaults to 100.",
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
        "description": "Order fields in ascending or descending order. Ex: parent_type|asc.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "CreateCSPMGCPAccount",
    "POST",
    "/cloud-connect-cspm-gcp/entities/account/v1",
    "Creates a new account in our system for a customer and generates a new service account for them to add "
    "access to in their GCP environment to grant us access.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateCSPMGCPAccount",
    "PATCH",
    "/cloud-connect-cspm-gcp/entities/account/v1",
    "Patches a existing account in our system for a customer.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteCSPMGCPAccount",
    "DELETE",
    "/cloud-connect-cspm-gcp/entities/account/v1",
    "Deletes a GCP account from the system.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Hierarchical Resource IDs of accounts",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "ConnectCSPMGCPAccount",
    "POST",
    "/cloud-connect-cspm-gcp/entities/account/v2",
    "Creates a new GCP account with newly-uploaded service account or connects with existing service account "
    "with only the following fields: parent_id, parent_type and service_account_id",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCSPMGCPValidateAccountsExt",
    "POST",
    "/cloud-connect-cspm-gcp/entities/account/validate/v1",
    "Run a synchronous health check.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCSPMGCPServiceAccountsExt",
    "GET",
    "/cloud-connect-cspm-gcp/entities/service-accounts/v1",
    "Returns the service account id and client email for external clients.",
    "cspm_registration",
    [
      {
        "pattern": "^\\d+$",
        "type": "string",
        "description": "Service Account ID",
        "name": "id",
        "in": "query"
      }
    ]
  ],
  [
    "UpdateCSPMGCPServiceAccountsExt",
    "PATCH",
    "/cloud-connect-cspm-gcp/entities/service-accounts/v1",
    "Patches the service account key for external clients.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ValidateCSPMGCPServiceAccountExt",
    "POST",
    "/cloud-connect-cspm-gcp/entities/service-accounts/validate/v1",
    "Validates credentials for a service account",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCSPMGCPUserScriptsAttachment",
    "GET",
    "/cloud-connect-cspm-gcp/entities/user-scripts-download/v1",
    "Return a script for customer to run in their cloud environment to grant us access to their GCP "
    "environment as a downloadable attachment",
    "cspm_registration",
    [
      {
        "enum": [
          "Folder",
          "Organization",
          "Project"
        ],
        "type": "string",
        "description": "GCP Hierarchy Parent Type, organization/folder/project",
        "name": "parent_type",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Hierarchical Resource IDs of accounts",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "GetBehaviorDetections",
    "GET",
    "/detects/entities/ioa/v1",
    "Get list of detected behaviors",
    "cspm_registration",
    [
      {
        "pattern": "^(aws|azure)$",
        "enum": [
          "aws",
          "azure"
        ],
        "type": "string",
        "description": "Cloud Provider (e.g.: aws|azure)",
        "name": "cloud_provider",
        "in": "query"
      },
      {
        "enum": [
          "ACM",
          "ACR",
          "Any",
          "App Engine",
          "AppService",
          "BigQuery",
          "Cloud Load Balancing",
          "Cloud Logging",
          "Cloud SQL",
          "Cloud Storage",
          "CloudFormation",
          "CloudTrail",
          "CloudWatch Logs",
          "Cloudfront",
          "Compute Engine",
          "Config",
          "Disk",
          "DynamoDB",
          "EBS",
          "EC2",
          "ECR",
          "EFS",
          "EKS",
          "ELB",
          "EMR",
          "Elasticache",
          "GuardDuty",
          "IAM",
          "Identity",
          "KMS",
          "KeyVault",
          "Kinesis",
          "Kubernetes",
          "Lambda",
          "LoadBalancer",
          "Monitor",
          "NLB/ALB",
          "NetworkSecurityGroup",
          "PostgreSQL",
          "RDS",
          "Redshift",
          "S3",
          "SES",
          "SNS",
          "SQLDatabase",
          "SQLServer",
          "SQS",
          "SSM",
          "Serverless Application Repository",
          "StorageAccount",
          "Subscriptions",
          "VPC",
          "VirtualMachine",
          "VirtualNetwork"
        ],
        "type": "string",
        "description": "Cloud Service (e.g. EC2 | EBS | S3)",
        "name": "service",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Cloud Account ID (e.g.: AWS accountID, Azure subscriptionID)",
        "name": "account_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "AWS Account ID",
        "name": "aws_account_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Azure Subscription ID",
        "name": "azure_subscription_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Azure Tenant ID",
        "name": "azure_tenant_id",
        "in": "query"
      },
      {
        "enum": [
          "closed",
          "open"
        ],
        "type": "string",
        "description": "State (e.g.: open | closed)",
        "name": "state",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter to get all events after this date, in format RFC3339 : e.g. 2006-01-02T15:04:05Z07:00",
        "name": "date_time_since",
        "in": "query"
      },
      {
        "type": "string",
        "default": "24h",
        "description": "Filter events using a duration string (e.g. 24h)",
        "name": "since",
        "in": "query"
      },
      {
        "enum": [
          "Critical",
          "High",
          "Informational",
          "Medium"
        ],
        "type": "string",
        "description": "Policy Severity",
        "name": "severity",
        "in": "query"
      },
      {
        "type": "string",
        "description": "String to get next page of results, is associated with a previous execution of "
        "GetBehaviorDetections. Must include all filters from previous execution.",
        "name": "next_token",
        "in": "query"
      },
      {
        "pattern": "^\\d+$",
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource ID",
        "name": "resource_id",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Resource UUID",
        "name": "resource_uuid",
        "in": "query"
      }
    ]
  ],
  [
    "GetConfigurationDetections",
    "GET",
    "/detects/entities/iom/v1",
    "Get list of active misconfigurations. This endpoint is deprecated, please use "
    "GetConfigurationDetectionIDsV2 and GetConfigurationDetectionEntities instead",
    "cspm_registration",
    [
      {
        "enum": [
          "aws",
          "azure",
          "gcp"
        ],
        "type": "string",
        "description": "Cloud Provider (e.g.: aws|azure|gcp)",
        "name": "cloud_provider",
        "in": "query"
      },
      {
        "type": "string",
        "description": "AWS account ID or GCP Project Number or Azure subscription ID",
        "name": "account_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Azure Subscription ID",
        "name": "azure_subscription_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Azure Tenant ID",
        "name": "azure_tenant_id",
        "in": "query"
      },
      {
        "enum": [
          "all",
          "new",
          "reoccurring"
        ],
        "type": "string",
        "description": "Status (e.g.: new|reoccurring|all)",
        "name": "status",
        "in": "query"
      },
      {
        "pattern": "^[0-9a-z-_]{2,}$",
        "type": "string",
        "description": "Cloud Provider Region",
        "name": "region",
        "in": "query"
      },
      {
        "enum": [
          "Critical",
          "High",
          "Informational",
          "Medium"
        ],
        "type": "string",
        "description": "Policy Severity",
        "name": "severity",
        "in": "query"
      },
      {
        "enum": [
          "ACM",
          "ACR",
          "Any",
          "App Engine",
          "AppService",
          "BigQuery",
          "Cloud Load Balancing",
          "Cloud Logging",
          "Cloud SQL",
          "Cloud Storage",
          "CloudFormation",
          "CloudTrail",
          "CloudWatch Logs",
          "Cloudfront",
          "Compute Engine",
          "Config",
          "Disk",
          "DynamoDB",
          "EBS",
          "EC2",
          "ECR",
          "EFS",
          "EKS",
          "ELB",
          "EMR",
          "Elasticache",
          "GuardDuty",
          "IAM",
          "Identity",
          "KMS",
          "KeyVault",
          "Kinesis",
          "Kubernetes",
          "Lambda",
          "LoadBalancer",
          "Monitor",
          "NLB/ALB",
          "NetworkSecurityGroup",
          "PostgreSQL",
          "RDS",
          "Redshift",
          "S3",
          "SES",
          "SNS",
          "SQLDatabase",
          "SQLServer",
          "SQS",
          "SSM",
          "Serverless Application Repository",
          "StorageAccount",
          "Subscriptions",
          "VPC",
          "VirtualMachine",
          "VirtualNetwork"
        ],
        "type": "string",
        "description": "Cloud Service (e.g.: EBS|EC2|S3 etc.)",
        "name": "service",
        "in": "query"
      },
      {
        "type": "string",
        "description": "String to get next page of results, is associated with a previous execution of "
        "GetConfigurationDetections. Cannot be combined with any filter except limit.",
        "name": "next_token",
        "in": "query"
      },
      {
        "pattern": "^\\d+$",
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "GetConfigurationDetectionEntities",
    "GET",
    "/detects/entities/iom/v2",
    "Get misconfigurations based on the ID - including custom policy detections in addition to default policy detections.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "detection ids",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getCloudEventIDs",
    "GET",
    "/detects/queries/cloud-events/v1",
    "Get list of related cloud event LogScale IDs for a given IOA",
    "cspm_registration",
    [
      {
        "type": "string",
        "description": "IOA Aggregate Event ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetConfigurationDetectionIDsV2",
    "GET",
    "/detects/queries/iom/v2",
    "Get list of active misconfiguration ids - including custom policy detections in addition to default policy detections.",
    "cspm_registration",
    [
      {
        "type": "string",
        "description": "use_current_scan_ids - *use this to get records for latest scans (ignored when "
        "next_token is set)*\naccount_name\naccount_id\nagent_id\nattack_types\nazure_subscription_id\ncloud_provider\n "
        "cloud_service_keyword\ncustom_policy_id\nis_managed\npolicy_id\npolicy_type\nresource_id\nregion\nstatus\nscan "
        "_time\nseverity\nseverity_string\n",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "default": "timestamp|desc",
        "description": "account_name\naccount_id\nattack_types\nazure_subscription_id\ncloud_provider\ncloud_s "
        "ervice_keyword\nstatus\nis_managed\npolicy_id\npolicy_type\nresource_id\nregion\nscan_time\nseverity\nseverity "
        "_string\ntimestamp",
        "name": "sort",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 0,
        "type": "integer",
        "default": 500,
        "description": "The max number of detections to return",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned detections. Cannot be combined with next_token filter",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "String to get next page of results. Cannot be combined with any filter except limit.",
        "name": "next_token",
        "in": "query"
      }
    ]
  ],
  [
    "GetIOAEvents",
    "GET",
    "/ioa/entities/events/v1",
    "For CSPM IOA events, gets list of IOA events.",
    "cspm_registration",
    [
      {
        "pattern": "^\\d+$",
        "type": "string",
        "description": "Policy ID",
        "name": "policy_id",
        "in": "query",
        "required": True
      },
      {
        "pattern": "^(aws|azure|gcp)$",
        "type": "string",
        "description": "Cloud Provider (e.g.: aws|azure|gcp)",
        "name": "cloud_provider",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Cloud account ID (e.g.: AWS accountID, Azure subscriptionID)",
        "name": "account_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "AWS accountID",
        "name": "aws_account_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Azure subscription ID",
        "name": "azure_subscription_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Azure tenant ID",
        "name": "azure_tenant_id",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "user IDs",
        "name": "user_ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "state",
        "name": "state",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return events.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "GetIOAUsers",
    "GET",
    "/ioa/entities/users/v1",
    "For CSPM IOA users, gets list of IOA users.",
    "cspm_registration",
    [
      {
        "pattern": "^\\d+$",
        "type": "string",
        "description": "Policy ID",
        "name": "policy_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "state",
        "name": "state",
        "in": "query"
      },
      {
        "pattern": "^(aws|azure|gcp)$",
        "type": "string",
        "description": "Cloud Provider (e.g.: aws|azure|gcp)",
        "name": "cloud_provider",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Cloud account ID (e.g.: AWS accountID, Azure subscriptionID)",
        "name": "account_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "AWS accountID",
        "name": "aws_account_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Azure subscription ID",
        "name": "azure_subscription_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Azure tenant ID",
        "name": "azure_tenant_id",
        "in": "query"
      }
    ]
  ],
  [
    "GetCSPMPolicy",
    "GET",
    "/settings/entities/policy-details/v1",
    "Given a policy ID, returns detailed policy information.",
    "cspm_registration",
    [
      {
        "pattern": "^\\d+$",
        "type": "integer",
        "description": "Policy ID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetCSPMPoliciesDetails",
    "GET",
    "/settings/entities/policy-details/v2",
    "Given an array of policy IDs, returns detailed policies information.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "integer"
        },
        "collectionFormat": "multi",
        "description": "Policy IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetCSPMPolicySettings",
    "GET",
    "/settings/entities/policy/v1",
    "Returns information about current policy settings.",
    "cspm_registration",
    [
      {
        "enum": [
          "ACM",
          "ACR",
          "Any",
          "App Engine",
          "AppService",
          "BigQuery",
          "Cloud Load Balancing",
          "Cloud Logging",
          "Cloud SQL",
          "Cloud Storage",
          "CloudFormation",
          "CloudTrail",
          "CloudWatch Logs",
          "Cloudfront",
          "Compute Engine",
          "Config",
          "Disk",
          "DynamoDB",
          "EBS",
          "EC2",
          "ECR",
          "EFS",
          "EKS",
          "ELB",
          "EMR",
          "Elasticache",
          "GuardDuty",
          "IAM",
          "Identity",
          "KMS",
          "KeyVault",
          "Kinesis",
          "Kubernetes",
          "Lambda",
          "LoadBalancer",
          "Monitor",
          "NLB/ALB",
          "NetworkSecurityGroup",
          "PostgreSQL",
          "RDS",
          "Redshift",
          "S3",
          "SES",
          "SNS",
          "SQLDatabase",
          "SQLServer",
          "SQS",
          "SSM",
          "Serverless Application Repository",
          "StorageAccount",
          "Subscriptions",
          "VPC",
          "VirtualMachine",
          "VirtualNetwork"
        ],
        "type": "string",
        "description": "Service type to filter policy settings by.",
        "name": "service",
        "in": "query"
      },
      {
        "pattern": "^\\d+$",
        "type": "string",
        "description": "Policy ID",
        "name": "policy-id",
        "in": "query"
      },
      {
        "pattern": "^(aws|azure|gcp)$",
        "enum": [
          "aws",
          "azure",
          "gcp"
        ],
        "type": "string",
        "description": "Cloud Platform (e.g.: aws|azure|gcp)",
        "name": "cloud-platform",
        "in": "query"
      }
    ]
  ],
  [
    "UpdateCSPMPolicySettings",
    "PATCH",
    "/settings/entities/policy/v1",
    "Updates a policy setting - can be used to override policy severity or to disable a policy entirely.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCSPMScanSchedule",
    "GET",
    "/settings/scan-schedule/v1",
    "Returns scan schedule configuration for one or more cloud platforms.",
    "cspm_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Cloud Platform",
        "name": "cloud-platform",
        "in": "query"
      }
    ]
  ],
  [
    "UpdateCSPMScanSchedule",
    "POST",
    "/settings/scan-schedule/v1",
    "Updates scan schedule configuration for one or more cloud platforms.",
    "cspm_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
