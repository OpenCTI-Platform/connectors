"""Internal API endpoint constant library (deprecated operations).

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

_cloud_azure_registration_endpoints = [
  [
    "cloud-registration-azure-delete-legacy-subscription",
    "DELETE",
    "/cloud-security-registration-azure/entities/accounts/legacy/v1",
    "Delete existing legacy Azure subscriptions.",
    "cloud_azure_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-registration-azure-trigger-health-check",
    "POST",
    "/cloud-security-registration-azure/entities/registrations/healthcheck/v1",
    "Trigger health check scan for Azure registrations",
    "cloud_azure_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Azure tenant IDs",
        "name": "tenant_ids",
        "in": "query"
      }
    ]
  ],
  [
    "cloud-registration-azure-get-registration",
    "GET",
    "/cloud-security-registration-azure/entities/registrations/v1",
    "Retrieve existing Azure registration for a tenant.",
    "cloud_azure_registration",
    [
      {
        "type": "string",
        "description": "Tenant ID",
        "name": "tenant_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "cloud-registration-azure-create-registration",
    "POST",
    "/cloud-security-registration-azure/entities/registrations/v1",
    "Create an Azure registration for a tenant.",
    "cloud_azure_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-registration-azure-update-registration",
    "PATCH",
    "/cloud-security-registration-azure/entities/registrations/v1",
    "Update an existing Azure registration for a tenant.",
    "cloud_azure_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-registration-azure-delete-registration",
    "DELETE",
    "/cloud-security-registration-azure/entities/registrations/v1",
    "Deletes existing Azure registrations.",
    "cloud_azure_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Azure tenant IDs",
        "name": "tenant_ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "cloud-registration-azure-validate-registration",
    "POST",
    "/cloud-security-registration-azure/entities/registrations/validate/v1",
    "Validate an Azure registration by checking service principal, role assignments and deployment stack (if "
    "the deployment method is Bicep)",
    "cloud_azure_registration",
    [
      {
        "maxLength": 36,
        "minLength": 36,
        "pattern": "^[0-9a-z-]{36}$",
        "type": "string",
        "description": "Azure tenant ID to be validated",
        "name": "tenant_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Azure deployment stack name to be validated",
        "name": "stack_name",
        "in": "query"
      }
    ]
  ],
  [
    "cloud-registration-azure-download-script",
    "POST",
    "/cloud-security-registration-azure/entities/scripts/v1",
    "Retrieve script to create resources",
    "cloud_azure_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
