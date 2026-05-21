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

_d4c_registration_endpoints = [
  [
    "GetCSPMAzureAccount",
    "GET",
    "/cloud-connect-azure/entities/account/v1",
    "Return information about Azure account registration",
    "d4c_registration",
    [
      {
        "type": "array",
        "items": {
          "maxLength": 36,
          "minLength": 36,
          "pattern": "^[0-9a-z-]{36}$",
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "SubscriptionIDs of accounts to select for this status operation. "
        "If this is empty then all accounts are returned.",
        "name": "ids",
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
      }
    ]
  ],
  [
    "CreateCSPMAzureAccount",
    "POST",
    "/cloud-connect-azure/entities/account/v1",
    "Creates a new account in our system for a customer and generates a script for them to run "
    "in their cloud environment to grant us access.",
    "d4c_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateCSPMAzureAccountClientID",
    "PATCH",
    "/cloud-connect-azure/entities/client-id/v1",
    "Update an Azure service account in our system by with the user-created client_id "
    "created with the public key we've provided",
    "d4c_registration",
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
      }
    ]
  ],
  [
    "GetCSPMAzureUserScriptsAttachment",
    "GET",
    "/cloud-connect-azure/entities/user-scripts-download/v1",
    "Return a script for customer to run in their cloud environment to grant us access to their "
    "Azure environment as a downloadable attachment",
    "d4c_registration",
    []
  ],
  [
    "GetCSPMAzureUserScripts",
    "GET",
    "/cloud-connect-azure/entities/user-scripts/v1",
    "Return a script for customer to run in their cloud environment to grant us access to their "
    "Azure environment",
    "d4c_registration",
    []
  ],
  [
    "GetCSPMCGPAccount",
    "GET",
    "/cloud-connect-gcp/entities/account/v1",
    "Returns information about the current status of an GCP account.",
    "d4c_registration",
    [
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
        "type": "array",
        "items": {
          "pattern": "\\d{10,}",
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Parent IDs of accounts",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "CreateCSPMGCPAccount",
    "POST",
    "/cloud-connect-gcp/entities/account/v1",
    "Creates a new account in our system for a customer and generates a new service account for them "
    "to add access to in their GCP environment to grant us access.",
    "d4c_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCSPMGCPUserScripts",
    "GET",
    "/cloud-connect-gcp/entities/user-scripts/v1",
    "Return a script for customer to run in their cloud environment to grant us access to their "
    "GCP environment",
    "d4c_registration",
    []
  ]
]
