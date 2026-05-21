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

_cloud_oci_registration_endpoints = [
  [
    "cloud-security-registration-oci-get-account",
    "GET",
    "/cloud-security-registration-oci/combined/accounts/v1",
    "Retrieve a list of OCI tenancies with support for FQL filtering, sorting, and pagination",
    "cloud_oci_registration",
    [
      {
        "type": "string",
        "description": "FQL (Falcon Query Language) string for filtering results. Allowed filters are "
        "Set{tenancy_name, home_region, key_age, overall_status, created_at, updated_at, tenancy_ocid}",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Field and direction for sorting results - allowed sort fields are Set{home_region, "
        "key_age, overall_status, created_at, updated_at, tenancy_ocid, tenancy_name}",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Token for cursor-based pagination. Currently unsupported.",
        "name": "next_token",
        "in": "query"
      },
      {
        "maximum": 10000,
        "minimum": 0,
        "type": "integer",
        "default": 100,
        "description": "Maximum number of records to return (default: 100, max: 10000)",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index of result",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "cloud-security-registration-oci-rotate-key",
    "POST",
    "/cloud-security-registration-oci/entities/account-rotate-keys/v1",
    "Refresh key for the OCI Tenancy",
    "cloud_oci_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-security-registration-oci-validate-tenancy",
    "POST",
    "/cloud-security-registration-oci/entities/account-validate/v1",
    "Validate the OCI account in CSPM for a provided CID. For internal clients only.",
    "cloud_oci_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-security-registration-oci-create-account",
    "POST",
    "/cloud-security-registration-oci/entities/accounts/v1",
    "Create OCI tenancy account in CSPM",
    "cloud_oci_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-security-registration-oci-update-account",
    "PATCH",
    "/cloud-security-registration-oci/entities/accounts/v1",
    "Patch an existing OCI account in our system for a customer.",
    "cloud_oci_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-security-registration-oci-delete-account",
    "DELETE",
    "/cloud-security-registration-oci/entities/accounts/v1",
    "Delete an existing OCI tenancy in CSPM.",
    "cloud_oci_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "OCI tenancy ocids to remove",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "cloud-security-registration-oci-download-script",
    "POST",
    "/cloud-security-registration-oci/entities/scripts/v1",
    "Retrieve script to create resources in tenancy OCID",
    "cloud_oci_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
