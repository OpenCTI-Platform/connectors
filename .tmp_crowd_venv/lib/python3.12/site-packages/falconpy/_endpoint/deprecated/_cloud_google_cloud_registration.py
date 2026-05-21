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

_cloud_google_cloud_registration_endpoints = [
  [
    "cloud-registration-gcp-trigger-health-check",
    "POST",
    "/cloud-security-registration-google-cloud/entities/registration-scans/v1",
    "Trigger health check scan for GCP registrations",
    "cloud_google_cloud_registration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "GCP Registration IDs",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "cloud-registration-gcp-get-registration",
    "GET",
    "/cloud-security-registration-google-cloud/entities/registrations/v1",
    "Retrieve a Google Cloud Registration.",
    "cloud_google_cloud_registration",
    [
      {
        "type": "string",
        "description": "Google Cloud Registration ID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "cloud-registration-gcp-put-registration",
    "PUT",
    "/cloud-security-registration-google-cloud/entities/registrations/v1",
    "Creates/Updates a Google Cloud Registration.",
    "cloud_google_cloud_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-registration-gcp-create-registration",
    "POST",
    "/cloud-security-registration-google-cloud/entities/registrations/v1",
    "Create a Google Cloud Registration.",
    "cloud_google_cloud_registration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-registration-gcp-update-registration",
    "PATCH",
    "/cloud-security-registration-google-cloud/entities/registrations/v1",
    "Update a Google Cloud Registration.",
    "cloud_google_cloud_registration",
    [
      {
        "type": "string",
        "description": "Google Cloud Registration ID",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cloud-registration-gcp-delete-registration",
    "DELETE",
    "/cloud-security-registration-google-cloud/entities/registrations/v1",
    "Deletes a Google Cloud Registration and returns the deleted registration in the response body.",
    "cloud_google_cloud_registration",
    [
      {
        "type": "string",
        "description": "Google Cloud Registration ID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ]
]
