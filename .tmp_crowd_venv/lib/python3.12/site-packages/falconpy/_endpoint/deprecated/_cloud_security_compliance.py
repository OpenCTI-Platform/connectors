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

_cloud_security_compliance_endpoints = [
  [
    "cloud-compliance-framework-posture-summaries",
    "GET",
    "/cloud-security-compliance/entities/framework-posture-summaries/v1",
    "Get sections and requirements with scores for benchmarks.",
    "cloud_security_compliance",
    [
      {
        "maxItems": 20,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "The uuids of compliance frameworks to retrieve (maximum 20 IDs allowed).",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "FQL filter, supported properties:\n  - account_id  account_name  business_impact  "
        "cloud_label  cloud_label_id  cloud_provider  environment  groups  region  resource_type  resource_type_name  "
        "tag_key  tag_value",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "cloud-compliance-rule-posture-summaries",
    "GET",
    "/cloud-security-compliance/entities/rule-posture-summaries/v1",
    "Get compliance score and counts for rules.",
    "cloud_security_compliance",
    [
      {
        "maxItems": 350,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "The uuids of compliance rules to retrieve (maximum 350 IDs allowed).",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "FQL filter, supported properties:\n  - account_id  account_name  business_impact  "
        "cloud_label  cloud_label_id  cloud_provider  environment  groups  region  resource_type  resource_type_name  "
        "tag_key  tag_value",
        "name": "filter",
        "in": "query"
      }
    ]
  ]
]
