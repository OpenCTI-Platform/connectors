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

_cloud_security_detections_endpoints = [
  [
    "cspm_evaluations_iom_entities",
    "GET",
    "/cloud-security-evaluations/entities/ioms/v1",
    "Gets IOMs based on the provided IDs",
    "cloud_security_detections",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "List of IOMs to return (maximum 100 IDs allowed).  Use POST method with same path if "
        "more entities are required.",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "cspm_evaluations_iom_queries",
    "GET",
    "/cloud-security-evaluations/queries/ioms/v1",
    "Gets a list of IOM IDs for the given parameters, filters and sort criteria.",
    "cloud_security_detections",
    [
      {
        "type": "string",
        "description": "FQL string to filter results in Falcon Query Language (FQL). Supported fields:   "
        "account_id  account_name  applicable_profile  attack_type  benchmark_name  benchmark_version  business_impact "
        "  cid  cloud_group  cloud_label  cloud_label_id  cloud_provider  cloud_scope  created_at  environment  "
        "extension_status  first_detected  framework  last_detected  policy_id  policy_name  policy_uuid  region  "
        "requirement  requirement_name  resource_gcrn  resource_id  resource_parent  resource_status  resource_type  "
        "resource_type_name  rule_group  rule_id  rule_name  rule_origin  rule_remediation  section  service  "
        "service_category  severity  status  suppressed_by  suppression_reason  tactic_id  tactic_name  tag_key  "
        "tag_value  tags  tags_string  technique_id  technique_name",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The field to sort on. Use |asc or |desc suffix to specify sort direction.Supported "
        "fields:   account_id  account_name  applicable_profile  attack_type  benchmark_name  benchmark_version  "
        "business_impact  cid  cloud_group  cloud_label  cloud_label_id  cloud_provider  cloud_scope  created_at  "
        "environment  extension_status  first_detected  framework  last_detected  policy_id  policy_name  policy_uuid  "
        "region  requirement  requirement_name  resource_gcrn  resource_id  resource_parent  resource_status  "
        "resource_type  resource_type_name  rule_group  rule_id  rule_name  rule_origin  rule_remediation  section  "
        "service  service_category  severity  status  suppressed_by  suppression_reason  tactic_id  tactic_name  "
        "tag_key  tag_value  tags  tags_string  technique_id  technique_name",
        "name": "sort",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 0,
        "type": "integer",
        "default": 500,
        "description": "The maximum number of items to return. When not specified or 0, 500 is used. When "
        "larger than 1000, 1000 is used.",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned assets",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "token-based pagination. Use for paginating through an entire result set. Use only one "
        "of 'offset' and 'after' parameters for paginating",
        "name": "after",
        "in": "query"
      }
    ]
  ]
]
