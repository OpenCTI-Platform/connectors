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

_cloud_security_endpoints = [
  [
    "combined-cloud-risks",
    "GET",
    "/cloud-security-risks/combined/cloud-risks/v1",
    "Gets cloud risks with full details based on filters and sort criteria",
    "cloud_security",
    [
      {
        "type": "string",
        "description": "FQL string to filter results in Falcon Query Language (FQL). Supported fields:   "
        "account_id  account_name  asset_gcrn  asset_id  asset_name  asset_region  asset_type  cloud_group  "
        "cloud_provider  first_seen  last_seen  resolved_at  risk_factor  rule_id  rule_name  service_category  "
        "severity  status  suppressed_by  suppressed_reason  tags",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The field to sort on. Use |asc or |desc suffix to specify sort direction.Supported "
        "fields:   account_id  account_name  asset_id  asset_name  asset_region  asset_type  cloud_provider  first_seen "
        "last_seen  resolved_at  rule_name  service_category  severity  status",
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
        "description": "Offset returned risks",
        "name": "offset",
        "in": "query"
      }
    ]
  ]
]
