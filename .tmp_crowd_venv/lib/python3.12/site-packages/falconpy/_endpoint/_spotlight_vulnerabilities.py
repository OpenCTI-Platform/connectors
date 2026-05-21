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

_spotlight_vulnerabilities_endpoints = [
  [
    "combinedQueryVulnerabilities",
    "GET",
    "/spotlight/combined/vulnerabilities/v1",
    "Search for Vulnerabilities in your environment by providing an FQL filter and paging details. Returns a "
    "set of Vulnerability entities which match the filter criteria",
    "spotlight_vulnerabilities",
    [
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an after token. On subsequent requests, provide the after token from the "
        "previous response to continue from that place in the results.",
        "name": "after",
        "in": "query"
      },
      {
        "maximum": 5000,
        "minimum": 1,
        "type": "integer",
        "description": "The number of items to return in this response (default: 100, max: 5000). Use with the "
        "after parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort vulnerabilities by their properties. Common sort options "
        "include:\n\n<ul><li>updated_timestamp|asc</li><li>closed_timestamp|asc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter items using a query in Falcon Query Language (FQL). Wildcards * and empty "
        "filter values are unsupported.\n\t\t\tAvailable filter fields that supports match (~): N/A\n\t\t\tAvailable "
        "filter fields that supports exact match: aid, cid, last_seen_within, status, cve.id, cve.is_cisa_kev, "
        "cve.remediation_level, cve.cps_rating, cve.exprt_rating, cve.exploit_status_to_include, cve.severity, "
        "cve.base_score, cve.types, host_info.asset_criticality, host_info.asset_roles, host_info.internet_exposure, "
        "host_info.tags, host_info.groups, host_info.product_type_desc, host_info.platform_name, "
        "suppression_info.is_suppressed, suppression_info.reason, host_info.instance_state\n\t\t\tAvailable filter "
        "fields that supports wildcard (*): N/A\n\t\t\tAvailable filter fields that supports range comparisons (>, <, "
        ">=, <=): created_timestamp, closed_timestamp, updated_timestamp, cve.base_score\n\t\t\t",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Select various details blocks to be returned for each vulnerability entity. Supported "
        "values:\n\n<ul><li>host_info</li><li>remediation</li><li>cve</li><li>evaluation_logic</li></ul>",
        "name": "facet",
        "in": "query"
      }
    ]
  ],
  [
    "getRemediationsV2",
    "GET",
    "/spotlight/entities/remediations/v2",
    "Get details on remediation by providing one or more IDs",
    "spotlight_vulnerabilities",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more remediation IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getVulnerabilities",
    "GET",
    "/spotlight/entities/vulnerabilities/v2",
    "Get details on vulnerabilities by providing one or more IDs",
    "spotlight_vulnerabilities",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more vulnerability IDs (max: 400). Find vulnerability IDs with GET "
        "/spotlight/queries/vulnerabilities/v1",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queryVulnerabilities",
    "GET",
    "/spotlight/queries/vulnerabilities/v1",
    "Search for Vulnerabilities in your environment by providing an FQL filter and paging details. Returns a "
    "set of Vulnerability IDs which match the filter criteria",
    "spotlight_vulnerabilities",
    [
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an after token. On subsequent requests, provide the after token from the "
        "previous response to continue from that place in the results.",
        "name": "after",
        "in": "query"
      },
      {
        "maximum": 400,
        "minimum": 1,
        "type": "integer",
        "description": "The number of items to return in this response (default: 100, max: 400). Use with the "
        "after parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort vulnerabilities by their properties. Available sort options: "
        "<ul><li>updated_timestamp|asc/desc</li><li>closed_timestamp|asc</li><li>updated_timestamp|asc/desc</li></ul>. "
        "Can be used in a format <field>|asc for ascending order or <field>|desc for descending order.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter items using a query in Falcon Query Language (FQL). Wildcards * and empty "
        "filter values are unsupported.\n\t\t\tAvailable filter fields that supports match (~): N/A\n\t\t\tAvailable "
        "filter fields that supports exact match: aid, cid, last_seen_within, status, cve.id, cve.is_cisa_kev, "
        "cve.remediation_level, cve.cps_rating, cve.exprt_rating, cve.exploit_status_to_include, cve.severity, "
        "cve.base_score, cve.types, host_info.asset_criticality, host_info.asset_roles, host_info.internet_exposure, "
        "host_info.tags, host_info.groups, host_info.product_type_desc, host_info.platform_name, "
        "suppression_info.is_suppressed, suppression_info.reason, host_info.instance_state\n\t\t\tAvailable filter "
        "fields that supports wildcard (*): N/A\n\t\t\tAvailable filter fields that supports range comparisons (>, <, "
        ">=, <=): created_timestamp, closed_timestamp, updated_timestamp, cve.base_score\n\t\t\t",
        "name": "filter",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getRemediations",
    "GET",
    "/spotlight/entities/remediations/v2",
    "Get details on remediations by providing one or more IDs",
    "spotlight_vulnerabilities",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more remediation IDs (max: 400).",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ]
]
