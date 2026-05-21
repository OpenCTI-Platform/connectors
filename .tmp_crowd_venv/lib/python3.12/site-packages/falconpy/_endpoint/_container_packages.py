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

_container_packages_endpoints = [
  [
    "ReadPackagesByImageCount",
    "GET",
    "/container-security/aggregates/packages/by-image-count/v1",
    "Retrieves the N most frequently used packages across images",
    "container_packages",
    [
      {
        "type": "string",
        "description": "Filter packages using a query in Falcon Query Language (FQL). Supported filter fields:"
        "ai_related  cveid  running_images  severity  type  vulnerability_count",
        "name": "filter",
        "in": "query"
      },
      {
        "maximum": 100,
        "minimum": 1,
        "type": "integer",
        "default": 5,
        "description": "Maximum number of package results to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ReadPackagesCountByZeroDay",
    "GET",
    "/container-security/aggregates/packages/count-by-zero-day/v1",
    "Retrieve packages count affected by zero day vulnerabilities",
    "container_packages",
    [
      {
        "type": "string",
        "description": "Filter packages using a query in Falcon Query Language (FQL). Supported filter fields:  cid",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadPackagesByFixableVulnCount",
    "GET",
    "/container-security/combined/packages/app-by-fixable-vulnerability-count/v1",
    "Retrieve top x app packages with the most fixable vulnerabilities",
    "container_packages",
    [
      {
        "type": "string",
        "description": "Filter packages using a query in Falcon Query Language (FQL). Supported filter fields:"
        "  ai_related  cid  container_id  cveid  fix_status  image_digest  license  package_name_version  severity  "
        "type  vulnerability_count",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset from where to begin. Maximum offset = 10000 - limit.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "ReadPackagesByVulnCount",
    "GET",
    "/container-security/combined/packages/by-vulnerability-count/v1",
    "Retrieve top x packages with the most vulnerabilities",
    "container_packages",
    [
      {
        "type": "string",
        "description": "Filter packages using a query in Falcon Query Language (FQL). Supported filter fields:"
        "  ai_related  cid  container_id  cveid  fix_status  image_digest  license  package_name_version  severity  "
        "type  vulnerability_count",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset from where to begin. Maximum offset = 10000 - limit.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "ReadPackagesCombinedExport",
    "GET",
    "/container-security/combined/packages/export/v1",
    "Retrieves a paginated list of packages identified by the provided filter criteria,used for export.Maximum"
    "page size: 100. Maximum available packages: 10,000",
    "container_packages",
    [
      {
        "type": "string",
        "description": "Filter packages using a query in Falcon Query Language (FQL). Supported filter fields:"
        "  ai_related  cid  container_id  cveid  fix_status  image_digest  license  package_name_version  severity  "
        "type  vulnerability_count",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "(true/false) load zero day affected packages",
        "name": "only_zero_day_affected",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort the records on. Supported columns:  license  package_name_version  "
        "type  vulnerability_count",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset from where to begin. Maximum offset = 10000 - limit.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "ReadPackagesCombined",
    "GET",
    "/container-security/combined/packages/v1",
    "Retrieve packages identified by the provided filter criteria",
    "container_packages",
    [
      {
        "type": "string",
        "description": "Filter packages using a query in Falcon Query Language (FQL). Supported filter fields:"
        "  ai_related  cid  container_id  cveid  fix_status  image_digest  license  package_name_version  severity  "
        "type  vulnerability_count",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "(true/false) load zero day affected packages",
        "name": "only_zero_day_affected",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort the records on. Supported columns:  license  package_name_version  "
        "type  vulnerability_count",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset from where to begin. Maximum offset = 10000 - limit.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "ReadPackagesCombinedV2",
    "GET",
    "/container-security/combined/packages/v2",
    "Retrieve packages identified by the provided filter criteria",
    "container_packages",
    [
      {
        "type": "string",
        "description": "Filter packages using a query in Falcon Query Language (FQL). Supported filter fields:"
        "  ai_related  cid  container_id  cveid  fix_status  image_digest  license  package_name_version  severity  "
        "type  vulnerability_count",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "(true/false) load zero day affected packages",
        "name": "only_zero_day_affected",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort the records on. Supported columns:  license  package_name_version  "
        "type  vulnerability_count",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 100.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset from where to begin. Maximum offset = 10000 - limit.",
        "name": "offset",
        "in": "query"
      }
    ]
  ]
]
