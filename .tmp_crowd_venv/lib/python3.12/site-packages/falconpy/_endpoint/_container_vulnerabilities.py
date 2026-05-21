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

_container_vulnerabilities_endpoints = [
  [
    "ReadVulnerabilityCountByActivelyExploited",
    "GET",
    "/container-security/aggregates/vulnerabilities/count-by-actively-exploited/v1",
    "Aggregate count of vulnerabilities grouped by actively exploited",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  ai_related  base_os  cid  container_id  container_running_status  containers_impacted_range  "
        "cps_rating  cve_id  cvss_score  description  exploited_status_name  exploited_status  fix_status  image_digest"
        "  image_id  images_impacted_range  include_base_image_vuln  package_name_version  registry  repository  "
        "severity  tag",
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
    "ReadVulnerabilityCountByCPSRating",
    "GET",
    "/container-security/aggregates/vulnerabilities/count-by-cps-rating/v1",
    "Aggregate count of vulnerabilities grouped by csp_rating",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  ai_related  base_os  cid  container_id  container_running_status  containers_impacted_range  "
        "cps_rating  cve_id  cvss_score  description  exploited_status_name  exploited_status  fix_status  image_digest"
        "  image_id  images_impacted_range  include_base_image_vuln  package_name_version  registry  repository  "
        "severity  tag",
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
    "ReadVulnerabilityCountByCVSSScore",
    "GET",
    "/container-security/aggregates/vulnerabilities/count-by-cvss-score/v1",
    "Aggregate count of vulnerabilities grouped by CVSS score",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  ai_related  base_os  cid  container_id  container_running_status  containers_impacted_range  "
        "cps_rating  cve_id  cvss_score  description  exploited_status_name  exploited_status  fix_status  image_digest"
        "  image_id  images_impacted_range  include_base_image_vuln  package_name_version  registry  repository  "
        "severity  tag",
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
    "ReadVulnerabilityCountBySeverity",
    "GET",
    "/container-security/aggregates/vulnerabilities/count-by-severity/v1",
    "Aggregate count of vulnerabilities grouped by severity",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  ai_related  base_os  cid  container_id  container_running_status  containers_impacted_range  "
        "cps_rating  cve_id  cvss_score  description  exploited_status_name  exploited_status  fix_status  image_digest"
        "  image_id  images_impacted_range  include_base_image_vuln  package_name_version  registry  repository  "
        "severity  tag",
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
    "ReadVulnerabilityCount",
    "GET",
    "/container-security/aggregates/vulnerabilities/count/v1",
    "Aggregate count of vulnerabilities",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  ai_related  base_os  cid  container_id  container_running_status  containers_impacted_range  "
        "cps_rating  cve_id  cvss_score  description  exploited_status_name  exploited_status  fix_status  image_digest"
        "  image_id  images_impacted_range  include_base_image_vuln  package_name_version  registry  repository  "
        "severity  tag",
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
    "ReadVulnerabilitiesByImageCount",
    "GET",
    "/container-security/combined/vulnerabilities/by-image-count/v1",
    "Retrieve top x vulnerabilities with the most impacted images",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  cid  cve_id  registry  repository  tag",
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
    "ReadVulnerabilitiesPublicationDate",
    "GET",
    "/container-security/combined/vulnerabilities/by-published-date/v1",
    "Retrieve top x vulnerabilities with the most recent publication date",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  cid  cve_id  registry  repository  tag",
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
    "ReadCombinedVulnerabilitiesDetails",
    "GET",
    "/container-security/combined/vulnerabilities/details/v1",
    "Retrieve vulnerability details related to an image",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Image UUID",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Filter the vulnerabilities using a query in Falcon Query Language (FQL). Supported "
        "vulnerability filter fields:  cid  cps_rating  cve_id  cvss_score  exploited_status_name  exploited_status  "
        "include_base_image_vuln  is_zero_day  remediation_available  severity",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 5000,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 5000.",
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
    "ReadCombinedVulnerabilitiesInfo",
    "GET",
    "/container-security/combined/vulnerabilities/info/v1",
    "Retrieve vulnerability and package related info for this customer",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Vulnerability CVE ID",
        "name": "cve_id",
        "in": "query",
        "required": True
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
    "ReadCombinedVulnerabilities",
    "GET",
    "/container-security/combined/vulnerabilities/v1",
    "Retrieves a paginated list of vulnerabilities filtered by the provided FQL. Maximum page size: 100. "
    "Maximum available vulnerabilities: 10,000",
    "container_vulnerabilities",
    [
      {
        "type": "string",
        "description": "Filter vulnerabilities using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  ai_related  base_os  cid  container_id  container_running_status  containers_impacted_range  "
        "cps_rating  cve_id  cvss_score  description  exploited_status_name  exploited_status  fix_status  image_digest"
        "  image_id  images_impacted_range  include_base_image_vuln  package_name_version  registry  repository  "
        "severity  tag",
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
      },
      {
        "type": "string",
        "description": "The fields to sort the records on. Supported columns:  cps_current_rating  cve_id  "
        "cvss_score  description  images_impacted  packages_impacted  severity",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
