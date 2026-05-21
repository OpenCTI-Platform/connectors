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

_container_images_endpoints = [
  [
    "AggregateImageAssessmentHistory",
    "GET",
    "/container-security/aggregates/images/assessment-history/v1",
    "Image assessment history",
    "container_images",
    [
      {
        "type": "string",
        "description": "Filter using a query in Falcon Query Language (FQL). Supported filter fields:  cid  "
        "registry  repository",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "AggregateImageCountByBaseOS",
    "GET",
    "/container-security/aggregates/images/count-by-os-distribution/v1",
    "Aggregate count of images grouped by Base OS distribution",
    "container_images",
    [
      {
        "type": "string",
        "description": "Filter images using a query in Falcon Query Language (FQL). Supported filter fields:  "
        "arch  base_os  cid  first_seen  image_digest  image_id  registry  repository  source  tag",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "AggregateImageCountByState",
    "GET",
    "/container-security/aggregates/images/count-by-state/v1",
    "Aggregate count of images grouped by state",
    "container_images",
    [
      {
        "type": "string",
        "description": "Filter images using a query in Falcon Query Language (FQL). Supported filter fields:  "
        "arch  base_os  cid  first_seen  image_digest  image_id  registry  repository  source  tag",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "AggregateImageCount",
    "GET",
    "/container-security/aggregates/images/count/v1",
    "Aggregate count of images",
    "container_images",
    [
      {
        "type": "string",
        "description": "Filter images using a query in Falcon Query Language (FQL). Supported filter fields:  "
        "ai_related  ai_vulnerability_count  arch  base_os  cid  container_id  container_running_status  cps_rating  "
        "crowdstrike_user  cve_id  detection_count  detection_name  detection_severity  first_seen  image_digest  "
        "image_id  include_base_image_vuln  layer_digest  package_name_version  registry  repository  source  tag  "
        "vulnerability_count  vulnerability_severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "CombinedBaseImages",
    "GET",
    "/container-security/combined/base-images/v1",
    "Retrieves a list of base images for the provided filter. Maximum page size: 100",
    "container_images",
    [
      {
        "type": "string",
        "description": "Search base images using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  image_digest  image_id  registry  repository  tag",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "GetCombinedImages",
    "GET",
    "/container-security/combined/image-assessment/images/v1",
    "Get image assessment results by providing an FQL filter and paging details",
    "container_images",
    [
      {
        "type": "string",
        "description": "Filter images using a query in Falcon Query Language (FQL). Supported filter fields:  "
        "ai_related  container_id  container_running_status  cve_id  detection_name  detection_severity  first_seen  "
        "image_digest  image_id  registry  repository  tag  vulnerability_severity",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort the records on. Supported columns:  first_seen  "
        "highest_detection_severity  highest_vulnerability_severity  image_digest  image_id  registry  repository  "
        "source  tag",
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
    "CombinedImageByVulnerabilityCount",
    "GET",
    "/container-security/combined/images/by-vulnerability-count/v1",
    "Retrieve top x images with the most vulnerabilities",
    "container_images",
    [
      {
        "type": "string",
        "description": "Filter images using a query in Falcon Query Language (FQL). Supported filter fields:  "
        "arch  base_os  cid  first_seen  image_digest  image_id  registry  repository  source  tag",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The upper-bound on the number of records to retrieve.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The fields to sort the records on. **Not supported.**",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "CombinedImageDetail",
    "GET",
    "/container-security/combined/images/detail/v1",
    "Retrieve image entities identified by the provided filter criteria",
    "container_images",
    [
      {
        "type": "string",
        "description": "Filter images using a query in Falcon Query Language (FQL). Supported filter fields:  "
        "arch  base_os  cid  first_seen  image_digest  image_id  registry  repository  source  tag",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "(true/false) include image config, default is false",
        "name": "with_config",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort the records on.",
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
    "ReadCombinedImagesExport",
    "GET",
    "/container-security/combined/images/export/v1",
    "Retrieves a paginated list of images, with an option to expand aggregated vulnerabilities/detections. "
    "Maximum page size: 100. Maximum available images: 10,000",
    "container_images",
    [
      {
        "type": "string",
        "description": "Filter images using a query in Falcon Query Language (FQL). Supported filter fields:  "
        "ai_related  ai_vulnerability_count  arch  base_os  cid  container_id  container_running_status  cps_rating  "
        "crowdstrike_user  cve_id  detection_count  detection_name  detection_severity  first_seen  image_digest  "
        "image_id  include_base_image_vuln  layer_digest  package_name_version  registry  repository  source  tag  "
        "vulnerability_count  vulnerability_severity",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Expand vulnerabilities details",
        "name": "expand_vulnerabilities",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Expand detections details",
        "name": "expand_detections",
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
        "description": "The fields to sort the records on. Supported columns:  ai_vulnerabilities  base_os  "
        "cid  detections  firstScanned  first_seen  highest_cps_current_rating  highest_detection_severity  "
        "highest_vulnerability_severity  image_digest  image_id  last_seen  layers_with_vulnerabilities  packages  "
        "registry  repository  source  tag  vulnerabilities",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "CombinedImageIssuesSummary",
    "GET",
    "/container-security/combined/images/issues-summary/v1",
    "Retrieve image issues summary such as Image detections, Runtime detections, Policies, vulnerabilities",
    "container_images",
    [
      {
        "type": "string",
        "description": "CS Customer ID",
        "name": "cid",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Registry",
        "name": "registry",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Repository name",
        "name": "repository",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Tag name",
        "name": "tag",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Digest ID",
        "name": "image_digest",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Include base image vulnerabilities.",
        "name": "include_base_image_vuln",
        "in": "query"
      }
    ]
  ],
  [
    "CombinedImageVulnerabilitySummary",
    "GET",
    "/container-security/combined/images/vulnerabilities-summary/v1",
    "aggregates information about vulnerabilities for an image",
    "container_images",
    [
      {
        "type": "string",
        "description": "CS Customer ID",
        "name": "cid",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Registry",
        "name": "registry",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Repository name",
        "name": "repository",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Tag name",
        "name": "tag",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Digest ID",
        "name": "image_digest",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Include base image vulnerabilities.",
        "name": "include_base_image_vuln",
        "in": "query"
      }
    ]
  ],
  [
    "CreateBaseImagesEntities",
    "POST",
    "/container-security/entities/base-images/v1",
    "Creates base images using the provided details",
    "container_images",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteBaseImages",
    "DELETE",
    "/container-security/entities/base-images/v1",
    "Delete base images by base image uuid",
    "container_images",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "BaseImageIDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ]
]
