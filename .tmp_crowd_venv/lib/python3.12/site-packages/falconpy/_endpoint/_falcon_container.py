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

_falcon_container_endpoints = [
  [
    "DownloadExportFile",
    "GET",
    "/container-security/entities/exports/files/v1",
    "Download an export file",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "Export job ID.",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ReadExportJobs",
    "GET",
    "/container-security/entities/exports/v1",
    "Read export jobs entities",
    "falcon_container",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Export Job IDs to read. Allowed up to 100 IDs per request.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "LaunchExportJob",
    "POST",
    "/container-security/entities/exports/v1",
    "Launch an export job of a Container Security resource. Maximum of 1 job in progress per resource",
    "falcon_container",
    [
      {
        "description": "Supported resources:  assets.clusters  assets.containers  assets.deployments  "
        "assets.images  assets.namespaces  assets.nodes  assets.pods  images.images-assessment-detections-expanded  "
        "images.images-assessment-expanded  images.images-assessment-vulnerabilities-expanded  images.images-assessment "
        "  images.images-detections  images.packages  images.vulnerabilities  investigate.container-alerts  "
        "investigate.drift-indicators  investigate.kubernetes-ioms  investigate.runtime-detections  "
        "investigate.unidentified-containers  policies.exclusions",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCredentials",
    "GET",
    "/container-security/entities/image-registry-credentials/v1",
    "Gets the registry credentials",
    "falcon_container",
    []
  ],
  [
    "ReadRegistryEntitiesByUUID",
    "GET",
    "/container-security/entities/registries/v1",
    "Retrieves a list of registry entities by the provided UUIDs. Maximum page size: 100",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "Registry entity UUID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateRegistryEntities",
    "POST",
    "/container-security/entities/registries/v1",
    "Create a registry entity using the provided details",
    "falcon_container",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateRegistryEntities",
    "PATCH",
    "/container-security/entities/registries/v1",
    "Update the registry entity, as identified by the entity UUID, using the provided details",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "Registry entity UUID",
        "name": "id",
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
    "DeleteRegistryEntities",
    "DELETE",
    "/container-security/entities/registries/v1",
    "Delete the registry entity identified by the entity UUID",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "Registry entity UUID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "QueryExportJobs",
    "GET",
    "/container-security/queries/exports/v1",
    "Query export jobs entities",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "Filter exports using a query in Falcon Query Language (FQL). Only the last 100 jobs "
        "are returned. Supported filter fields:  resource  status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadRegistryEntities",
    "GET",
    "/container-security/queries/registries/v1",
    "Retrieves a list of registry entities identified by the customer id. Maximum page size: 5,000",
    "falcon_container",
    [
      {
        "type": "integer",
        "description": "The upper-bound on the number of records to retrieve.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset from where to begin.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort the records on.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "ReadImageVulnerabilities",
    "POST",
    "/image-assessment/combined/vulnerability-lookups/v1",
    "Retrieve known vulnerabilities for the provided image",
    "falcon_container",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCombinedImages",
    "GET",
    "/container-security/combined/image-assessment/images/v1",
    "Get image assessment results by providing an FQL filter and paging details",
    "falcon_container_image",
    [
      {
        "type": "string",
        "description": "Filter images using a query in Falcon Query Language (FQL). Supported filters:  "
        "container_running_status, cve_id, first_seen, registry, repository, tag, vulnerability_severity",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The upper-bound on the number of records to retrieve [1-100]",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset from where to begin.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort the records on. Supported columns:  [first_seen registry repository "
        "tag vulnerability_severity]",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "GetImageAssessmentReport",
    "GET",
    "/reports",
    "Retrieves the Assessment report for the Image ID provided.",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "The hash digest for the image.",
        "name": "digest",
        "in": "query",
        "required": False
      },
      {
        "type": "string",
        "description": "The image ID.",
        "name": "image_id",
        "in": "query",
        "required": False
      },
      {
        "type": "string",
        "description": "The repository the image resides within.",
        "name": "repository",
        "in": "query",
        "required": False
      },
      {
        "type": "string",
        "description": "The image tag.",
        "name": "tag",
        "in": "query",
        "required": False
      }
    ]
  ],
  [
    "DeleteImageDetails",
    "DELETE",
    "/images/{}",
    "Delete Images by ids.",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "The ID of the image to be deleted.",
        "name": "image_id",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "ImageMatchesPolicy",
    "GET",
    "/policy-checks",
    "After an image scan, use this operation to see if any images match a policy. If deny is true, the policy "
    "suggestion is that you do not deploy the image in your environment.",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "The repository the image resides within.",
        "name": "repository",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The image tag.",
        "name": "tag",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "PostImageScanInventory",
    "POST",
    "/image-assessment/entities/image-inventory/v1",
    "Post image scan inventory",
    "falcon_container",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "HeadImageScanInventory",
    "HEAD",
    "/image-assessment/entities/image-inventory/v1",
    "Get headers for POST request for image scan inventory",
    "falcon_container",
    []
  ],
  [
    "PolicyChecks",
    "GET",
    "/image-assessment/entities/policy-checks/v2",
    "Check image prevention policies",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "Registry",
        "name": "registry",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Repository",
        "name": "repository",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Tag",
        "name": "tag",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetReportByReference",
    "GET",
    "/image-assessment/entities/reports/v2",
    "Get image assessment scan report by image reference (v2)",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "Registry",
        "name": "registry",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Repository",
        "name": "repository",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Tag",
        "name": "tag",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Image ID",
        "name": "image_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Digest",
        "name": "digest",
        "in": "query"
      },
      {
        "type": "string",
        "default": "json",
        "description": "Specify image-assessment scan report format. Supported formats:   cyclonedx-json  json  sarif",
        "name": "report_format",
        "in": "query"
      }
    ]
  ],
  [
    "GetReportByScanID",
    "GET",
    "/image-assessment/entities/reports/v2/{uuid}",
    "Get image assessment scan report by scan UUID (v2)",
    "falcon_container",
    [
      {
        "type": "string",
        "description": "Scan UUID",
        "name": "uuid",
        "in": "path",
        "required": True
      },
      {
        "type": "string",
        "default": "json",
        "description": "Specify image-assessment scan report format. Supported formats:   cyclonedx-json  json  sarif",
        "name": "report_format",
        "in": "query"
      }
    ]
  ]
]
