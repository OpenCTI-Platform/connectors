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

_container_detections_endpoints = [
  [
    "ReadDetectionsCountBySeverity",
    "GET",
    "/container-security/aggregates/detections/count-by-severity/v1",
    "Aggregate counts of detections by severity",
    "container_detections",
    [
      {
        "type": "string",
        "description": "Filter images detections using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  cid  detection_type  image_digest  image_registry  image_repository  image_tag  severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadDetectionsCountByType",
    "GET",
    "/container-security/aggregates/detections/count-by-type/v1",
    "Aggregate counts of detections by detection type",
    "container_detections",
    [
      {
        "type": "string",
        "description": "Filter images detections using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  cid  detection_type  image_digest  image_registry  image_repository  image_tag  severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadDetectionsCount",
    "GET",
    "/container-security/aggregates/detections/count/v1",
    "Aggregate count of detections",
    "container_detections",
    [
      {
        "type": "string",
        "description": "Filter images detections using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  cid  detection_type  image_digest  image_registry  image_repository  image_tag  severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadCombinedDetections",
    "GET",
    "/container-security/combined/detections/v1",
    "Retrieve image assessment detections identified by the provided filter criteria",
    "container_detections",
    [
      {
        "type": "string",
        "description": "Filter images detections using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  cid  detection_type  image_digest  image_registry  image_repository  image_tag  severity",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort the records on. Supported columns:  containers_impacted  "
        "detection_name  detection_severity  detection_type  images_impacted  last_detected",
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
    "GetRuntimeDetectionsCombinedV2",
    "GET",
    "/container-security/combined/runtime-detections/v2",
    "Retrieve container runtime detections by the provided search criteria",
    "container_detections",
    [
      {
        "type": "string",
        "description": "Filter Container Runtime Detections using a query in Falcon Query Language (FQL). "
        "Supported filter fields:  agent_type  aid  cid  cloud_name  cloud  cluster_name  computer_name  container_id  "
        "detect_timestamp  host_id  host_type  image_id  name  namespace  pod_name  severity",
        "name": "filter",
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
    "ReadDetections",
    "GET",
    "/container-security/entities/detections/v1",
    "Retrieve image assessment detection entities identified by the provided filter criteria",
    "container_detections",
    [
      {
        "type": "string",
        "description": "Filter images detections using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  cid  detection_type  image_digest  image_registry  image_repository  image_tag  severity",
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
    "SearchDetections",
    "GET",
    "/container-security/queries/detections/v1",
    "Retrieve image assessment detection entities identified by the provided filter criteria",
    "container_detections",
    [
      {
        "type": "string",
        "description": "Filter images detections using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  cid  detection_type  image_digest  image_registry  image_repository  image_tag  severity",
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
  ]
]
