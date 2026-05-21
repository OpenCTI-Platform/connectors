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

_unidentified_containers_endpoints = [
  [
    "ReadUnidentifiedContainersByDateRangeCount",
    "GET",
    "/container-security/aggregates/unidentified-containers/count-by-date/v1",
    "Returns the count of Unidentified Containers over the last 7 days",
    "unidentified_containers",
    [
      {
        "type": "string",
        "description": "Search Unidentified Containers using a query in Falcon Query Language (FQL). Supported"
        " filter fields:  assessed_images_count  cid  cluster_name  containers_impacted_count  detections_count  "
        "image_assessment_detections_count  last_seen  namespace  node_name  severity  unassessed_images_count  "
        "visible_to_k8s",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadUnidentifiedContainersCount",
    "GET",
    "/container-security/aggregates/unidentified-containers/count/v1",
    "Returns the total count of Unidentified Containers over a time period",
    "unidentified_containers",
    [
      {
        "type": "string",
        "description": "Search Unidentified Containers using a query in Falcon Query Language (FQL). Supported"
        " filter fields:  assessed_images_count  cid  cluster_name  containers_impacted_count  detections_count  "
        "image_assessment_detections_count  last_seen  namespace  node_name  severity  unassessed_images_count  "
        "visible_to_k8s",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "SearchAndReadUnidentifiedContainers",
    "GET",
    "/container-security/combined/unidentified-containers/v1",
    "Search Unidentified Containers by the provided search criteria",
    "unidentified_containers",
    [
      {
        "type": "string",
        "description": "Search Unidentified Containers using a query in Falcon Query Language (FQL). Supported"
        " filter fields:  assessed_images_count  cid  cluster_name  containers_impacted_count  detections_count  "
        "image_assessment_detections_count  last_seen  namespace  node_name  severity  unassessed_images_count  "
        "visible_to_k8s",
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
  ]
]
