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

_container_image_compliance_endpoints = [
  [
    "extAggregateClusterAssessments",
    "GET",
    "/container-compliance/aggregates/compliance-by-clusters/v2",
    "get the assessments for each cluster",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\ncloud_info.cloud_provider: Cloud provider\ncloud_info.cloud_region: Cloud "
        "region\ncloud_info.cluster_name: Kubernetes cluster name\ncloud_info.cloud_account_id: Cloud account "
        "ID\ncloud_info.namespace: Kubernetes namespace\ncompliance_finding.framework: Compliance finding framework "
        "(available values: CIS)\ncid: Customer ID\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateImageAssessments",
    "GET",
    "/container-compliance/aggregates/compliance-by-images/v2",
    "get the assessments for each image",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\nimage_tag: Image tag\ncompliance_finding.name: Compliance finding Name\nimage_registry: Image "
        "registry\nimage_repository: Image repository\nimage_digest: Image digest (sha256 "
        "digest)\ncloud_info.cloud_account_id: Cloud account ID\ncid: Customer ID\ncompliance_finding.id: Compliance "
        "finding ID\ncloud_info.namespace: Kubernetes namespace\nasset_type: asset type (container, "
        "image)\ncloud_info.cloud_provider: Cloud provider\ncloud_info.cluster_name: Kubernetes cluster "
        "name\ncloud_info.cloud_region: Cloud region\nimage_id: Image ID\ncompliance_finding.framework: Compliance "
        "finding framework (available values: CIS)\ncompliance_finding.severity: Compliance finding severity; available "
        "values: 4, 3, 2, 1 (4: critical, 3: high, 2: medium, 1:low)\n",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "'after' value from the last response. Keep it empty for the first request.",
        "name": "after",
        "in": "query"
      },
      {
        "type": "string",
        "description": "number of images to return in the response after 'after' key. Keep it empty for the "
        "default number of 10000",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateRulesAssessments",
    "GET",
    "/container-compliance/aggregates/compliance-by-rules/v2",
    "get the assessments for each rule",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\ncompliance_finding.id: Compliance finding ID\ncompliance_finding.severity: Compliance finding "
        "severity; available values: 4, 3, 2, 1 (4: critical, 3: high, 2: medium, 1:low)\ncloud_info.cloud_provider: "
        "Cloud provider\nimage_repository: Image repository\nimage_digest: Image digest (sha256 "
        "digest)\ncloud_info.cloud_region: Cloud region\ncompliance_finding.framework: Compliance finding framework "
        "(available values: CIS)\nimage_tag: Image tag\ncloud_info.cluster_name: Kubernetes cluster "
        "name\ncompliance_finding.name: Compliance finding Name\nimage_registry: Image "
        "registry\ncloud_info.cloud_account_id: Cloud account ID\ncid: Customer ID\nimage_id: Image ID\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateFailedContainersByRulesPath",
    "GET",
    "/container-compliance/aggregates/failed-containers-by-rules/v2",
    "get the containers grouped into rules on which they failed",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\nimage_id: Image ID\ncloud_info.namespace: Kubernetes namespace\ncid: Customer "
        "ID\ncloud_info.cluster_name: Kubernetes cluster name\nimage_repository: Image "
        "repository\ncloud_info.cloud_account_id: Cloud account ID\ncloud_info.cloud_region: Cloud "
        "region\ncompliance_finding.framework: Compliance finding framework (available values: CIS)\nimage_registry: "
        "Image registry\nimage_digest: Image digest (sha256 digest)\ncompliance_finding.severity: Compliance finding "
        "severity; available values: 4, 3, 2, 1 (4: critical, 3: high, 2: medium, 1:low)\ncompliance_finding.name: "
        "Compliance finding Name\ncompliance_finding.id: Compliance finding ID\nimage_tag: Image "
        "tag\ncloud_info.cloud_provider: Cloud provider\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateFailedContainersCountBySeverity",
    "GET",
    "/container-compliance/aggregates/failed-containers-count-by-severity/v2",
    "get the failed containers count grouped into severity levels",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\nimage_registry: Image registry\ncompliance_finding.id: Compliance finding "
        "ID\ncloud_info.cloud_region: Cloud region\ncloud_info.cloud_provider: Cloud provider\nimage_repository: Image "
        "repository\nimage_digest: Image digest (sha256 digest)\ncloud_info.cloud_account_id: Cloud account "
        "ID\ncloud_info.namespace: Kubernetes namespace\ncompliance_finding.name: Compliance finding Name\nimage_id: "
        "Image ID\ncid: Customer ID\ncompliance_finding.severity: Compliance finding severity; available values: 4, 3, "
        "2, 1 (4: critical, 3: high, 2: medium, 1:low)\nimage_tag: Image tag\ncompliance_finding.framework: Compliance "
        "finding framework (available values: CIS)\ncloud_info.cluster_name: Kubernetes cluster name\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateFailedImagesByRulesPath",
    "GET",
    "/container-compliance/aggregates/failed-images-by-rules/v2",
    "get the images grouped into rules on which they failed",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported Filters:\ncid: "
        "Customer ID\ncompliance_finding.name: Compliance finding Name\nimage_repository: Image "
        "repository\nimage_digest: Image digest (sha256 digest)\ncloud_info.cloud_account_id: Cloud account "
        "ID\ncompliance_finding.framework: Compliance finding framework (available values: "
        "CIS)\ncompliance_finding.severity: Compliance finding severity; available values: 4, 3, 2, 1 (4: critical, 3: "
        "high, 2: medium, 1:low)\nimage_tag: Image tag\nimage_registry: Image registry\ncloud_info.cloud_region: Cloud "
        "region\ncloud_info.namespace: Kubernetes namespace\ncompliance_finding.id: Compliance finding "
        "ID\ncloud_info.cloud_provider: Cloud provider\ncloud_info.cluster_name: Kubernetes cluster name\nimage_id: "
        "Image ID\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateFailedImagesCountBySeverity",
    "GET",
    "/container-compliance/aggregates/failed-images-count-by-severity/v2",
    "get the failed images count grouped into severity levels",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\ncloud_info.cloud_region: Cloud region\ncloud_info.cloud_provider: Cloud "
        "provider\ncompliance_finding.name: Compliance finding Name\nimage_id: Image ID\ncompliance_finding.id: "
        "Compliance finding ID\nimage_digest: Image digest (sha256 digest)\ncompliance_finding.framework: Compliance "
        "finding framework (available values: CIS)\nimage_tag: Image tag\ncloud_info.namespace: Kubernetes "
        "namespace\ncid: Customer ID\ncompliance_finding.severity: Compliance finding severity; available values: 4, 3, "
        " 2, 1 (4: critical, 3: high, 2: medium, 1:low)\ncloud_info.cluster_name: Kubernetes cluster "
        "name\nimage_registry: Image registry\nimage_repository: Image repository\ncloud_info.cloud_account_id: Cloud "
        "account ID\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateFailedRulesByClusters",
    "GET",
    "/container-compliance/aggregates/failed-rules-by-clusters/v2",
    "get the failed rules for each cluster grouped into severity levels",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\nimage_digest: Image digest (sha256 digest)\ncid: Customer ID\ncloud_info.cloud_provider: Cloud "
        "provider\ncloud_info.cluster_name: Kubernetes cluster name\nimage_id: Image ID\nimage_repository: Image "
        "repository\ncloud_info.cloud_account_id: Cloud account ID\ncompliance_finding.severity: Compliance finding "
        "severity; available values: 4, 3, 2, 1 (4: critical, 3: high, 2: medium, 1:low)\nasset_type: asset type "
        "(container, image)\nimage_tag: Image tag\nimage_registry: Image registry\ncompliance_finding.id: Compliance "
        "finding ID\ncloud_info.cloud_region: Cloud region\ncompliance_finding.framework: Compliance finding framework "
        "(available values: CIS)\ncompliance_finding.name: Compliance finding Name\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateFailedRulesByImages",
    "GET",
    "/container-compliance/aggregates/failed-rules-by-images/v2",
    "get images with failed rules, rule count grouped by severity for each image",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\nimage_digest: Image digest (sha256 digest)\ncompliance_finding.severity: Compliance finding "
        "severity; available values: 4, 3, 2, 1 (4: critical, 3: high, 2: medium, 1:low)\nimage_registry: Image "
        "registry\ncompliance_finding.framework: Compliance finding framework (available values: "
        "CIS)\nimage_repository: Image repository\ncompliance_finding.id: Compliance finding "
        "ID\ncloud_info.cloud_account_id: Cloud account ID\ncloud_info.namespace: Kubernetes "
        "namespace\ncloud_info.cloud_provider: Cloud provider\ncloud_info.cluster_name: Kubernetes cluster "
        "name\ncloud_info.cloud_region: Cloud region\ncid: Customer ID\nasset_type: asset type (container, "
        "image)\nimage_tag: Image tag\ncompliance_finding.name: Compliance finding Name\nimage_id: Image ID\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateFailedRulesCountBySeverity",
    "GET",
    "/container-compliance/aggregates/failed-rules-count-by-severity/v2",
    "get the failed rules count grouped into severity levels",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\nimage_digest: Image digest (sha256 digest)\ncloud_info.cloud_account_id: Cloud account "
        "ID\ncloud_info.cloud_region: Cloud region\nimage_tag: Image tag\nimage_id: Image ID\ncid: Customer "
        "ID\ncompliance_finding.severity: Compliance finding severity; available values: 4, 3, 2, 1 (4: critical, 3: "
        "high, 2: medium, 1:low)\nimage_registry: Image registry\nimage_repository: Image "
        "repository\ncompliance_finding.framework: Compliance finding framework (available values: CIS)\nasset_type: "
        "asset type (container, image)\ncloud_info.cloud_provider: Cloud provider\ncloud_info.cluster_name: Kubernetes "
        "cluster name\ncompliance_finding.name: Compliance finding Name\ncompliance_finding.id: Compliance finding "
        "ID\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "extAggregateRulesByStatus",
    "GET",
    "/container-compliance/aggregates/rules-by-status/v2",
    "get the rules grouped by their statuses",
    "container_image_compliance",
    [
      {
        "type": "string",
        "description": "Filter results using a query in Falcon Query Language (FQL). Supported "
        "Filters:\nasset_type: asset type (container, image)\nimage_tag: Image tag\ncontainer_name: Container "
        "name\ncompliance_finding.name: Compliance finding Name\nimage_id: Image ID\nimage_repository: Image "
        "repository\ncompliance_finding.framework: Compliance finding framework (available values: "
        "CIS)\ncompliance_finding.severity: Compliance finding severity; available values: 4, 3, 2, 1 (4: critical, 3: "
        "high, 2: medium, 1:low)\ncloud_info.cluster_name: Kubernetes cluster name\nimage_digest: Image digest (sha256 "
        "digest)\ncontainer_id: Container ID\ncloud_info.cloud_account_id: Cloud account ID\ncid: Customer "
        "ID\ncloud_info.cloud_provider: Cloud provider\nimage_registry: Image registry\ncompliance_finding.id: "
        "Compliance finding ID\ncloud_info.cloud_region: Cloud region\n",
        "name": "filter",
        "in": "query"
      }
    ]
  ]
]
