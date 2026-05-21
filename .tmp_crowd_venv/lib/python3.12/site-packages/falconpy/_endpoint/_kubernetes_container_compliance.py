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

_kubernetes_container_compliance_endpoints = [
  [
    "AggregateAssessmentsGroupedByClustersV2",
    "GET",
    "/container-compliance/aggregates/clusters/v2",
    "Returns cluster details along with aggregated assessment results organized by cluster, including "
    "pass/fail assessment counts for various asset types.",
    "kubernetes_container_compliance",
    [
      {
        "type": "integer",
        "description": "The zero-based position of the first record to return.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of records to return. (1-500) Default is 20.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL filter expression used to limit the results. Filter fields include: cid, "
        "cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, "
        "cloud_info.cluster_name, cloud_info.cluster_type, compliance_finding.framework_name, "
        "compliance_finding.framework_name_version, compliance_finding.framework_version, compliance_finding.severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "AggregateComplianceByAssetType",
    "GET",
    "/container-compliance/aggregates/compliance-by-asset-type/v2",
    "Provides aggregated compliance assessment metrics and rule status information, organized by asset type.",
    "kubernetes_container_compliance",
    [
      {
        "type": "string",
        "description": "FQL filter expression used to limit the results. Filter fields include: cid, "
        "cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, "
        "cloud_info.cluster_name, cloud_info.cluster_type, compliance_finding.asset_type, "
        "compliance_finding.framework_name, compliance_finding.framework_name_version, "
        "compliance_finding.framework_version, compliance_finding.severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "AggregateComplianceByClusterType",
    "GET",
    "/container-compliance/aggregates/compliance-by-cluster-type/v2",
    "Provides aggregated compliance assessment metrics and rule status information, organized by Kubernetes cluster type.",
    "kubernetes_container_compliance",
    [
      {
        "type": "string",
        "description": "FQL filter expression used to limit the results. Filter fields include: cid, "
        "cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, "
        "cloud_info.cluster_name, cloud_info.cluster_type, compliance_finding.asset_type, "
        "compliance_finding.framework_name, compliance_finding.framework_name_version, "
        "compliance_finding.framework_version, compliance_finding.severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "AggregateComplianceByFramework",
    "GET",
    "/container-compliance/aggregates/compliance-by-framework/v2",
    "Provides aggregated compliance assessment metrics and rule status information, organized by compliance framework.",
    "kubernetes_container_compliance",
    [
      {
        "type": "string",
        "description": "FQL filter expression used to limit the results. Filter fields include: cid, "
        "cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, "
        "cloud_info.cluster_name, cloud_info.cluster_type, compliance_finding.asset_type, "
        "compliance_finding.framework_name, compliance_finding.framework_name_version, "
        "compliance_finding.framework_version, compliance_finding.severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "AggregateFailedRulesByClustersV3",
    "GET",
    "/container-compliance/aggregates/failed-rules-by-clusters/v3",
    "Retrieves the most non-compliant clusters, ranked in descending order based on the number of failed "
    "compliance rules across severity levels (critical, high, medium, and low).",
    "kubernetes_container_compliance",
    [
      {
        "type": "string",
        "description": "FQL filter expression used to limit the results. Filter fields include: cid, "
        "cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, "
        "cloud_info.cluster_name, cloud_info.cluster_type, compliance_finding.asset_type, "
        "compliance_finding.framework_name, compliance_finding.framework_name_version, "
        "compliance_finding.framework_version, compliance_finding.severity",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of records to return. (1-100) Default is 10.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "AggregateAssessmentsGroupedByRulesV2",
    "GET",
    "/container-compliance/aggregates/rules/v2",
    "Returns rule details along with aggregated assessment results organized by compliance rule, including "
    "pass/fail assessment counts.",
    "kubernetes_container_compliance",
    [
      {
        "type": "integer",
        "description": "The zero-based position of the first record to return.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of records to return. (1-500) Default is 20.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL filter expression used to limit the results. Filter fields include: cid, "
        "cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, "
        "cloud_info.cluster_name, cloud_info.cluster_type, compliance_finding.asset_type, "
        "compliance_finding.framework_name, compliance_finding.framework_name_version, "
        "compliance_finding.framework_version, compliance_finding.id, compliance_finding.severity, "
        "compliance_finding.status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "AggregateTopFailedImages",
    "GET",
    "/container-compliance/aggregates/top-failed-images/v2",
    "Retrieves the most non-compliant container images, ranked in descending order based on the number of "
    "failed assessments across severity levels (critical, high, medium, and low).",
    "kubernetes_container_compliance",
    [
      {
        "type": "string",
        "description": "FQL filter expression used to limit the results. Filter fields include: cid, "
        "cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, "
        "cloud_info.cluster_name, cloud_info.cluster_type, compliance_finding.asset_type, "
        "compliance_finding.framework_name, compliance_finding.framework_name_version, "
        "compliance_finding.framework_version, compliance_finding.severity",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of records to return. (1-100) Default is 10.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "CombinedImagesFindings",
    "GET",
    "/container-compliance/combined/findings-by-images/v2",
    "Returns detailed compliance assessment results for container images, providing the information needed to "
    "identify compliance violations.",
    "kubernetes_container_compliance",
    [
      {
        "type": "string",
        "description": "FQL filter expression used to limit the results. Filter fields include: cid, "
        "cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, "
        "cloud_info.cluster_name, cloud_info.cluster_type, cloud_info.namespace, compliance_finding.asset_uid, "
        "compliance_finding.framework_name, compliance_finding.framework_name_version, "
        "compliance_finding.framework_version, compliance_finding.id, compliance_finding.severity, "
        "compliance_finding.status, image_digest, image_id, image_registry, image_repository, image_tag",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an after token. On subsequent requests, provide the after token from the "
        "previous response to continue from that place in the results.",
        "name": "after",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of images for which assessments are to be returned: 1-100. Default "
        "is 100. Use with the after parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "CombinedNodesFindings",
    "GET",
    "/container-compliance/combined/findings-by-nodes/v2",
    "Returns detailed compliance assessment results for kubernetes nodes, providing the information needed to "
    "identify compliance violations.",
    "kubernetes_container_compliance",
    [
      {
        "type": "string",
        "description": "FQL filter expression used to limit the results. Filter fields include: cid, "
        "cloud_info.cloud_account_id, cloud_info.cloud_provider, cloud_info.cloud_region, cloud_info.cluster_id, "
        "cloud_info.cluster_name, cloud_info.cluster_type, compliance_finding.asset_type, compliance_finding.asset_uid, "
        " compliance_finding.framework_name, compliance_finding.framework_name_version, "
        "compliance_finding.framework_version, compliance_finding.id, compliance_finding.severity, "
        "compliance_finding.status, aid, node_id, node_name, node_type",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an after token. On subsequent requests, provide the after token from the "
        "previous response to continue from that place in the results.",
        "name": "after",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of nodes for which assessments are to be returned: 1-100. Default "
        "is 100. Use with the after parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "getRulesMetadataByID",
    "GET",
    "/container-compliance/combined/rule-details-by-rule-ids/v1",
    "Retrieve detailed compliance rule information including descriptions, remediation steps, and audit "
    "procedures by specifying rule identifiers.",
    "kubernetes_container_compliance",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "comma separated list of rule ids",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ]
]
