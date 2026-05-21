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
# pylint: disable=C0302

_kubernetes_protection_endpoints = [
  [
    "ReadClustersByDateRangeCount",
    "GET",
    "/container-security/aggregates/clusters/count-by-date/v1",
    "Retrieve clusters by date range counts",
    "kubernetes_protection",
    []
  ],
  [
    "ReadClustersByKubernetesVersionCount",
    "GET",
    "/container-security/aggregates/clusters/count-by-kubernetes-version/v1",
    "Bucket clusters by kubernetes version",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes clusters that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  access  agent_id  agent_status  agent_type  cid  cloud_account_id  cloud_name"
        "  cloud_region  cloud_service  cluster_id  cluster_name  cluster_status  container_count  iar_coverage  "
        "kac_agent_id  kubernetes_version  last_seen  management_status  namespace  node_count  pod_count  pod_name  "
        "tags",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadClustersByStatusCount",
    "GET",
    "/container-security/aggregates/clusters/count-by-status/v1",
    "Bucket clusters by status",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes clusters that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  access  agent_id  agent_status  agent_type  cid  cloud_account_id  cloud_name"
        "  cloud_region  cloud_service  cluster_id  cluster_name  cluster_status  container_count  iar_coverage  "
        "kac_agent_id  kubernetes_version  last_seen  management_status  namespace  node_count  pod_count  pod_name  "
        "tags",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadClusterCount",
    "GET",
    "/container-security/aggregates/clusters/count/v1",
    "Retrieve cluster counts",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes clusters that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  access  agent_id  agent_status  agent_type  cid  cloud_account_id  cloud_name"
        "  cloud_region  cloud_service  cluster_id  cluster_name  cluster_status  container_count  iar_coverage  "
        "kac_agent_id  kubernetes_version  last_seen  management_status  namespace  node_count  pod_count  pod_name  "
        "tags",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadContainersByDateRangeCount",
    "GET",
    "/container-security/aggregates/containers/count-by-date/v1",
    "Retrieve containers by date range counts",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Get container counts using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  app_name  cid  cloud_account_id  "
        "cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  container_id  "
        "container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  image_digest  "
        "image_has_been_assessed  image_id  image_registry  image_repository  image_tag  image_vulnerability_count  "
        "insecure_mount_source  insecure_mount_type  insecure_propagation_mode  interactive_mode  ipv4  ipv6  "
        "kac_agent_id  labels  last_seen  namespace  node_name  node_uid  package_name_version  pod_id  pod_name  port"
        "privileged  root_write_access  run_as_root_group  run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadContainerCountByRegistry",
    "GET",
    "/container-security/aggregates/containers/count-by-registry/v1",
    "Retrieves a list with the top container image registries. Maximum page size: 200",
    "kubernetes_protection",
    [
      {
        "type": "boolean",
        "default": False,
        "description": "(true/false) whether to return registries under assessment or not under assessment. If"
        "not provided all registries are considered",
        "name": "under_assessment",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The upper-bound on the number of records to retrieve.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes container image registries that match a query in Falcon "
        "Query Language (FQL). Supported filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  "
        "app_name  cid  cloud_account_id  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  "
        "cluster_name  container_id  container_image_id  container_name  cve_id  detection_name  first_seen  "
        "image_detection_count  image_digest  image_has_been_assessed  image_id  image_registry  image_repository  "
        "image_tag  image_vulnerability_count  insecure_mount_source  insecure_mount_type  insecure_propagation_mode  "
        "interactive_mode  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  "
        "package_name_version  pod_id  pod_name  port  privileged  root_write_access  run_as_root_group  "
        "run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "FindContainersCountAffectedByZeroDayVulnerabilities",
    "GET",
    "/container-security/aggregates/containers/count-by-zero-day/v1",
    "Retrieve containers count affected by zero day vulnerabilities",
    "kubernetes_protection",
    []
  ],
  [
    "ReadVulnerableContainerImageCount",
    "GET",
    "/container-security/aggregates/containers/count-vulnerable-images/v1",
    "Retrieve count of vulnerable images running on containers",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes containers that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  app_name  cid  "
        "cloud_account_id  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  "
        "container_id  container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  "
        "image_digest  image_has_been_assessed  image_id  image_registry  image_repository  image_tag  "
        "image_vulnerability_count  insecure_mount_source  insecure_mount_type  insecure_propagation_mode  "
        "interactive_mode  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  "
        "package_name_version  pod_id  pod_name  port  privileged  root_write_access  run_as_root_group  "
        "run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadContainerCount",
    "GET",
    "/container-security/aggregates/containers/count/v1",
    "Retrieve container counts",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes containers that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  app_name  cid  "
        "cloud_account_id  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  "
        "container_id  container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  "
        "image_digest  image_has_been_assessed  image_id  image_registry  image_repository  image_tag  "
        "image_vulnerability_count  insecure_mount_source  insecure_mount_type  insecure_propagation_mode  "
        "interactive_mode  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  "
        "package_name_version  pod_id  pod_name  port  privileged  root_write_access  run_as_root_group  "
        "run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "FindContainersByContainerRunTimeVersion",
    "GET",
    "/container-security/aggregates/containers/find-by-runtimeversion/v1",
    "Retrieve containers by container_runtime_version",
    "kubernetes_protection",
    [
      {
        "type": "integer",
        "default": 200,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 200.",
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
        "description": "The fields to sort the records on.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes containers that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  app_name  cid  "
        "cloud_account_id  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  "
        "container_id  container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  "
        "image_digest  image_has_been_assessed  image_id  image_registry  image_repository  image_tag  "
        "image_vulnerability_count  insecure_mount_source  insecure_mount_type  insecure_propagation_mode  "
        "interactive_mode  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  "
        "package_name_version  pod_id  pod_name  port  privileged  root_write_access  run_as_root_group  "
        "run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "GroupContainersByManaged",
    "GET",
    "/container-security/aggregates/containers/group-by-managed/v1",
    "Group the containers by Managed",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes containers that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  agent_id  ai_related  allow_privilege_escalation  app_name  cid  "
        "cloud_account_id  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  "
        "container_id  container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  "
        "image_digest  image_has_been_assessed  image_id  image_registry  image_repository  image_tag  "
        "image_vulnerability_count  insecure_mount_source  insecure_mount_type  insecure_propagation_mode  "
        "interactive_mode  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  pod_id  "
        "pod_name  port  privileged  root_write_access  run_as_root_group  run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadContainerImageDetectionsCountByDate",
    "GET",
    "/container-security/aggregates/containers/image-detections-count-by-date/v1",
    "Retrieve count of image assessment detections on running containers over a period of time",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes containers that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  app_name  cid  "
        "cloud_account_id  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  "
        "container_id  container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  "
        "image_digest  image_has_been_assessed  image_id  image_registry  image_repository  image_tag  "
        "image_vulnerability_count  insecure_mount_source  insecure_mount_type  insecure_propagation_mode  "
        "interactive_mode  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  "
        "package_name_version  pod_id  pod_name  port  privileged  root_write_access  run_as_root_group  "
        "run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadContainerImagesByState",
    "GET",
    "/container-security/aggregates/containers/images-by-state/v1",
    "Retrieve count of image states running on containers",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Filter using a query in Falcon Query Language (FQL). Supported filter fields:  cid",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadContainersSensorCoverage",
    "GET",
    "/container-security/aggregates/containers/sensor-coverage/v1",
    "Bucket containers by agent type and calculate sensor coverage",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes containers that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  app_name  cid  "
        "cloud_account_id  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  "
        "container_id  container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  "
        "image_digest  image_has_been_assessed  image_id  image_registry  image_repository  image_tag  "
        "image_vulnerability_count  insecure_mount_source  insecure_mount_type  insecure_propagation_mode  "
        "interactive_mode  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  "
        "package_name_version  pod_id  pod_name  port  privileged  root_write_access  run_as_root_group  "
        "run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadContainerVulnerabilitiesBySeverityCount",
    "GET",
    "/container-security/aggregates/containers/vulnerability-count-by-severity/v1",
    "Retrieve container vulnerabilities by severity counts",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Get vulnerabilities count by severity for container using a query in Falcon Query "
        "Language (FQL). Supported filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  "
        "app_name  cid  cloud_account_id  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  "
        "cluster_name  container_id  container_image_id  container_name  cve_id  detection_name  first_seen  "
        "image_detection_count  image_digest  image_has_been_assessed  image_id  image_registry  image_repository  "
        "image_tag  image_vulnerability_count  insecure_mount_source  insecure_mount_type  insecure_propagation_mode  "
        "interactive_mode  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  "
        "package_name_version  pod_id  pod_name  port  privileged  root_write_access  run_as_root_group  "
        "run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadDeploymentsByDateRangeCount",
    "GET",
    "/container-security/aggregates/deployments/count-by-date/v1",
    "Retrieve deployments by date range counts",
    "kubernetes_protection",
    []
  ],
  [
    "ReadDeploymentCount",
    "GET",
    "/container-security/aggregates/deployments/count/v1",
    "Retrieve deployment counts",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes deployments that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  agent_id  agent_type  annotations_list  cid  cloud_account_id  cloud_name  "
        "cloud_region  cloud_service  cluster_id  cluster_name  deployment_id  deployment_name  deployment_status  "
        "first_seen  kac_agent_id  last_seen  namespace  pod_count  resource_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadClusterEnrichment",
    "GET",
    "/container-security/aggregates/enrichment/clusters/entities/v1",
    "Retrieve cluster enrichment data",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "One or more cluster ids for which to retrieve enrichment info",
        "name": "cluster_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Supported filter fields:  last_seen",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadContainerEnrichment",
    "GET",
    "/container-security/aggregates/enrichment/containers/entities/v1",
    "Retrieve container enrichment data",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "One or more container ids for which to retrieve enrichment info",
        "name": "container_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Supported filter fields:  last_seen",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadDeploymentEnrichment",
    "GET",
    "/container-security/aggregates/enrichment/deployments/entities/v1",
    "Retrieve deployment enrichment data",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "One or more deployment ids for which to retrieve enrichment info",
        "name": "deployment_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Supported filter fields:  last_seen",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadNodeEnrichment",
    "GET",
    "/container-security/aggregates/enrichment/nodes/entities/v1",
    "Retrieve node enrichment data",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "One or more node names for which to retrieve enrichment info",
        "name": "node_name",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Supported filter fields:  last_seen",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadPodEnrichment",
    "GET",
    "/container-security/aggregates/enrichment/pods/entities/v1",
    "Retrieve pod enrichment data",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "One or more pod ids for which to retrieve enrichment info",
        "name": "pod_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Supported filter fields:  last_seen",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadDistinctContainerImageCount",
    "GET",
    "/container-security/aggregates/images/count-by-distinct/v1",
    "Retrieve count of distinct images running on containers",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes containers using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  app_name  cid  cloud_account_id"
        "  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  container_id  "
        "container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  image_digest  "
        "image_has_been_assessed  image_id  image_registry  image_repository  image_tag  image_vulnerability_count  "
        "insecure_mount_source  insecure_mount_type  insecure_propagation_mode  interactive_mode  ipv4  ipv6  "
        "kac_agent_id  labels  last_seen  namespace  node_name  node_uid  package_name_version  pod_id  pod_name  port"
        "privileged  root_write_access  run_as_root_group  run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadContainerImagesByMostUsed",
    "GET",
    "/container-security/aggregates/images/most-used/v1",
    "Bucket container by image-digest",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes containers that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  app_name  cid  "
        "cloud_account_id  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  "
        "container_id  container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  "
        "image_digest  image_has_been_assessed  image_id  image_registry  image_repository  image_tag  "
        "image_vulnerability_count  insecure_mount_source  insecure_mount_type  insecure_propagation_mode  "
        "interactive_mode  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  "
        "package_name_version  pod_id  pod_name  port  privileged  root_write_access  run_as_root_group  "
        "run_as_root_user  running_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadKubernetesIomByDateRange",
    "GET",
    "/container-security/aggregates/kubernetes-ioms/count-by-date/v1",
    "Returns the count of Kubernetes IOMs by the date. by default it's for 7 days.",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Filter Kubernetes IOMs using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  cid  created_timestamp  detect_timestamp  prevented  severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadKubernetesIomCount",
    "GET",
    "/container-security/aggregates/kubernetes-ioms/count/v1",
    "Returns the total count of Kubernetes IOMs over the past seven days",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Filter Kubernetes IOMs using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  cid  created_timestamp  detect_timestamp  prevented  severity",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadNamespacesByDateRangeCount",
    "GET",
    "/container-security/aggregates/namespaces/count-by-date/v1",
    "Retrieve namespaces by date range counts",
    "kubernetes_protection",
    []
  ],
  [
    "ReadNamespaceCount",
    "GET",
    "/container-security/aggregates/namespaces/count/v1",
    "Retrieve namespace counts",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes namespaces that match a query in Falcon Query Language "
        "(FQL). Supported filter fields:  agent_id  agent_type  annotations_list  cid  cloud_account_id  cloud_name  "
        "cloud_region  cloud_service  cluster_id  cluster_name  first_seen  kac_agent_id  last_seen  namespace_id  "
        "namespace_name  resource_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadNodesByCloudCount",
    "GET",
    "/container-security/aggregates/nodes/count-by-cloud/v1",
    "Bucket nodes by cloud providers",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes nodes using a query in Falcon Query Language (FQL). Supported filter"
        " fields:  agent_id  agent_type  annotations_list  cid  cloud_account_id  cloud_name  cloud_region  "
        "cloud_service  cluster_id  cluster_name  container_count  container_runtime_version  first_seen  image_digest"
        "ipv4  kac_agent_id  last_seen  linux_sensor_coverage  node_name  node_uid  pod_count  resource_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadNodesByContainerEngineVersionCount",
    "GET",
    "/container-security/aggregates/nodes/count-by-container-engine-version/v1",
    "Bucket nodes by their container engine version",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes nodes using a query in Falcon Query Language (FQL). Supported filter"
        " fields:  agent_id  agent_type  annotations_list  cid  cloud_account_id  cloud_name  cloud_region  "
        "cloud_service  cluster_id  cluster_name  container_count  container_runtime_version  first_seen  image_digest"
        "ipv4  kac_agent_id  last_seen  linux_sensor_coverage  node_name  node_uid  pod_count  resource_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadNodesByDateRangeCount",
    "GET",
    "/container-security/aggregates/nodes/count-by-date/v1",
    "Retrieve nodes by date range counts",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes nodes using a query in Falcon Query Language (FQL). Supported filter"
        " fields:  agent_id  agent_type  annotations_list  cid  cloud_account_id  cloud_name  cloud_region  "
        "cloud_service  cluster_id  cluster_name  container_count  container_runtime_version  first_seen  image_digest"
        "ipv4  kac_agent_id  last_seen  linux_sensor_coverage  node_name  node_uid  pod_count  resource_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadNodeCount",
    "GET",
    "/container-security/aggregates/nodes/count/v1",
    "Retrieve node counts",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes nodes that match a query in Falcon Query Language (FQL). "
        "Supported filter fields:  agent_id  agent_type  annotations_list  cid  cloud_account_id  cloud_name  "
        "cloud_region  cloud_service  cluster_id  cluster_name  container_count  container_runtime_version  first_seen"
        "  image_digest  ipv4  kac_agent_id  last_seen  linux_sensor_coverage  node_name  node_uid  pod_count  "
        "resource_status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadPodsByDateRangeCount",
    "GET",
    "/container-security/aggregates/pods/count-by-date/v1",
    "Retrieve pods by date range counts",
    "kubernetes_protection",
    []
  ],
  [
    "ReadPodCount",
    "GET",
    "/container-security/aggregates/pods/count/v1",
    "Retrieve pod counts",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve count of Kubernetes pods that match a query in Falcon Query Language (FQL). "
        "Supported filter fields:  agent_id  agent_type  allow_privilege_escalation  annotations_list  app_name  cid  "
        "cloud_account_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  container_count  "
        "first_seen  ipv4  ipv6  kac_agent_id  labels  last_seen  namespace  node_name  node_uid  owner_id  owner_type"
        "  pod_external_id  pod_id  pod_name  port  privileged  resource_status  root_write_access  run_as_root_group  "
        "run_as_root_user",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "ReadClusterCombined",
    "GET",
    "/container-security/combined/clusters/v1",
    "Retrieve kubernetes clusters identified by the provided filter criteria",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes clusters using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  access  agent_id  agent_status  agent_type  cid  cloud_account_id  cloud_name  cloud_region  "
        "cloud_service  cluster_id  cluster_name  cluster_status  container_count  iar_coverage  kac_agent_id  "
        "kubernetes_version  last_seen  management_status  namespace  node_count  pod_count  pod_name  tags",
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
        "default": 200,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 200.",
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
    "ReadClusterCombinedV2",
    "GET",
    "/container-security/combined/clusters/v2",
    "Retrieve Kubernetes cluster data",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes clusters using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  access  agent_id  agent_status  agent_type  cid  cloud_account_id  cloud_name  cloud_region  "
        "cloud_service  cluster_id  cluster_name  cluster_status  container_count  iar_coverage  kac_agent_id  "
        "kubernetes_version  last_seen  management_status  namespace  node_count  pod_count  pod_name  tags",
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
        "type": "boolean",
        "description": "Flag to include node, pod and container counts in the response",
        "name": "include_counts",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 200,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 200.",
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
    "ReadRunningContainerImages",
    "GET",
    "/container-security/combined/container-images/v1",
    "Retrieve images on running containers",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Retrieve list of images on running containers using a query in Falcon Query Language "
        "(FQL). Supported filter fields:  cid  cluster_id  cluster_name  hosts  image_digest  image_has_been_assessed  "
        "image_id  image_name  image_registry  image_repository  image_tag  last_seen  running_status",
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
        "default": 200,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 200.",
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
    "ReadContainerCombined",
    "GET",
    "/container-security/combined/containers/v1",
    "Retrieves a paginated list of containers identified by the provided filter criteria. Maximum page size: "
    "200. Maximum available containers: 10,000",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes containers using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  agent_id  agent_type  ai_related  allow_privilege_escalation  app_name  cid  cloud_account_id"
        "  cloud_instance_id  cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  container_id  "
        "container_image_id  container_name  cve_id  detection_name  first_seen  image_detection_count  image_digest  "
        "image_has_been_assessed  image_id  image_registry  image_repository  image_tag  image_vulnerability_count  "
        "insecure_mount_source  insecure_mount_type  insecure_propagation_mode  interactive_mode  ipv4  ipv6  "
        "kac_agent_id  labels  last_seen  namespace  node_name  node_uid  package_name_version  pod_id  pod_name  port"
        "privileged  root_write_access  run_as_root_group  run_as_root_user  running_status",
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
        "default": 200,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 200.",
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
    "ReadDeploymentCombined",
    "GET",
    "/container-security/combined/deployments/v1",
    "Retrieve kubernetes deployments identified by the provided filter criteria",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes deployments using a query in Falcon Query Language (FQL). Supported "
        "filter fields:  agent_id  agent_type  annotations_list  cid  cloud_account_id  cloud_name  cloud_region  "
        "cloud_service  cluster_id  cluster_name  deployment_id  deployment_name  deployment_status  first_seen  "
        "kac_agent_id  last_seen  namespace  pod_count  resource_status",
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
        "default": 200,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 200.",
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
    "PostSearchKubernetesIOMEntities",
    "POST",
    "/container-security/combined/kubernetes-ioms/search/v1",
    "Search for Kubernetes IOMs with filtering options.Pagination is supported via Elasticsearch's "
    "search_after search param and point in time. Assets are sorted by unique ID in ascending direction.",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes IOMs using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  cid  cis_id  cluster_id  cluster_name  containers_impacted_ai_related  containers_impacted_count  "
        "containers_impacted_ids  detection_type  name  namespace  prevented  resource_id  resource_name  resource_type"
        "severity",
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
        "description": "Maximum number of records to return (default: 100, max: 500)",
        "name": "limit",
        "in": "query"
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "SearchAndReadKubernetesIomEntities",
    "GET",
    "/container-security/combined/kubernetes-ioms/v1",
    "Retrieves a list of Kubernetes IOMs identified by the provided search criteria. Maximum page size: 100. "
    "Maximum available Kubernetes IOMs: 10,000",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes IOMs using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  cid  cis_id  cluster_id  cluster_name  containers_impacted_ai_related  containers_impacted_count  "
        "containers_impacted_ids  detection_type  name  namespace  prevented  resource_id  resource_name  resource_type"
        "severity",
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
    "ReadNodeCombined",
    "GET",
    "/container-security/combined/nodes/v1",
    "Retrieve kubernetes nodes identified by the provided filter criteria",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes nodes using a query in Falcon Query Language (FQL). Supported filter"
        " fields:  agent_id  agent_type  annotations_list  cid  cloud_account_id  cloud_name  cloud_region  "
        "cloud_service  cluster_id  cluster_name  container_count  container_runtime_version  first_seen  image_digest"
        "ipv4  kac_agent_id  last_seen  linux_sensor_coverage  node_name  node_uid  pod_count  resource_status",
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
        "default": 200,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 200.",
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
    "ReadPodCombined",
    "GET",
    "/container-security/combined/pods/v1",
    "Retrieve kubernetes pods identified by the provided filter criteria",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes pods using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  agent_id  agent_type  allow_privilege_escalation  annotations_list  app_name  cid  cloud_account_id  "
        "cloud_name  cloud_region  cloud_service  cluster_id  cluster_name  container_count  first_seen  ipv4  ipv6  "
        "kac_agent_id  labels  last_seen  namespace  node_name  node_uid  owner_id  owner_type  pod_external_id  pod_id"
        "pod_name  port  privileged  resource_status  root_write_access  run_as_root_group  run_as_root_user",
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
        "default": 200,
        "description": "The upper-bound on the number of records to retrieve. Maximum limit: 200.",
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
    "ReadKubernetesIomEntities",
    "GET",
    "/container-security/entities/kubernetes-ioms/v1",
    "Retrieve Kubernetes IOM entities identified by the provided IDs",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Search Kubernetes IOMs by ids - The maximum amount is 100 IDs",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "SearchKubernetesIoms",
    "GET",
    "/container-security/queries/kubernetes-ioms/v1",
    "Search Kubernetes IOMs by the provided search criteria. this endpoint returns a list of Kubernetes IOM "
    "UUIDs matching the query",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Search Kubernetes IOMs using a query in Falcon Query Language (FQL). Supported filter "
        "fields:  cid  cis_id  cluster_id  cluster_name  containers_impacted_ai_related  containers_impacted_count  "
        "containers_impacted_ids  detection_type  name  namespace  prevented  resource_id  resource_name  resource_type"
        "severity",
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
    "GetAWSAccountsMixin0",
    "GET",
    "/kubernetes-protection/entities/accounts/aws/v1",
    "Provides a list of AWS accounts.",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "AWS Account IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "pattern": "^(true|false)$",
        "enum": [
          "false",
          "true"
        ],
        "type": "string",
        "description": "Filter by whether an account originates from Horizon or not",
        "name": "is_horizon_acct",
        "in": "query"
      },
      {
        "pattern": "^(provisioned|operational)$",
        "enum": [
          "operational",
          "provisioned"
        ],
        "type": "string",
        "description": "Filter by account status",
        "name": "status",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 0,
        "type": "integer",
        "description": "Limit returned accounts",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned accounts",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "CreateAWSAccount",
    "POST",
    "/kubernetes-protection/entities/accounts/aws/v1",
    "Creates a new AWS account in our system for a customer and generates the installation script",
    "kubernetes_protection",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateAWSAccount",
    "PATCH",
    "/kubernetes-protection/entities/accounts/aws/v1",
    "Updates the AWS account per the query parameters provided",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "AWS Account ID",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "pattern": "^[a-z\\d-]+$",
        "type": "string",
        "description": "Default Region for Account Automation",
        "name": "region",
        "in": "query"
      }
    ]
  ],
  [
    "DeleteAWSAccountsMixin0",
    "DELETE",
    "/kubernetes-protection/entities/accounts/aws/v1",
    "Delete AWS accounts.",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "AWS Account IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ListAzureAccounts",
    "GET",
    "/kubernetes-protection/entities/accounts/azure/v1",
    "Provides the azure subscriptions registered to Kubernetes Protection",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Azure Tenant IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Azure Subscription IDs",
        "name": "subscription_id",
        "in": "query"
      },
      {
        "pattern": "^(provisioned|operational)$",
        "enum": [
          "operational",
          "provisioned"
        ],
        "type": "string",
        "description": "Filter by account status",
        "name": "status",
        "in": "query"
      },
      {
        "pattern": "^(true|false)$",
        "enum": [
          "false",
          "true"
        ],
        "type": "string",
        "description": "Filter by whether an account originates from Horizon or not",
        "name": "is_horizon_acct",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 0,
        "type": "integer",
        "description": "Limit returned accounts",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned accounts",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "CreateAzureSubscription",
    "POST",
    "/kubernetes-protection/entities/accounts/azure/v1",
    "Creates a new Azure Subscription in our system",
    "kubernetes_protection",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteAzureSubscription",
    "DELETE",
    "/kubernetes-protection/entities/accounts/azure/v1",
    "Deletes a new Azure Subscription in our system",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Azure Subscription IDs",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "GetLocations",
    "GET",
    "/kubernetes-protection/entities/cloud-locations/v1",
    "Provides the cloud locations acknowledged by the Kubernetes Protection service",
    "kubernetes_protection",
    [
      {
        "enum": [
          "aws",
          "azure",
          "gcp"
        ],
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Cloud Provider",
        "name": "clouds",
        "in": "query"
      }
    ]
  ],
  [
    "GetCombinedCloudClusters",
    "GET",
    "/kubernetes-protection/entities/cloud_cluster/v1",
    "Returns a combined list of provisioned cloud accounts and known kubernetes clusters",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Cloud location",
        "name": "locations",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Cloud Account IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "enum": [
          "aks",
          "eks"
        ],
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Cluster Service",
        "name": "cluster_service",
        "in": "query"
      },
      {
        "enum": [
          "Not Installed",
          "Running",
          "Stopped"
        ],
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Cluster Status",
        "name": "cluster_status",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 0,
        "type": "integer",
        "description": "Limit returned accounts",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned accounts",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "GetAzureTenantConfig",
    "GET",
    "/kubernetes-protection/entities/config/azure/v1",
    "Gets the Azure tenant Config",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Azure Tenant IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 0,
        "type": "integer",
        "description": "Limit returned accounts",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned accounts",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "GetStaticScripts",
    "GET",
    "/kubernetes-protection/entities/gen/scripts/v1",
    "Gets static bash scripts that are used during registration",
    "kubernetes_protection",
    []
  ],
  [
    "GetHelmValuesYaml",
    "GET",
    "/kubernetes-protection/entities/integration/agent/v1",
    "Provides a sample Helm values.yaml file for a customer to install alongside the agent Helm chart",
    "kubernetes_protection",
    [
      {
        "type": "string",
        "description": "Cluster name. For EKS it will be cluster ARN.",
        "name": "cluster_name",
        "in": "query",
        "required": True
      },
      {
        "type": "boolean",
        "description": "Set to true if the cluster is not managed by a cloud provider, false if it is.",
        "name": "is_self_managed_cluster",
        "in": "query"
      }
    ]
  ],
  [
    "RegenerateAPIKey",
    "POST",
    "/kubernetes-protection/entities/integration/api-key/v1",
    "Regenerate API key for docker registry integrations",
    "kubernetes_protection",
    []
  ],
  [
    "GetClusters",
    "GET",
    "/kubernetes-protection/entities/kubernetes/clusters/v1",
    "Provides the clusters acknowledged by the Kubernetes Protection service",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Cluster name. For EKS it will be cluster ARN.",
        "name": "cluster_names",
        "in": "query"
      },
      {
        "enum": [
          "Not Installed",
          "Running",
          "Stopped"
        ],
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Cluster Status",
        "name": "status",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Cluster Account id. For EKS it will be AWS account ID.",
        "name": "account_ids",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Cloud location",
        "name": "locations",
        "in": "query"
      },
      {
        "enum": [
          "aks",
          "eks"
        ],
        "type": "string",
        "description": "Cluster Service",
        "name": "cluster_service",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 0,
        "type": "integer",
        "description": "Limit returned accounts",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned accounts",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "TriggerScan",
    "POST",
    "/kubernetes-protection/entities/scan/trigger/v1",
    "Triggers a dry run or a full scan of a customer's kubernetes footprint",
    "kubernetes_protection",
    [
      {
        "pattern": "^(dry-run|full|cluster-refresh)$",
        "enum": [
          "cluster-refresh",
          "dry-run",
          "full"
        ],
        "type": "string",
        "default": "dry-run",
        "description": "Scan Type to do",
        "name": "scan_type",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "PatchAzureServicePrincipal",
    "PATCH",
    "/kubernetes-protection/entities/service-principal/azure/v1",
    "Adds the client ID for the given tenant ID to our system",
    "kubernetes_protection",
    [
      {
        "maxLength": 36,
        "minLength": 36,
        "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$",
        "type": "string",
        "description": "Azure Tenant ID",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "maxLength": 36,
        "minLength": 36,
        "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$",
        "type": "string",
        "description": "Azure Client ID",
        "name": "client_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetAzureTenantIDs",
    "GET",
    "/kubernetes-protection/entities/tenants/azure/v1",
    "Provides all the azure subscriptions and tenants",
    "kubernetes_protection",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Azure Tenant IDs",
        "name": "ids",
        "in": "query"
      },
      {
        "enum": [
          "Not Installed",
          "Running",
          "Stopped"
        ],
        "type": "string",
        "description": "Cluster Status",
        "name": "status",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 0,
        "type": "integer",
        "description": "Limit returned accounts",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned accounts",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "GetAzureInstallScript",
    "GET",
    "/kubernetes-protection/entities/user-script/azure/v1",
    "Provides the script to run for a given tenant id and subscription IDs",
    "kubernetes_protection",
    [
      {
        "maxLength": 36,
        "minLength": 36,
        "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$",
        "type": "string",
        "description": "Azure Tenant ID",
        "name": "id",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Azure Subscription IDs",
        "name": "subscription_id",
        "in": "query"
      }
    ]
  ]
]
