"""Internal API endpoint constant library (deprecated operations).

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

_cloud_security_assets_endpoints = [
  [
    "cloud-security-assets-combined-application-findings",
    "GET",
    "/cloud-security-assets/combined/application-findings/v1",
    "Get findings for an application resource with pagination",
    "cloud_security_assets",
    [
      {
        "type": "string",
        "description": "Application CRN",
        "name": "crn",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Finding type",
        "name": "type",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "FQL string to filter findings",
        "name": "filter",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Pagination offset",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 50,
        "description": "Page size",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "cloud-security-assets-combined-compliance-by-account",
    "GET",
    "/cloud-security-assets/combined/compliance-controls/by-account-region-and-resource-type/v1",
    "Gets combined compliance data aggregated by account and region. Results can be filtered and sorted.",
    "cloud_security_assets",
    [
      {
        "type": "string",
        "description": "FQL string to filter on asset contents. Filterable fields include:  account_id  "
        "account_name  assessment_id  business_impact  cloud_group  cloud_label  cloud_label_id  cloud_provider  "
        "cloud_scope  compliant  control.benchmark.name  control.benchmark.version  control.extension.status  "
        "control.framework  control.name  control.type  control.version  environment  last_evaluated  region  "
        "resource_provider  resource_type  resource_type_name  service  service_category  severities  tag_key  "
        "tag_value  tags_string",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort expression in format: field|direction (e.g., last_evaluated|desc). Allowed sort "
        "fields:   account_id  account_name  assessment_id  cloud_provider  control.benchmark.name  "
        "control.benchmark.version  control.framework  control.name  control.type  control.version  last_evaluated  "
        "region  resource_counts.compliant  resource_counts.non_compliant  resource_counts.total  resource_provider  "
        "resource_type  resource_type_name  service  service_category",
        "name": "sort",
        "in": "query"
      },
      {
        "maximum": 10000,
        "minimum": 0,
        "type": "integer",
        "default": 20,
        "description": "The maximum number of items to return. When not specified or 0, 20 is used. When "
        "larger than 10000, 10000 is used.",
        "name": "limit",
        "in": "query"
      },
      {
        "maximum": 9999,
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned controls. Use only one of 'offset' and 'after' parameter for "
        "paginating. 'offset' can only be used on offsets < 10,000. For paginating through the entire result set, use "
        "'after' parameter",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "token-based pagination. use for paginating through an entire result set. Use only one "
        "of 'offset' and 'after' parameters for paginating",
        "name": "after",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Include counts of failing IOMs by severity level",
        "name": "include_failing_iom_severity_counts",
        "in": "query"
      }
    ]
  ],
  [
    "cloud-security-assets-entities-get",
    "GET",
    "/cloud-security-assets/entities/resources/v1",
    "Gets raw resources based on the provided IDs param.  Maximum of 100 resources can be requested with this "
    "method.  Use POST method with same path if more are required.",
    "cloud_security_assets",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "List of assets to return (maximum 100 IDs allowed).  Use POST method with same path if "
        "more entities are required.",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "cloud-security-assets-queries",
    "GET",
    "/cloud-security-assets/queries/resources/v1",
    "Gets a list of resource IDs for the given parameters, filters and sort criteria",
    "cloud_security_assets",
    [
      {
        "type": "string",
        "description": "token-based pagination. use for paginating through an entire result set. Use only one "
        "of 'offset' and 'after' parameters for paginating",
        "name": "after",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL string to filter on asset contents. Filterable fields include:  account_id  "
        "account_name  active  aspm.deployment_cloud_resource_id  aspm.deployment_provider  aspm.deployment_type  "
        "aspm.technologies  azure.vm_id  business_impact  cloud_group  cloud_label  cloud_label_id  cloud_provider  "
        "cloud_scope  cluster_id  cluster_name  compartment_ocid  compliant.benchmark_name  compliant.benchmark_version "
        "  compliant.framework  compliant.policy_id  compliant.requirement  compliant.rule  compliant.section  "
        "configuration.id  control.benchmark.name  control.benchmark.version  control.framework  control.requirement  "
        "control.type  control.version  creation_time  cve_ids  data_classifications.found  data_classifications.label "
        "  data_classifications.label_id  data_classifications.scanned  data_classifications.tag  "
        "data_classifications.tag_id  environment  exprt_ratings  first_seen  highest_severity  id  "
        "insights.boolean_value  insights.date_value  insights.id  insights.integer_value  insights.string_list_value  "
        "insights.string_value  instance_id  instance_state  ioa_count  iom_count  legacy_resource_id  legacy_uuid  "
        "managed_by  non_compliant.benchmark_name  non_compliant.benchmark_version  non_compliant.framework  "
        "non_compliant.policy_id  non_compliant.requirement  non_compliant.rule  non_compliant.rule_name  "
        "non_compliant.section  non_compliant.severity  organization_Id  os_version  platform_name  publicly_exposed  "
        "region  resource_id  resource_name  resource_parent  resource_type  resource_type_name  sensor_priority  "
        "service  service_category  severity  snapshot_detections  ssm_managed  status  tag_key  tag_value  tags  "
        "tags_string  tenant_id  updated_at  vmware.guest_os_id  vmware.guest_os_version  vmware.host_system_name  "
        "vmware.host_type  vmware.instance_uuid  vmware.vm_host_name  vmware.vm_tools_status  zone",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The field to sort on.  Sortable fields include:  account_id  account_name  active  "
        "aspm.deployment_cloud_resource_id  aspm.deployment_provider  aspm.deployment_type  aspm.technologies  "
        "cloud_provider  cluster_id  cluster_name  compartment_name  compartment_ocid  compartment_path  creation_time "
        "  data_classifications.found  data_classifications.scanned  first_seen  id  instance_id  instance_state  "
        "ioa_count  iom_count  managed_by  organization_Id  os_version  platform_name  publicly_exposed  region  "
        "resource_id  resource_name  resource_parent  resource_type  resource_type_name  service  service_category  "
        "ssm_managed  status  tenancy_name  tenancy_ocid  tenancy_type  tenant_id  updated_at  vmware.guest_os_id  "
        "vmware.guest_os_version  vmware.host_system_name  vmware.host_type  vmware.instance_uuid  vmware.vm_host_name "
        "vmware.vm_tools_status  zone\n\nUse |asc or |desc suffix to specify sort direction.",
        "name": "sort",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 0,
        "type": "integer",
        "default": 500,
        "description": "The maximum number of items to return. When not specified or 0, 500 is used. When "
        "larger than 1000, 1000 is used.",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "Offset returned assets. Use only one of 'offset' and 'after' parameter for paginating. "
        " 'offset' can only be used on offsets < 10,000. For paginating through the entire result set, use 'after' "
        "parameter",
        "name": "offset",
        "in": "query"
      }
    ]
  ]
]
