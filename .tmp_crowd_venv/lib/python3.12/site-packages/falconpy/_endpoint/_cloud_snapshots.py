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

_cloud_snapshots_endpoints = [
  [
    "CombinedDetections",
    "GET",
    "/iac/combined/detections/v1",
    "Search IaC Detections using a query in Falcon Query Language",
    "cloud_snapshots",
    [
      {
        "type": "string",
        "description": "Search IaC detections using a query in Falcon Query Language (FQL). Supported filters: "
        " detection_uuid,file_name,last_detected,platform,project_name,project_owner,project_ref,provider,resource_name "
        ",rule_category,rule_name,rule_type,rule_uuid,service,severity",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "the upper-bound on the number of records to retrieve",
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
        "description": "fields to sort the records on. Supported columns:  [detection_uuid file_name "
        "last_detected platform project_name project_owner project_ref provider resource_name rule_category rule_name "
        "rule_type rule_uuid service severity]",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "GetCredentialsIAC",
    "GET",
    "/iac/entities/image-registry-credentials/v1",
    "Gets the registry credentials (external endpoint)",
    "cloud_snapshots",
    []
  ],
  [
    "ReadDeploymentsCombined",
    "GET",
    "/snapshots/combined/deployments/v1",
    "Retrieve snapshot jobs identified by the provided IDs",
    "cloud_snapshots",
    [
      {
        "type": "string",
        "description": "Search snapshot jobs using a query in Falcon Query Language (FQL). Supported filters: "
        "account_id,asset_identifier,cloud_provider,region,status",
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
        "description": "The offset from where to begin.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The fields to sort the records on. Supported columns:  [account_id asset_identifier "
        "cloud_provider instance_type last_updated_timestamp region status]",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "RegisterCspmSnapshotAccount",
    "POST",
    "/snapshots/entities/accounts/v1",
    "Register customer cloud account for snapshot scanning",
    "cloud_snapshots",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ReadDeploymentsEntities",
    "GET",
    "/snapshots/entities/deployments/v1",
    "Retrieve snapshot jobs identified by the provided IDs",
    "cloud_snapshots",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Search snapshot jobs by ids - The maximum amount is 100 IDs",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "CreateDeploymentEntity",
    "POST",
    "/snapshots/entities/deployments/v1",
    "Launch a snapshot scan for a given cloud asset",
    "cloud_snapshots",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCredentialsMixin0",
    "GET",
    "/snapshots/entities/image-registry-credentials/v1",
    "Gets the registry credentials",
    "cloud_snapshots",
    []
  ],
  [
    "CreateInventory",
    "POST",
    "/snapshots/entities/inventories/v1",
    "Create inventory from data received from snapshot",
    "cloud_snapshots",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetScanReport",
    "GET",
    "/snapshots/entities/scanreports/v1",
    "retrieve the scan report for an instance",
    "cloud_snapshots",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "the instance identifiers to fetch the report for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ]
]
