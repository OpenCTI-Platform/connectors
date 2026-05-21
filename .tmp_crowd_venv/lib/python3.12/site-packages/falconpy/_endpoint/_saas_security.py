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

_saas_security_endpoints = [
  [
    "GetMetricsV3",
    "GET",
    "/saas-security/aggregates/check-metrics/v3",
    "GET Metrics",
    "saas_security",
    [
      {
        "enum": [
          "Passed",
          "Failed",
          "Dismissed",
          "Pending",
          "Can't Run",
          "Stale"
        ],
        "type": "string",
        "description": "Exposure status",
        "name": "status",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of objects to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The starting index of the results",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of integration IDs",
        "name": "integration_id",
        "in": "query"
      },
      {
        "enum": [
          1,
          2,
          3
        ],
        "type": "string",
        "description": "Impact",
        "name": "impact",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Compliance",
        "name": "compliance",
        "in": "query"
      },
      {
        "enum": [
          "apps",
          "devices",
          "users",
          "assets",
          "permissions",
          "Falcon Shield Security Check",
          "custom"
        ],
        "type": "string",
        "description": "Check Type",
        "name": "check_type",
        "in": "query"
      }
    ]
  ],
  [
    "GetAlertsV3",
    "GET",
    "/saas-security/entities/alerts/v3",
    "GET Alert by ID or GET Alerts",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Alert ID",
        "name": "id",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of objects to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The starting index of the results",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The last id of the alert you want to get",
        "name": "last_id",
        "in": "query"
      },
      {
        "enum": [
          "configuration_drift",
          "check_degraded",
          "integration_failure",
          "Threat"
        ],
        "type": "string",
        "description": "The type of alert you want to get",
        "name": "type",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of integration ID's of the alert you want to get",
        "name": "integration_id",
        "in": "query"
      },
      {
        "type": "string",
        "format": "date-time",
        "description": "The start date of the alert you want to get (in YYYY-MM-DD format)",
        "name": "from_date",
        "in": "query"
      },
      {
        "type": "string",
        "format": "date-time",
        "description": "The end date of the alert you want to get (in YYYY-MM-DD format)",
        "name": "to_date",
        "in": "query"
      },
      {
        "type": "boolean",
        "name": "ascending",
        "in": "query"
      }
    ]
  ],
  [
    "GetAppInventoryUsers",
    "GET",
    "/saas-security/entities/app-users/v3",
    "GET Application Users",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Item ID in format: 'integration_id|||app_id' (item_id)",
        "name": "item_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetAppInventory",
    "GET",
    "/saas-security/entities/apps/v3",
    "GET Applications Inventory",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Comma separated list of app types",
        "name": "type",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of objects to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The starting index of the results",
        "name": "offset",
        "in": "query"
      },
      {
        "enum": [
          "approved",
          "in review",
          "rejected",
          "unclassified"
        ],
        "type": "string",
        "description": "Comma separated list of application statuses (approved, in review, rejected, unclassified)",
        "name": "status",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of access levels",
        "name": "access_level",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of scopes",
        "name": "scopes",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Users. Format: 'is equal value' or 'contains value' or 'value' (implies 'is equal value')",
        "name": "users",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of groups",
        "name": "groups",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Last activity was within or was not within the last 'value' days. Format: 'was value' "
        "or 'was not value' or 'value' (implies 'was value'). 'value' is an integer",
        "name": "last_activity",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of integration IDs",
        "name": "integration_id",
        "in": "query"
      }
    ]
  ],
  [
    "GetSecurityCheckAffectedV3",
    "GET",
    "/saas-security/entities/check-affected/v3",
    "GET Security Check Affected",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Security Check ID",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "description": "The maximum number of objects to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The starting index of the results",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "DismissAffectedEntityV3",
    "POST",
    "/saas-security/entities/check-dismiss-affected/v3",
    "POST Dismiss Affected Entity",
    "saas_security",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      },
      {
        "type": "string",
        "description": "Security Check ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "DismissSecurityCheckV3",
    "POST",
    "/saas-security/entities/check-dismiss/v3",
    "POST Dismiss Security Check by ID",
    "saas_security",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      },
      {
        "type": "string",
        "description": "Security Check ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetSecurityChecksV3",
    "GET",
    "/saas-security/entities/checks/v3",
    "GET Security Check by ID or GET List Security Checks",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Security Check ID",
        "name": "id",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of objects to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The starting index of the results",
        "name": "offset",
        "in": "query"
      },
      {
        "enum": [
          "Passed",
          "Failed",
          "Dismissed",
          "Pending",
          "Can't Run",
          "Stale"
        ],
        "type": "string",
        "description": "Exposure status",
        "name": "status",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of integration IDs",
        "name": "integration_id",
        "in": "query"
      },
      {
        "enum": [
          "Low",
          "Medium",
          "High"
        ],
        "type": "string",
        "description": "Impact",
        "name": "impact",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Compliance",
        "name": "compliance",
        "in": "query"
      },
      {
        "enum": [
          "apps",
          "devices",
          "users",
          "assets",
          "permissions",
          "Falcon Shield Security Check",
          "custom"
        ],
        "type": "string",
        "description": "Check Type",
        "name": "check_type",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of check tags names or ids",
        "name": "check_tags",
        "in": "query"
      }
    ]
  ],
  [
    "GetSecurityCheckComplianceV3",
    "GET",
    "/saas-security/entities/compliance/v3",
    "GET Compliance",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Security Check ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "IntegrationBuilderEndTransactionV3",
    "POST",
    "/saas-security/entities/custom-integration-close/v3",
    "POST Data Upload Transaction Completion",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Integration ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "IntegrationBuilderResetV3",
    "POST",
    "/saas-security/entities/custom-integration-reset/v3",
    "Reset",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Integration ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "IntegrationBuilderGetStatusV3",
    "GET",
    "/saas-security/entities/custom-integration-status/v3",
    "GET Status",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Integration ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "IntegrationBuilderUploadV3",
    "POST",
    "/saas-security/entities/custom-integration-upload/v3",
    "POST Upload",
    "saas_security",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      },
      {
        "type": "string",
        "description": "Integration ID",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Source ID",
        "name": "source_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetAssetInventoryV3",
    "GET",
    "/saas-security/entities/data/v3",
    "GET Data Inventory",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Comma separated list of integration IDs",
        "name": "integration_id",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of objects to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The starting index of the results",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of resource types",
        "name": "resource_type",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of access levels",
        "name": "access_level",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Last accessed date was within or was not within the last 'value' days. Format: 'was "
        "value' or 'was not value' or 'value' (implies 'was value'). 'value' is an integer",
        "name": "last_accessed",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Last modified date was within or was not within the last 'value' days. Format: 'was "
        "value' or 'was not value' or 'value' (implies 'was value'). 'value' is an integer",
        "name": "last_modified",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Resource name contains 'value' (case insensitive)",
        "name": "resource_name",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Password protected",
        "name": "password_protected",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Resource owner contains 'value' (case insensitive)",
        "name": "resource_owner",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Resource owner enabled",
        "name": "resource_owner_enabled",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of unmanaged domains",
        "name": "unmanaged_domain",
        "in": "query"
      }
    ]
  ],
  [
    "GetDeviceInventoryV3",
    "GET",
    "/saas-security/entities/devices/v3",
    "GET Device Inventory",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Comma separated integration ID's",
        "name": "integration_id",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of objects to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The starting index of the results",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Email",
        "name": "email",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Privileged Only",
        "name": "privileged_only",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Unassociated Devices",
        "name": "unassociated_devices",
        "in": "query"
      }
    ]
  ],
  [
    "GetIntegrationsV3",
    "GET",
    "/saas-security/entities/integrations/v3",
    "GET Integrations",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Comma separated SaaS ID's",
        "name": "saas_id",
        "in": "query"
      }
    ]
  ],
  [
    "GetActivityMonitorV3",
    "GET",
    "/saas-security/entities/monitor/v3",
    "GET Activity Monitor",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Integration ID",
        "name": "integration_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Actor",
        "name": "actor",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of categories",
        "name": "category",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Comma separated list of projections",
        "name": "projection",
        "in": "query"
      },
      {
        "type": "string",
        "format": "date-time",
        "description": "From Date",
        "name": "from_date",
        "in": "query"
      },
      {
        "type": "string",
        "format": "date-time",
        "description": "To Date",
        "name": "to_date",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Max number of logs to fetch",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of logs to skip",
        "name": "skip",
        "in": "query"
      }
    ]
  ],
  [
    "GetSupportedSaasV3",
    "GET",
    "/saas-security/entities/supported-saas/v3",
    "GET Supported SaaS",
    "saas_security",
    []
  ],
  [
    "GetSystemLogsV3",
    "GET",
    "/saas-security/entities/system-logs/v3",
    "GET System Logs",
    "saas_security",
    [
      {
        "type": "string",
        "format": "date-time",
        "description": "From Date (in YYYY-MM-DD format)",
        "name": "from_date",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of objects to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The starting index of the results",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "format": "date-time",
        "description": "To Date (in YYYY-MM-DD format)",
        "name": "to_date",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Fetch Total Count?",
        "name": "total_count",
        "in": "query"
      }
    ]
  ],
  [
    "GetSystemUsersV3",
    "GET",
    "/saas-security/entities/system-users/v3",
    "GET System Users",
    "saas_security",
    []
  ],
  [
    "GetUserInventoryV3",
    "GET",
    "/saas-security/entities/users/v3",
    "GET User Inventory",
    "saas_security",
    [
      {
        "type": "string",
        "description": "Comma separated integration ID's",
        "name": "integration_id",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of objects to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The starting index of the results",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Email",
        "name": "email",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Privileged Only",
        "name": "privileged_only",
        "in": "query"
      }
    ]
  ]
]
