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

_firewall_management_endpoints = [
  [
    "aggregate-events",
    "POST",
    "/fwmgr/aggregates/events/GET/v1",
    "Aggregate events for customer",
    "firewall_management",
    [
      {
        "description": "Query criteria and settings",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "aggregate-policy-rules",
    "POST",
    "/fwmgr/aggregates/policy-rules/GET/v1",
    "Aggregate rules within a policy for customer",
    "firewall_management",
    [
      {
        "description": "Query criteria and settings",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "aggregate-rule-groups",
    "POST",
    "/fwmgr/aggregates/rule-groups/GET/v1",
    "Aggregate rule groups for customer",
    "firewall_management",
    [
      {
        "description": "Query criteria and settings",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "aggregate-rules",
    "POST",
    "/fwmgr/aggregates/rules/GET/v1",
    "Aggregate rules for customer",
    "firewall_management",
    [
      {
        "description": "Query criteria and settings",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "get-events",
    "GET",
    "/fwmgr/entities/events/v1",
    "Get events entities by ID and optionally version",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The events to retrieve, identified by ID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "get-firewall-fields",
    "GET",
    "/fwmgr/entities/firewall-fields/v1",
    "Get the firewall field specifications by ID",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the rule types to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "get-network-locations-details",
    "GET",
    "/fwmgr/entities/network-locations-details/v1",
    "Get network locations entities by ID",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The events to retrieve, identified by ID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "update-network-locations-metadata",
    "POST",
    "/fwmgr/entities/network-locations-metadata/v1",
    "Updates the network locations metadata such as polling_intervals for the cid",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
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
    "update-network-locations-precedence",
    "POST",
    "/fwmgr/entities/network-locations-precedence/v1",
    "Updates the network locations precedence according to the list of ids provided.",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
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
    "get-network-locations",
    "GET",
    "/fwmgr/entities/network-locations/v1",
    "Get a summary of network locations entities by ID",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The events to retrieve, identified by ID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "upsert-network-locations",
    "PUT",
    "/fwmgr/entities/network-locations/v1",
    "Updates the network locations provided, and return the ID.",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
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
    "create-network-locations",
    "POST",
    "/fwmgr/entities/network-locations/v1",
    "Create new network locations provided, and return the ID.",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "A network location ID from which to copy location. If this is provided then the body "
        "of the request is ignored.",
        "name": "clone_id",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "A boolean to determine whether the cloned location needs to be added to the same "
        "firewall rules that original location is added to.",
        "name": "add_fw_rules",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
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
    "update-network-locations",
    "PATCH",
    "/fwmgr/entities/network-locations/v1",
    "Updates the network locations provided, and return the ID.",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
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
    "delete-network-locations",
    "DELETE",
    "/fwmgr/entities/network-locations/v1",
    "Delete network location entities by ID.",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the network locations to be deleted",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "get-platforms",
    "GET",
    "/fwmgr/entities/platforms/v1",
    "Get platforms by ID, e.g., windows or mac or droid",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the platforms to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "get-policy-containers",
    "GET",
    "/fwmgr/entities/policies/v1",
    "Get policy container entities by policy ID",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The policy container(s) to retrieve, identified by policy ID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "update-policy-container-v1",
    "PUT",
    "/fwmgr/entities/policies/v1",
    "Update an identified policy container. WARNING: This endpoint is deprecated in favor of v2, using this "
    "endpoint could disable your local logging setting.",
    "firewall_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "update-policy-container",
    "PUT",
    "/fwmgr/entities/policies/v2",
    "Update an identified policy container, including local logging functionality.",
    "firewall_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "get-rule-groups",
    "GET",
    "/fwmgr/entities/rule-groups/v1",
    "Get rule group entities by ID. These groups do not contain their rule entites, just the rule IDs in precedence order.",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the rule groups to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "create-rule-group",
    "POST",
    "/fwmgr/entities/rule-groups/v1",
    "Create new rule group on a platform for a customer with a name and description, and return the ID",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "A rule group ID from which to copy rules. If this is provided then the 'rules' "
        "property of the body is ignored.",
        "name": "clone_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "If this flag is set to true then the rules will be cloned from the clone_id from the "
        "CrowdStrike Firewal Rule Groups Library.",
        "name": "library",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
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
    "update-rule-group",
    "PATCH",
    "/fwmgr/entities/rule-groups/v1",
    "Update name, description, or enabled status of a rule group, or create, edit, delete, or reorder rules",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
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
    "delete-rule-groups",
    "DELETE",
    "/fwmgr/entities/rule-groups/v1",
    "Delete rule group entities by ID",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the rule groups to be deleted",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
        "in": "query"
      }
    ]
  ],
  [
    "create-rule-group-validation",
    "POST",
    "/fwmgr/entities/rule-groups/validation/v1",
    "Validates the request of creating a new rule group on a platform for a customer with a name and description",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "A rule group ID from which to copy rules. If this is provided then the 'rules' "
        "property of the body is ignored.",
        "name": "clone_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "If this flag is set to true then the rules will be cloned from the clone_id from the "
        "CrowdStrike Firewall Rule Groups Library.",
        "name": "library",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
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
    "update-rule-group-validation",
    "PATCH",
    "/fwmgr/entities/rule-groups/validation/v1",
    "Validates the request of updating name, description, or enabled status of a rule group, or create, edit, "
    "delete, or reorder rules",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Audit log comment for this action",
        "name": "comment",
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
    "get-rules",
    "GET",
    "/fwmgr/entities/rules/v1",
    "Get rule entities by ID (64-bit unsigned int as decimal string) or Family ID (32-character hexadecimal string)",
    "firewall_management",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The rules to retrieve, identified by ID",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "validate-filepath-pattern",
    "POST",
    "/fwmgr/entities/rules/validate-filepath/v1",
    "Validates that the test pattern matches the executable filepath glob pattern.",
    "firewall_management",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "query-events",
    "GET",
    "/fwmgr/queries/events/v1",
    "Find all event IDs matching the query with filter",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Possible order by fields: ",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Filter term criteria: enabled, platform, "
        "name, description, etc TODO. Filter range criteria: created_on, modified_on; use any common date format, such "
        "as '2010-05-15T14:55:21.892315096Z'.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match query criteria, which includes all the filter string fields, plus TODO",
        "name": "q",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
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
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "query-firewall-fields",
    "GET",
    "/fwmgr/queries/firewall-fields/v1",
    "Get the firewall field specification IDs for the provided platform",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Get fields configuration for this platform",
        "name": "platform_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "query-network-locations",
    "GET",
    "/fwmgr/queries/network-locations/v1",
    "Get a list of network location IDs",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Possible order by fields: ",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Filter term criteria: name",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match query criteria, which includes all the filter string fields",
        "name": "q",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
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
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "query-platforms",
    "GET",
    "/fwmgr/queries/platforms/v1",
    "Get the list of platform names",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "query-policy-rules",
    "GET",
    "/fwmgr/queries/policy-rules/v1",
    "Find all firewall rule IDs matching the query with filter, and return them in precedence order",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "The ID of the policy container within which to query",
        "name": "id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Possible order by fields: ",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Filter term criteria: enabled, platform, "
        "name, description, etc TODO. Filter range criteria: created_on, modified_on; use any common date format, such "
        "as '2010-05-15T14:55:21.892315096Z'.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match query criteria, which includes all the filter string fields, plus TODO",
        "name": "q",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "query-rule-groups",
    "GET",
    "/fwmgr/queries/rule-groups/v1",
    "Find all rule group IDs matching the query with filter",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Possible order by fields: ",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Filter term criteria: enabled, platform, "
        "name, description, etc TODO. Filter range criteria: created_on, modified_on; use any common date format, such "
        "as '2010-05-15T14:55:21.892315096Z'.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match query criteria, which includes all the filter string fields, plus TODO",
        "name": "q",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
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
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "query-rules",
    "GET",
    "/fwmgr/queries/rules/v1",
    "Find all rule IDs matching the query with filter",
    "firewall_management",
    [
      {
        "type": "string",
        "description": "Possible order by fields: ",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Filter term criteria: enabled, platform, "
        "name, description, etc TODO. Filter range criteria: created_on, modified_on; use any common date format, such "
        "as '2010-05-15T14:55:21.892315096Z'.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match query criteria, which includes all the filter string fields, plus TODO",
        "name": "q",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
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
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      }
    ]
  ]
]
