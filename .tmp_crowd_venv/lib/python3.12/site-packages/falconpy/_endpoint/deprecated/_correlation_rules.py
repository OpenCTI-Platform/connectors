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

_correlation_rules_endpoints = [
  [
    "aggregates.rule-versions.post.v1",
    "POST",
    "/correlation-rules/aggregates/rule-versions/v1",
    "Get rules aggregates as specified via json in the request body.",
    "correlation_rules",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "combined.rules.get.v1",
    "GET",
    "/correlation-rules/combined/rules/v1",
    "Find all rules matching the query and filter.\nSupported filters: "
    "customer_id,user_id,user_uuid,status,name,created_on,last_updated_on\nSupported range filters: "
    "created_on,last_updated_on",
    "correlation_rules",
    [
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters",
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
        "enum": [
          "created_on",
          "created_on|desc",
          "last_updated_on",
          "last_updated_on|desc"
        ],
        "type": "string",
        "default": "created_on",
        "description": "Rule property to sort on",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return IDs",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "Number of IDs to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "combined.rules.get.v2",
    "GET",
    "/correlation-rules/combined/rules/v2",
    "Find all rules matching the query and filter.\nSupported filters: "
    "customer_id,user_id,user_uuid,status,name,created_on,last_updated_on\nSupported range filters: "
    "created_on,last_updated_on",
    "correlation_rules",
    [
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters",
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
        "enum": [
          "created_on",
          "created_on|desc",
          "last_updated_on",
          "last_updated_on|desc"
        ],
        "type": "string",
        "default": "created_on",
        "description": "Rule property to sort on",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return IDs",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "Number of IDs to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "entities.latest-rules.get.v1",
    "GET",
    "/correlation-rules/entities/latest-rules/v1",
    "Retrieve latest rule versions by rule IDs",
    "correlation_rules",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The rule IDs",
        "name": "rule_ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities.rule-versions_export.post.v1",
    "POST",
    "/correlation-rules/entities/rule-versions/export/v1",
    "Export rule versions",
    "correlation_rules",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities.rule-versions_import.post.v1",
    "POST",
    "/correlation-rules/entities/rule-versions/import/v1",
    "Import rule versions",
    "correlation_rules",
    []
  ],
  [
    "entities.rule-versions_publish.patch.v1",
    "PATCH",
    "/correlation-rules/entities/rule-versions/publish/v1",
    "Publish existing rule version",
    "correlation_rules",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities.rule-versions.delete.v1",
    "DELETE",
    "/correlation-rules/entities/rule-versions/v1",
    "Delete versions by IDs",
    "correlation_rules",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities.rules.get.v1",
    "GET",
    "/correlation-rules/entities/rules/v1",
    "Retrieve rules by IDs",
    "correlation_rules",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities.rules.post.v1",
    "POST",
    "/correlation-rules/entities/rules/v1",
    "Create rule",
    "correlation_rules",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities.rules.patch.v1",
    "PATCH",
    "/correlation-rules/entities/rules/v1",
    "Update rules",
    "correlation_rules",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "entities.rules.delete.v1",
    "DELETE",
    "/correlation-rules/entities/rules/v1",
    "Delete rules by IDs",
    "correlation_rules",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "entities.rules.get.v2",
    "GET",
    "/correlation-rules/entities/rules/v2",
    "Retrieve rule versions by IDs",
    "correlation_rules",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queries.rules.get.v1",
    "GET",
    "/correlation-rules/queries/rules/v1",
    "Find all rule IDs matching the query and filter.\nSupported filters: "
    "customer_id,user_id,user_uuid,status,name,created_on,last_updated_on\nSupported range filters: "
    "created_on,last_updated_on",
    "correlation_rules",
    [
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters",
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
        "enum": [
          "created_on",
          "created_on|desc",
          "last_updated_on",
          "last_updated_on|desc"
        ],
        "type": "string",
        "default": "created_on",
        "description": "Rule property to sort on",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return IDs",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "Number of IDs to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "queries.rules.get.v2",
    "GET",
    "/correlation-rules/queries/rules/v2",
    "Find all rule version IDs matching the query and filter.\nSupported filters: "
    "customer_id,user_id,user_uuid,status,name,created_on,last_updated_on,state,version,rule_id\nSupported range "
    "filters: created_on,last_updated_on",
    "correlation_rules",
    [
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters",
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
        "enum": [
          "created_on",
          "created_on|desc",
          "last_updated_on",
          "last_updated_on|desc"
        ],
        "type": "string",
        "default": "created_on",
        "description": "Rule property to sort on",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return IDs",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "Number of IDs to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ]
]
