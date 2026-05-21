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

_identity_protection_endpoints = [
  [
    "api.preempt.proxy.post.graphql",
    "POST",
    "/identity-protection/combined/graphql/v1",
    "Identity Protection GraphQL API. Allows to retrieve entities, timeline activities, identity-based "
    "incidents and security assessment. Allows to perform actions on entities and identity-based incidents.",
    "identity_protection",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "api.preempt.proxy.get.policy-rules",
    "GET",
    "/identity-protection/entities/policy-rules/v1",
    "Get policy rules",
    "identity_protection",
    [
      {
        "maxItems": 100,
        "minItems": 1,
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Rule IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "api.preempt.proxy.post.policy-rules",
    "POST",
    "/identity-protection/entities/policy-rules/v1",
    "Create policy rule",
    "identity_protection",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "api.preempt.proxy.delete.policy-rules",
    "DELETE",
    "/identity-protection/entities/policy-rules/v1",
    "Delete policy rules",
    "identity_protection",
    [
      {
        "maxItems": 100,
        "minItems": 1,
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Rule IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "api.preempt.proxy.get.policy-rules.query",
    "GET",
    "/identity-protection/queries/policy-rules/v1",
    "Query policy rule IDs",
    "identity_protection",
    [
      {
        "type": "boolean",
        "description": "Whether the rule is enabled",
        "name": "enabled",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Whether the rule is in simulation mode",
        "name": "simulation_mode",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Rule name",
        "name": "name",
        "in": "query"
      }
    ]
  ],
  [
    "api_preempt_proxy_post_graphql",
    "POST",
    "/identity-protection/combined/graphql/v1",
    "Identity Protection GraphQL API. Allows to retrieve entities, timeline activities, identity-based "
    "incidents and security assessment. Allows to perform actions on entities and identity-based incidents.",
    "identity_protection",
    [
      {
        "type": "string",
        "description": "Authorization Header",
        "name": "Authorization",
        "in": "header",
        "required": True
      }
    ]
  ],
  [
    "api_preempt_proxy_get_policy_rules",
    "GET",
    "/identity-protection/entities/policy-rules/v1",
    "Get policy rules",
    "identity_protection",
    [
      {
        "type": "string",
        "description": "Authorization Header",
        "name": "Authorization",
        "in": "header",
        "required": True
      },
      {
        "maxItems": 100,
        "minItems": 1,
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Rule IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "api_preempt_proxy_post_policy_rules",
    "POST",
    "/identity-protection/entities/policy-rules/v1",
    "Create policy rule",
    "identity_protection",
    [
      {
        "type": "string",
        "description": "Authorization Header",
        "name": "Authorization",
        "in": "header",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "api_preempt_proxy_delete_policy_rules",
    "DELETE",
    "/identity-protection/entities/policy-rules/v1",
    "Delete policy rules",
    "identity_protection",
    [
      {
        "type": "string",
        "description": "Authorization Header",
        "name": "Authorization",
        "in": "header",
        "required": True
      },
      {
        "maxItems": 100,
        "minItems": 1,
        "uniqueItems": True,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Rule IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "api_preempt_proxy_get_policy_rules_query",
    "GET",
    "/identity-protection/queries/policy-rules/v1",
    "Query policy rule IDs",
    "identity_protection",
    [
      {
        "type": "string",
        "description": "Authorization Header",
        "name": "Authorization",
        "in": "header",
        "required": True
      },
      {
        "type": "boolean",
        "description": "Whether the rule is enabled",
        "name": "enabled",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "Whether the rule is in simulation mode",
        "name": "simulation_mode",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Rule name",
        "name": "name",
        "in": "query"
      }
    ]
  ]
]
