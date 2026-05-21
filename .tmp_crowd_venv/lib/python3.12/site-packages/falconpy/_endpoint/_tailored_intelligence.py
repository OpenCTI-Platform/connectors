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

_tailored_intelligence_endpoints = [
  [
    "GetEventsBody",
    "GET",
    "/ti/events/entities/events-full-body/v2",
    "Get event body for the provided event ID",
    "tailored_intelligence",
    [
      {
        "type": "string",
        "description": "Return the event body for event id.",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetEventsEntities",
    "POST",
    "/ti/events/entities/events/GET/v2",
    "Get events entities for specified ids.",
    "tailored_intelligence",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "QueryEvents",
    "GET",
    "/ti/events/queries/events/v2",
    "Get events ids that match the provided filter criteria.",
    "tailored_intelligence",
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
      },
      {
        "type": "string",
        "description": "Possible order by fields: source_type, created_date, updated_date. Ex: 'updated_date|desc'.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Special value '*' means to not filter on anything.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match phrase_prefix query criteria; included fields: _all (all filter string fields indexed).",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "GetRulesEntities",
    "POST",
    "/ti/rules/entities/rules/GET/v2",
    "Get rules entities for specified ids.",
    "tailored_intelligence",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "QueryRules",
    "GET",
    "/ti/rules/queries/rules/v2",
    "Get rules ids that match the provided filter criteria.",
    "tailored_intelligence",
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
      },
      {
        "type": "string",
        "description": "Possible order by fields: name, value, rule_type, customer_id, created_date, "
        "updated_date. Ex: 'updated_date|asc'.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Special value '*' means to not filter on anything.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match phrase_prefix query criteria; included fields: _all (all filter string fields indexed).",
        "name": "q",
        "in": "query"
      }
    ]
  ]
]
