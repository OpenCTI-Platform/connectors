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

_fdr_endpoints = [
  [
    "fdrschema_combined_event_get",
    "GET",
    "/fdr/combined/schema-members/v1",
    "Fetch combined schema",
    "fdr",
    []
  ],
  [
    "fdrschema_entities_event_get",
    "GET",
    "/fdr/entities/schema-events/v1",
    "Fetch event schema by ID",
    "fdr",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Specify feed IDs to fetch",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "fdrschema_entities_field_get",
    "GET",
    "/fdr/entities/schema-fields/v1",
    "Fetch field schema by ID",
    "fdr",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Specify feed IDs to fetch",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "fdrschema_queries_event_get",
    "GET",
    "/fdr/queries/schema-events/v1",
    "Get list of event IDs given a particular query.",
    "fdr",
    [
      {
        "type": "integer",
        "description": "Limit of the data",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Offset into the data",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL filter of the data",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort the data",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "fdrschema_queries_field_get",
    "GET",
    "/fdr/queries/schema-fields/v1",
    "Get list of field IDs given a particular query.",
    "fdr",
    [
      {
        "type": "integer",
        "description": "Limit of the data",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Offset into the data",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL filter of the data",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort the data",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
