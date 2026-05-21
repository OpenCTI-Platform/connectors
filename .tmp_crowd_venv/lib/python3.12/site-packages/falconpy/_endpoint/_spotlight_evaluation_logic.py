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

_spotlight_evaluation_logic_endpoints = [
  [
    "combinedQueryEvaluationLogic",
    "GET",
    "/spotlight/combined/evaluation-logic/v1",
    "Search for evaluation logic in your environment by providing a FQL filter and paging details. Returns a "
    "set of evaluation logic entities which match the filter criteria.",
    "spotlight_evaluation_logic",
    [
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
        "description": "Maximum number of entities to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters.",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Sort evaluation logic by their properties.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "getEvaluationLogic",
    "GET",
    "/spotlight/entities/evaluation-logic/v1",
    "Get details on evaluation logic items by providing one or more IDs.",
    "spotlight_evaluation_logic",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more evaluation logic IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queryEvaluationLogic",
    "GET",
    "/spotlight/queries/evaluation-logic/v1",
    "Search for evaluation logic in your environment by providing a FQL filter and paging details. Returns a "
    "set of evaluation logic IDs which match the filter criteria.",
    "spotlight_evaluation_logic",
    [
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
        "description": "Maximum number of entities to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters.",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Sort evaluation logic by their properties.",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
