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

_ml_exclusions_endpoints = [
  [
    "getMLExclusionsV1",
    "GET",
    "/policy/entities/ml-exclusions/v1",
    "Get a set of ML Exclusions by specifying their IDs",
    "ml_exclusions",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The ids of the exclusions to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createMLExclusionsV1",
    "POST",
    "/policy/entities/ml-exclusions/v1",
    "Create the ML exclusions",
    "ml_exclusions",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updateMLExclusionsV1",
    "PATCH",
    "/policy/entities/ml-exclusions/v1",
    "Update the ML exclusions",
    "ml_exclusions",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteMLExclusionsV1",
    "DELETE",
    "/policy/entities/ml-exclusions/v1",
    "Delete the ML exclusions by id",
    "ml_exclusions",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The ids of the exclusions to delete",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Explains why this exclusions was deleted",
        "name": "comment",
        "in": "query"
      }
    ]
  ],
  [
    "queryMLExclusionsV1",
    "GET",
    "/policy/queries/ml-exclusions/v1",
    "Search for ML exclusions.",
    "ml_exclusions",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "applied_globally.asc",
          "applied_globally.desc",
          "created_by.asc",
          "created_by.desc",
          "created_on.asc",
          "created_on.desc",
          "last_modified.asc",
          "last_modified.desc",
          "modified_by.asc",
          "modified_by.desc",
          "value.asc",
          "value.desc"
        ],
        "type": "string",
        "description": "The sort expression that should be used to sort the results.",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
