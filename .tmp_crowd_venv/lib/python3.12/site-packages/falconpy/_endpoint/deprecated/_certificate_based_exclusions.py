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

_certificate_based_exclusions_endpoints = [
  [
    "cb-exclusions.get.v1",
    "GET",
    "/exclusions/entities/cert-based-exclusions/v1",
    "Find all exclusion IDs matching the query with filter",
    "certificate_based_exclusions",
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
    "cb-exclusions.create.v1",
    "POST",
    "/exclusions/entities/cert-based-exclusions/v1",
    "Create new Certificate Based Exclusions.",
    "certificate_based_exclusions",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cb-exclusions.update.v1",
    "PATCH",
    "/exclusions/entities/cert-based-exclusions/v1",
    "Updates existing Certificate Based Exclusions",
    "certificate_based_exclusions",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "cb-exclusions.delete.v1",
    "DELETE",
    "/exclusions/entities/cert-based-exclusions/v1",
    "Delete the exclusions by id",
    "certificate_based_exclusions",
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
        "description": "The comment why these exclusions were deleted",
        "name": "comment",
        "in": "query"
      }
    ]
  ],
  [
    "certificates.get.v1",
    "GET",
    "/exclusions/entities/certificates/v1",
    "Retrieves certificate signing information for a file",
    "certificate_based_exclusions",
    [
      {
        "type": "string",
        "description": "The SHA256 Hash of the file to retrieve certificate signing info for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "cb-exclusions.query.v1",
    "GET",
    "/exclusions/queries/cert-based-exclusions/v1",
    "Search for cert-based exclusions.",
    "certificate_based_exclusions",
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
        "maximum": 100,
        "type": "integer",
        "description": "The maximum records to return. [1-100]",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "created_by",
          "created_on",
          "modified_by",
          "modified_on",
          "name"
        ],
        "type": "string",
        "description": "The sort expression that should be used to sort the results.",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
