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

_deployments_endpoints = [
  [
    "CombinedReleaseNotesV1",
    "GET",
    "/deployment-coordinator/combined/release-notes/v1",
    "Queries for release-notes resources and returns details",
    "deployments",
    [
      {
        "type": "string",
        "description": "authorization header",
        "name": "Authorization",
        "in": "header",
        "required": True
      },
      {
        "type": "string",
        "description": "FQL query specifying filter parameters.",
        "name": "filter",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maximum": 500,
        "type": "integer",
        "description": "Maximum number of records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "string",
        "description": "Starting pagination offset of records to return.",
        "name": "offset",
        "in": "query"
      },
      {
        "pattern": "^\\w+(\\.asc|\\.desc)?(,\\w+(\\.asc|\\.desc)?)*$",
        "type": "string",
        "description": "Sort items by providing a comma separated list of property and direction (eg "
        "name.desc,time.asc). If direction is omitted, defaults to descending.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "CombinedReleasesV1Mixin0",
    "GET",
    "/deployment-coordinator/combined/releases/v1",
    "Queries for releases resources and returns details",
    "deployments",
    [
      {
        "type": "string",
        "description": "authorization header",
        "name": "Authorization",
        "in": "header",
        "required": True
      },
      {
        "type": "string",
        "description": "FQL query specifying filter parameters.",
        "name": "filter",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maximum": 500,
        "type": "integer",
        "description": "Maximum number of records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "string",
        "description": "Starting pagination offset of records to return.",
        "name": "offset",
        "in": "query"
      },
      {
        "pattern": "^\\w+(\\.asc|\\.desc)?(,\\w+(\\.asc|\\.desc)?)*$",
        "type": "string",
        "description": "Sort items by providing a comma separated list of property and direction (eg "
        "name.desc,time.asc). If direction is omitted, defaults to descending.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "GetDeploymentsExternalV1",
    "GET",
    "/deployment-coordinator/entities/deployments/external/v1",
    "Get deployment resources by ids",
    "deployments",
    [
      {
        "type": "string",
        "description": "authorization header",
        "name": "Authorization",
        "in": "header",
        "required": True
      },
      {
        "minItems": 1,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "release version ids to retrieve deployment details",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetEntityIDsByQueryPOST",
    "POST",
    "/deployment-coordinator/entities/release-notes/GET/v1",
    "returns the release notes for the IDs in the request",
    "deployments",
    [
      {
        "type": "string",
        "description": "authorization header",
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
    "GetEntityIDsByQueryPOSTV2",
    "POST",
    "/deployment-coordinator/entities/release-notes/GET/v2",
    "returns the release notes for the IDs in the request with EA and GA dates in ISO 8601 format",
    "deployments",
    [
      {
        "type": "string",
        "description": "authorization header",
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
    "QueryReleaseNotesV1",
    "GET",
    "/deployment-coordinator/queries/release-notes/v1",
    "Queries for release-notes resources and returns ids",
    "deployments",
    [
      {
        "type": "string",
        "description": "authorization header",
        "name": "Authorization",
        "in": "header",
        "required": True
      },
      {
        "type": "string",
        "description": "FQL query specifying filter parameters.",
        "name": "filter",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maximum": 500,
        "type": "integer",
        "description": "Maximum number of records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "string",
        "description": "Starting pagination offset of records to return.",
        "name": "offset",
        "in": "query"
      },
      {
        "pattern": "^\\w+(\\.asc|\\.desc)?(,\\w+(\\.asc|\\.desc)?)*$",
        "type": "string",
        "description": "Sort items by providing a comma separated list of property and direction (eg "
        "name.desc,time.asc). If direction is omitted, defaults to descending.",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
