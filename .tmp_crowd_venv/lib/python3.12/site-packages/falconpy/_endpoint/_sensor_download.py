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

_sensor_download_endpoints = [
  [
    "GetCombinedSensorInstallersByQuery",
    "GET",
    "/sensors/combined/installers/v1",
    "Get sensor installer details by provided query",
    "sensor_download",
    [
      {
        "type": "integer",
        "description": "The first item to return, where 0 is the latest item. Use with the limit parameter to "
        "manage pagination of results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort items using their properties. Common sort options "
        "include:\n\n<ul><li>version|asc</li><li>release_date|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter items using a query in Falcon Query Language (FQL). An asterisk wildcard * "
        "includes all results.\n\nCommon filter options "
        "include:\n<ul><li>platform:\"windows\"</li><li>version:>\"5.2\"</li></ul>",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "GetCombinedSensorInstallersByQueryV2",
    "GET",
    "/sensors/combined/installers/v2",
    "Get sensor installer details by provided query",
    "sensor_download",
    [
      {
        "type": "integer",
        "description": "The first item to return, where 0 is the latest item. Use with the limit parameter to "
        "manage pagination of results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort items using their properties. Common sort options "
        "include:\n\n<ul><li>version|asc</li><li>release_date|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter items using a query in Falcon Query Language (FQL). An asterisk wildcard * "
        "includes all results.\n\nCommon filter options "
        "include:\n<ul><li>platform:\"windows\"</li><li>version:>\"5.2\"</li></ul>",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "DownloadSensorInstallerById",
    "GET",
    "/sensors/entities/download-installer/v1",
    "Download sensor installer by SHA256 ID",
    "sensor_download",
    [
      {
        "type": "string",
        "description": "SHA256 of the installer to download",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "DownloadSensorInstallerByIdV2",
    "GET",
    "/sensors/entities/download-installer/v2",
    "Download sensor installer by SHA256 ID",
    "sensor_download",
    [
      {
        "type": "string",
        "description": "SHA256 of the installer to download",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetSensorInstallersEntities",
    "GET",
    "/sensors/entities/installers/v1",
    "Get sensor installer details by provided SHA256 IDs",
    "sensor_download",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the installers",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetSensorInstallersEntitiesV2",
    "GET",
    "/sensors/entities/installers/v2",
    "Get sensor installer details by provided SHA256 IDs",
    "sensor_download",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the installers",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetSensorInstallersCCIDByQuery",
    "GET",
    "/sensors/queries/installers/ccid/v1",
    "Get CCID to use with sensor installers",
    "sensor_download",
    []
  ],
  [
    "GetSensorInstallersByQuery",
    "GET",
    "/sensors/queries/installers/v1",
    "Get sensor installer IDs by provided query",
    "sensor_download",
    [
      {
        "type": "integer",
        "description": "The first item to return, where 0 is the latest item. Use with the limit parameter to "
        "manage pagination of results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort items using their properties. Common sort options "
        "include:\n\n<ul><li>version|asc</li><li>release_date|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter items using a query in Falcon Query Language (FQL). An asterisk wildcard * "
        "includes all results.\n\nCommon filter options "
        "include:\n<ul><li>platform:\"windows\"</li><li>version:>\"5.2\"</li></ul>",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "GetSensorInstallersByQueryV2",
    "GET",
    "/sensors/queries/installers/v2",
    "Get sensor installer IDs by provided query",
    "sensor_download",
    [
      {
        "type": "integer",
        "description": "The first item to return, where 0 is the latest item. Use with the limit parameter to "
        "manage pagination of results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort items using their properties. Common sort options "
        "include:\n\n<ul><li>version|asc</li><li>release_date|desc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter items using a query in Falcon Query Language (FQL). An asterisk wildcard * "
        "includes all results.\n\nCommon filter options "
        "include:\n<ul><li>platform:\"windows\"</li><li>version:>\"5.2\"</li></ul>",
        "name": "filter",
        "in": "query"
      }
    ]
  ]
]
