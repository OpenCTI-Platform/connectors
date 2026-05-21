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

_api_integrations_endpoints = [
  [
    "GetCombinedPluginConfigs",
    "GET",
    "/plugins/combined/configs/v1",
    "Queries for config resources and returns details",
    "api_integrations",
    [
      {
        "type": "string",
        "description": "Filter items using a query in Falcon Query Language (FQL).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 100,
        "description": "The number of items to return in this response (default: 100, max: 500). Use with the "
        "offset parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The first item to return, where 0 is the latest item. Use with the limit parameter to "
        "manage pagination of results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort items using their properties.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "ExecuteCommandProxy",
    "POST",
    "/plugins/entities/execute-proxy/v1",
    "Execute a command and proxy the response directly.",
    "api_integrations",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ExecuteCommand",
    "POST",
    "/plugins/entities/execute/v1",
    "Execute a command.",
    "api_integrations",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
