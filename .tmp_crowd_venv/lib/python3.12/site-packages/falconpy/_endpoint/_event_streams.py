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

_event_streams_endpoints = [
  [
    "refreshActiveStreamSession",
    "POST",
    "/sensors/entities/datafeed-actions/v1/{}",
    "Refresh an active event stream. Use the URL shown in a GET /sensors/entities/datafeed/v2 response.",
    "event_streams",
    [
      {
        "type": "string",
        "description": "Action name. Allowed value is refresh_active_stream_session.",
        "name": "action_name",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9).",
        "name": "appId",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "description": "Partition to request data for.",
        "name": "partition",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "listAvailableStreamsOAuth2",
    "GET",
    "/sensors/entities/datafeed/v2",
    "Discover all event streams in your environment",
    "event_streams",
    [
      {
        "type": "string",
        "description": "Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9).",
        "name": "appId",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Format for streaming events. Valid values: json, flatjson",
        "name": "format",
        "in": "query"
      }
    ]
  ]
]
