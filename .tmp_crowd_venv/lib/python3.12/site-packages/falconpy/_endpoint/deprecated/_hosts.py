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

_hosts_endpoints = [
  [
    "entities.perform_action",
    "POST",
    "/devices/entities/group-actions/v1",
    "Performs the specified action on the provided group IDs.",
    "hosts",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The group ids to act on",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "enum": [
          "add_group_member",
          "remove_all",
          "remove_group_member"
        ],
        "type": "string",
        "description": "The action to perform.",
        "name": "action_name",
        "in": "query",
        "required": True
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Bool to disable hostname check on add-member",
        "name": "disable_hostname_check",
        "in": "query"
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetOnlineState.V1",
    "GET",
    "/devices/entities/online-state/v1",
    "Get the online status for one or more hosts by specifying each host’s unique ID. Successful requests "
    "return an HTTP 200 response and the status for each host identified by a `state` of `online`, `offline`, or "
    "`unknown` for each host, identified by host `id`.\n\nUse QueryDevicesByFilterScroll to get a list of host "
    "IDs.",
    "hosts",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The unique ID of the host to get the online status of.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ]
]
