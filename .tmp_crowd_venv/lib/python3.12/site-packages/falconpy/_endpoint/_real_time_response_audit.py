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

_real_time_response_audit_endpoints = [
  [
    "RTRAuditSessions",
    "GET",
    "/real-time-response-audit/combined/sessions/v1",
    "Get all the RTR sessions created for a customer in a specified duration",
    "real_time_response_audit",
    [
      {
        "type": "string",
        "description": "Optional filter criteria in the form of an FQL query. For more information about FQL "
        "queries, see our [FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-"
        "query-language-feature-guide).",
        "name": "filter",
        "in": "query"
      },
      {
        "enum": [
          "created_at",
          "updated_at",
          "deleted_at"
        ],
        "type": "string",
        "description": "how to sort the session IDs. e.g. sort=created_at|desc will sort the results based on "
        "createdAt in descending order",
        "name": "sort",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "string",
        "description": "number of sessions to be returned",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "offset value to be used for paginated results",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "get sessions with command info included; by default sessions are returned without "
        "command info which include cloud_request_ids and logs fields",
        "name": "with_command_info",
        "in": "query"
      }
    ]
  ]
]
