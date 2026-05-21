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

_quarantine_endpoints = [
  [
    "ActionUpdateCount",
    "GET",
    "/quarantine/aggregates/action-update-count/v1",
    "Returns count of potentially affected quarantined files for each action.",
    "quarantine",
    [
      {
        "type": "string",
        "description": "FQL specifying filter parameters.",
        "name": "filter",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetAggregateFiles",
    "POST",
    "/quarantine/aggregates/quarantined-files/GET/v1",
    "Get quarantine file aggregates as specified via json in request body.",
    "quarantine",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetQuarantineFiles",
    "POST",
    "/quarantine/entities/quarantined-files/GET/v1",
    "Get quarantine file metadata for specified ids.",
    "quarantine",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateQuarantinedDetectsByIds",
    "PATCH",
    "/quarantine/entities/quarantined-files/v1",
    "Apply action by quarantine file ids",
    "quarantine",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "QueryQuarantineFiles",
    "GET",
    "/quarantine/queries/quarantined-files/v1",
    "Get quarantine file ids that match the provided filter criteria.",
    "quarantine",
    [
      {
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of ids to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Possible order by fields: hostname, username, date_updated, date_created, paths.path, "
        "state, paths.state. Ex: 'date_created|asc'.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Special value '*' means to not filter on "
        "anything. Filter term criteria: status, adversary_id, device.device_id, device.country, device.hostname, "
        "behaviors.behavior_id, behaviors.ioc_type, behaviors.ioc_value, behaviors.username, behaviors.tree_root_hash. "
        "Filter range criteria:, max_severity, max_confidence, first_behavior, last_behavior.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match phrase_prefix query criteria; included fields: _all (all filter string fields), "
        "sha256, state, paths.path, paths.state, hostname, username, date_updated, date_created.",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "UpdateQfByQuery",
    "PATCH",
    "/quarantine/queries/quarantined-files/v1",
    "Apply quarantine file actions by query.",
    "quarantine",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
