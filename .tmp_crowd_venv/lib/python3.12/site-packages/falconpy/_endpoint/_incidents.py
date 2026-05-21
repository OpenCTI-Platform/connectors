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

_incidents_endpoints = [
  [
    "CrowdScore",
    "GET",
    "/incidents/combined/crowdscores/v1",
    "Query environment wide CrowdScore and return the entity data",
    "incidents",
    [
      {
        "type": "string",
        "description": "Optional filter and sort criteria in the form of an FQL query. For more information "
        "about FQL queries, see [our FQL documentation in "
        "Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return. [1-2500]",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "adjusted_score.asc",
          "adjusted_score.desc",
          "score.asc",
          "score.desc",
          "timestamp.asc",
          "timestamp.desc"
        ],
        "type": "string",
        "description": "The property to sort on, followed by a dot (.), followed by the sort direction, either "
        "\"asc\" or \"desc\".",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "GetBehaviors",
    "POST",
    "/incidents/entities/behaviors/GET/v1",
    "Get details on behaviors by providing behavior IDs",
    "incidents",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PerformIncidentAction",
    "POST",
    "/incidents/entities/incident-actions/v1",
    "Perform a set of actions on one or more incidents, such as adding tags or comments or updating the "
    "incident name or description",
    "incidents",
    [
      {
        "type": "boolean",
        "default": False,
        "description": "If true, update assigned-to-uuid and or status of detections associated with the "
        "incident(s). Defaults to false",
        "name": "update_detects",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "If true and update-detects is true, the assigned-to-uuid or status for ALL detections "
        "associated with the incident(s) will be overwritten. If false, only detects that have default values for "
        "assigned-to-uuid and/or status will be updated. Defaults to false. Ignored if 'update-detects' is missing or "
        "false.",
        "name": "overwrite_detects",
        "in": "query"
      },
      {
        "description": "Incident Update request body containing minimum 1 and maximum 5000 Incident ID(s) and "
        "action param(s) to be performed action against.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetIncidents",
    "POST",
    "/incidents/entities/incidents/GET/v1",
    "Get details on incidents by providing incident IDs",
    "incidents",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "QueryBehaviors",
    "GET",
    "/incidents/queries/behaviors/v1",
    "Search for behaviors by providing an FQL filter, sorting, and paging details",
    "incidents",
    [
      {
        "type": "string",
        "description": "Optional filter and sort criteria in the form of an FQL query. For more information "
        "about FQL queries, see [our FQL documentation in "
        "Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return ids.",
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
          "alert_ids.asc",
          "alert_ids.desc",
          "cmdline.asc",
          "cmdline.desc",
          "detection_ids.asc",
          "detection_ids.desc",
          "display_name.asc",
          "display_name.desc",
          "domain.asc",
          "domain.desc",
          "filepath.asc",
          "filepath.desc",
          "timestamp.asc",
          "timestamp.desc"
        ],
        "type": "string",
        "description": "The property to sort on, followed by a dot (.), followed by the sort direction, either "
        "\"asc\" or \"desc\".",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "QueryIncidents",
    "GET",
    "/incidents/queries/incidents/v1",
    "Search for incidents by providing an FQL filter, sorting, and paging details",
    "incidents",
    [
      {
        "enum": [
          "assigned_to.asc",
          "assigned_to.desc",
          "assigned_to_name.asc",
          "assigned_to_name.desc",
          "end.asc",
          "end.desc",
          "modified_timestamp.asc",
          "modified_timestamp.desc",
          "name.asc",
          "name.desc",
          "sort_score.asc",
          "sort_score.desc",
          "start.asc",
          "start.desc",
          "state.asc",
          "state.desc",
          "status.asc",
          "status.desc"
        ],
        "type": "string",
        "description": "The property to sort on, followed by a dot (.), followed by the sort direction, either "
        "\"asc\" or \"desc\".",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Optional filter and sort criteria in the form of an FQL query. For more information "
        "about FQL queries, see [our FQL documentation in "
        "Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      }
    ]
  ]
]
