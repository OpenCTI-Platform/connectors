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

_alerts_endpoints = [
  [
    "PostAggregatesAlertsV1",
    "POST",
    "/alerts/aggregates/alerts/v1",
    "Deprecated: Please use version v2 of this endpoint. Retrieves aggregate values for Alerts across all CIDs.",
    "alerts",
    [
      {
        "description": "request body takes a list of aggregate-alert query requests",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PostAggregatesAlertsV2",
    "POST",
    "/alerts/aggregates/alerts/v2",
    "Retrieves aggregate values for Alerts across all CIDs.",
    "alerts",
    [
      {
        "type": "boolean",
        "default": True,
        "description": "allows previously hidden alerts to be retrieved",
        "name": "include_hidden",
        "in": "query"
      },
      {
        "description": "request body takes a list of aggregate-alert query requests",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PostCombinedAlertsV1",
    "POST",
    "/alerts/combined/alerts/v1",
    "Retrieves all Alerts that match a particular FQL filter.\nThis API is intended for retrieval of large "
    "amounts of Alerts(>10k) using a pagination based on a `after` token.\nIf you need to use `offset` pagination, "
    "consider using GET /alerts/queries/alerts/* and POST /alerts/entities/alerts/* APIs.\n\n",
    "alerts",
    [
      {
        "description": "after  The after token is used for pagination of results.\nThe after token is present "
        "when more results are available on the next page.\nTo retrieve all Alerts: \n  - Use the after token in "
        "subsequent requests to fetch the next page.\n  - Continue this process until you reach a page without an after "
        " token, indicating the last page.\n\nThis value is highly dependant on the sort parameter, so if you plan to "
        "change the sort order, you will have to re-start your search from the first page (without after "
        "parameter).\n\nfilter  Filter Alerts using a query in Falcon Query Language (FQL).Filter fields can be any "
        "keyword field that is part of #domain.Alert \nAn asterisk wildcard * includes all results.  \nEmpty value "
        "means to not filter on anything.\nMost commonly used filter fields that supports exact match: cid, id, "
        "aggregate_id, product, type, pattern_id, platform ...\nMost commonly used filter fields that supports wildcard "
        " (*): assigned_to_name, assigned_to_uuid, tactic_id, technique ...\nMost commonly filter fields that supports "
        "range comparisons (>, <, >=, <=): severity, created_timestamp, timestamp, updated_timestamp...\nAll filter "
        "fields and operations support negation (!).\n\n\nThe full list of valid filter options is extensive. Review it "
        " in our [documentation inside the Falcon console](https://falcon.crowdstrike.com/documentation/45/falcon-"
        "query-language-fql).\n\nlimit  The maximum number of detections to return in this response (default: 100; max: "
        " 1000). Use this parameter together with the after parameter to manage pagination of the results.\n\nsort  "
        "Sort parameter takes the form of <field|direction>. \n\nThe sorting fields can be any keyword field that is "
        "part of #domain.Alert except for the text based fields. Most commonly used fields for sorting are: timestamp, "
        "created_timestamp, updated_timestamp, status, aggregate_id, assigned_to_name, assigned_to_uid, "
        "assigned_to_uuid, tactic_id, tactic, technique, technique_id, pattern_id or product.\n\nBy default all the "
        "results are sorted by the created_timestamp field in the descending order.\n\n**Important:** The pagination is "
        " done on live data in the order defined by the sort field parameter (default: created_timestamp|desc), so if "
        "you want to avoid inconsistent results where the same record might appear on multiple pages (or none), sort "
        "only on the fields that do not change over time (e.g. created_timestamp, composite_id, ...).\n\n",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PostEntitiesAlertsV1",
    "POST",
    "/alerts/entities/alerts/v1",
    "Deprecated: please use version v2 of this endpoint. Retrieves all Alerts given their ids.",
    "alerts",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PatchEntitiesAlertsV1",
    "PATCH",
    "/alerts/entities/alerts/v1",
    "Perform actions on detections identified by detection ID(s) in request.\nEach action has a name and a "
    "description which describes what the action does.\n\nremove_tag - remove a tag from 1 or more "
    "detection(s)\nassign_to_user_id - assign 1 or more detection(s) to a user identified by user id (eg: "
    "user1@example.com)\nunassign - unassign an previously assigned user from 1 or more detection(s). The value "
    "passed to this action is ignored.\nnew_behavior_processed - adds a newly processed behavior to 1 or more "
    "detection(s)\nupdate_status - update status for 1 or more detection(s)\nassign_to_uuid - assign 1 or more "
    "detection(s) to a user identified by UUID\nadd_tag - add a tag to 1 or more "
    "detection(s)\nremove_tags_by_prefix - remove tags with given prefix from 1 or more "
    "detection(s)\nappend_comment - appends new comment to existing comments\nassign_to_name - assign 1 or more "
    "detection(s) to a user identified by user name\nshow_in_ui - shows 1 or more detection(s) on UI if set to "
    "true, hides otherwise. an empty/nil value is also valid\nskip_side_effects - internal only command to skip "
    "side effects during Beta phase\n",
    "alerts",
    [
      {
        "description": "request body takes a list of action parameter request that is applied against all \"ids\" provided",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PostEntitiesAlertsV2",
    "POST",
    "/alerts/entities/alerts/v2",
    "Retrieves all Alerts given their composite ids.",
    "alerts",
    [
      {
        "type": "boolean",
        "default": True,
        "description": "allows previously hidden alerts to be retrieved",
        "name": "include_hidden",
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
    "PatchEntitiesAlertsV2",
    "PATCH",
    "/alerts/entities/alerts/v2",
    "Deprecated: Please use version v3 of this endpoint.\nPerform actions on Alerts identified by composite "
    "ID(s) in request.\nEach action has a name and a description which describes what the action does.\nIf a "
    "request adds and removes tag in a single request, the order of processing would be to remove tags before "
    "adding new ones in.\n\n",
    "alerts",
    [
      {
        "description": "ids  IDs of Alerts to modify.\n\naction_parameters values  assign_to_uuid\n\t- Assign "
        "Alert to user UUID, such as 00000000-0000-0000-0000-000000000000  assign_to_user_id\n\t- Assign Alert to user "
        "ID, such as user@example.com  assign_to_name\n\t- Assign Alert to username, such as John Doe  unassign\n\t- "
        "Unassign Alert clears out the assigned user UUID, user ID, and username.  add_tag\n \t- Add a tag to the "
        "Alert.  remove_tag\n\t- Remove a tag from the Alert.  remove_tags_by_prefix\n\t- Remove tags from the Alert "
        "based on the prefix.  append_comment\n\t- Comments are displayed with the Alert in Falcon and are usually used "
        " to provide context or notes for other Falcon users. An Alert can have multiple comments over time.  "
        "update_status values\n\t- new\n\t- in_progress\n\t- reopened\n\t- closed  show_in_ui values\n\t- true: This "
        "alert is displayed in Falcon\n\t- false: This alert is not displayed in Falcon.\n",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PatchEntitiesAlertsV3",
    "PATCH",
    "/alerts/entities/alerts/v3",
    "Perform actions on Alerts identified by composite ID(s) in request.\nEach action has a name and a "
    "description which describes what the action does.\nIf a request adds and removes tag in a single request, the "
    "order of processing would be to remove tags before adding new ones in.\n\n",
    "alerts",
    [
      {
        "type": "boolean",
        "default": True,
        "description": "allows previously hidden alerts to be retrieved",
        "name": "include_hidden",
        "in": "query"
      },
      {
        "description": "composite_ids  CompositeIDs of Alerts to modify.\n\naction_parameters values  "
        "assign_to_uuid\n\t- Assign Alert to user UUID, such as 00000000-0000-0000-0000-000000000000  "
        "assign_to_user_id\n\t- Assign Alert to user ID, such as user@example.com  assign_to_name\n\t- Assign Alert to "
        "username, such as John Doe  unassign\n\t- Unassign Alert clears out the assigned user UUID, user ID, and "
        "username.  add_tag\n \t- Add a tag to the Alert.  remove_tag\n\t- Remove a tag from the Alert.  "
        "remove_tags_by_prefix\n\t- Remove tags from the Alert based on the prefix.  append_comment\n\t- Comments are "
        "displayed with the Alert in Falcon and are usually used to provide context or notes for other Falcon users. An "
        " Alert can have multiple comments over time.  update_status values\n\t- new\n\t- in_progress\n\t- "
        "reopened\n\t- closed  show_in_ui values\n\t- true: This alert is displayed in Falcon\n\t- false: This alert is "
        "not displayed in Falcon.\n",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetQueriesAlertsV1",
    "GET",
    "/alerts/queries/alerts/v1",
    "Deprecated: please use version v2 of this endpoint. Retrieves all Alerts ids that match a given query.",
    "alerts",
    [
      {
        "type": "integer",
        "description": "The first detection to return, where 0 is the latest detection. Use with the offset "
        "parameter to manage pagination of results.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 10000,
        "minimum": 0,
        "type": "integer",
        "description": "The maximum number of detections to return in this response (default: 100; max: "
        "10000). Use this parameter together with the offset parameter to manage pagination of the results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort parameter takes the form <field|direction>. Direction can be either asc "
        "(ascending) or desc (descending) order. For example: status|asc or status|desc.\n\nThe sorting fields can be "
        "any keyword field that is part of #domain.Alert except for the text based fields. Most commonly used fields "
        "are status, cid, aggregate_id, timestamp, created_timestamp, updated_timestamp, assigned_to_name, "
        "assigned_to_uid, assigned_to_uuid, show_in_ui, tactic_id, tactic, technique, technique_id, pattern_id, "
        "product, comment, tags\nIf the fields are missing from the Alerts, the service will fallback to its default "
        "ordering ",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter Alerts using a query in Falcon Query Language (FQL).Filter fields can be any "
        "keyword field that is part of #domain.Alert \nAn asterisk wildcard * includes all results.  \nEmpty value "
        "means to not filter on anything.\nMost commonly used filter fields that supports exact match: cid, id, "
        "aggregate_id, product, type, pattern_id, platform ...\nMost commonly used filter fields that supports wildcard "
        " (*): assigned_to_name, assigned_to_uuid, tactic_id, technique ...\nMost commonly filter fields that supports "
        "range comparisons (>, <, >=, <=): severity, created_timestamp, timestamp, updated_timestamp...\nAll filter "
        "fields and operations support negation (!).\n\n\nThe full list of valid filter options is extensive. Review it "
        " in our [documentation inside the Falcon console](https://falcon.crowdstrike.com/documentation/45/falcon-"
        "query-language-fql).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Search all alert metadata for the provided string",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "GetQueriesAlertsV2",
    "GET",
    "/alerts/queries/alerts/v2",
    "Retrieves all Alerts ids that match a given query.",
    "alerts",
    [
      {
        "type": "boolean",
        "default": True,
        "description": "allows previously hidden alerts to be retrieved",
        "name": "include_hidden",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The first detection to return, where 0 is the latest detection. Use with the offset "
        "parameter to manage pagination of results.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 10000,
        "minimum": 0,
        "type": "integer",
        "description": "The maximum number of detections to return in this response (default: 100; max: "
        "10000). Use this parameter together with the offset parameter to manage pagination of the results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort parameter takes the form <field|direction>. Direction can be either asc "
        "(ascending) or desc (descending) order. For example: status|asc or status|desc.\n\nThe sorting fields can be "
        "any keyword field that is part of #domain.Alert except for the text based fields. Most commonly used fields "
        "are status, cid, aggregate_id, timestamp, created_timestamp, updated_timestamp, assigned_to_name, "
        "assigned_to_uid, assigned_to_uuid, show_in_ui, tactic_id, tactic, technique, technique_id, pattern_id, "
        "product, comment, tags\nIf the fields are missing from the Alerts, the service will fallback to its default "
        "ordering ",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter Alerts using a query in Falcon Query Language (FQL).Filter fields can be any "
        "keyword field that is part of #domain.Alert \nAn asterisk wildcard * includes all results.  \nEmpty value "
        "means to not filter on anything.\nMost commonly used filter fields that supports exact match: cid, id, "
        "aggregate_id, product, type, pattern_id, platform ...\nMost commonly used filter fields that supports wildcard "
        " (*): assigned_to_name, assigned_to_uuid, tactic_id, technique ...\nMost commonly filter fields that supports "
        "range comparisons (>, <, >=, <=): severity, created_timestamp, timestamp, updated_timestamp...\nAll filter "
        "fields and operations support negation (!).\n\n\nThe full list of valid filter options is extensive. Review it "
        " in our [documentation inside the Falcon console](https://falcon.crowdstrike.com/documentation/45/falcon-"
        "query-language-fql).",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Search all alert metadata for the provided string",
        "name": "q",
        "in": "query"
      }
    ]
  ]
]
