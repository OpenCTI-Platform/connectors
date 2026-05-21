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

_falcon_complete_dashboard_endpoints = [
  [
    "AggregateAlerts",
    "POST",
    "/falcon-complete-dashboards/aggregates/alerts/GET/v1",
    "Retrieve aggregate epp alerts values based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateAllowList",
    "POST",
    "/falcon-complete-dashboards/aggregates/allowlist/GET/v1",
    "Retrieve aggregate allowlist ticket values based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateBlockList",
    "POST",
    "/falcon-complete-dashboards/aggregates/blocklist/GET/v1",
    "Retrieve aggregate blocklist ticket values based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateDetections",
    "POST",
    "/falcon-complete-dashboards/aggregates/detects/GET/v1",
    "Retrieve aggregate detection values based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateDeviceCountCollection",
    "POST",
    "/falcon-complete-dashboards/aggregates/devicecount-collections/GET/v1",
    "Retrieve aggregate host/devices count based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateEscalations",
    "POST",
    "/falcon-complete-dashboards/aggregates/escalations/GET/v1",
    "Retrieve aggregate escalation ticket values based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateFCIncidents",
    "POST",
    "/falcon-complete-dashboards/aggregates/incidents/GET/v1",
    "Retrieve aggregate incident values based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregatePreventionPolicy",
    "POST",
    "/falcon-complete-dashboards/aggregates/prevention-policies/v1",
    "Retrieve prevention policies aggregate values based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateRemediations",
    "POST",
    "/falcon-complete-dashboards/aggregates/remediations/GET/v1",
    "Retrieve aggregate remediation ticket values based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateSensorUpdatePolicy",
    "POST",
    "/falcon-complete-dashboards/aggregates/sensor-update-policies/v1",
    "Retrieve sensor update policies aggregate values",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateSupportIssues",
    "POST",
    "/falcon-complete-dashboards/aggregates/support-issues/v1",
    "Retrieve aggregate support issue ticket values based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateTotalDeviceCounts",
    "POST",
    "/falcon-complete-dashboards/aggregates/total-device-counts/v1",
    "Retrieve aggregate total host/devices based on the matched filter",
    "falcon_complete_dashboard",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "QueryAlertIdsByFilter",
    "GET",
    "/falcon-complete-dashboards/queries/alerts/v1",
    "Retrieve Alerts Ids for epp that match the provided FQL filter criteria with scrolling enabled",
    "falcon_complete_dashboard",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
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
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "QueryAlertIdsByFilterV2",
    "GET",
    "/falcon-complete-dashboards/queries/alerts/v2",
    "Retrieve Alerts Ids for epp, idp and ngsiem that match the provided FQL filter criteria with scrolling enabled",
    "falcon_complete_dashboard",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
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
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "QueryAllowListFilter",
    "GET",
    "/falcon-complete-dashboards/queries/allowlist/v1",
    "Retrieve allowlist tickets that match the provided filter criteria with scrolling enabled",
    "falcon_complete_dashboard",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
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
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "QueryBlockListFilter",
    "GET",
    "/falcon-complete-dashboards/queries/blocklist/v1",
    "Retrieve block listtickets that match the provided filter criteria with scrolling enabled",
    "falcon_complete_dashboard",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
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
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "QueryDetectionIdsByFilter",
    "GET",
    "/falcon-complete-dashboards/queries/detects/v1",
    "Retrieve DetectionsIds that match the provided FQL filter, criteria with scrolling enabled",
    "falcon_complete_dashboard",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
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
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "GetDeviceCountCollectionQueriesByFilter",
    "GET",
    "/falcon-complete-dashboards/queries/devicecount-collections/v1",
    "Retrieve device count collection Ids that match the provided FQL filter, criteria with scrolling enabled",
    "falcon_complete_dashboard",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
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
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "QueryEscalationsFilter",
    "GET",
    "/falcon-complete-dashboards/queries/escalations/v1",
    "Retrieve escalation tickets that match the provided filter criteria with scrolling enabled",
    "falcon_complete_dashboard",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
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
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "QueryIncidentIdsByFilter",
    "GET",
    "/falcon-complete-dashboards/queries/incidents/v1",
    "Retrieve incidents that match the provided filter criteria with scrolling enabled",
    "falcon_complete_dashboard",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
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
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "QueryRemediationsFilter",
    "GET",
    "/falcon-complete-dashboards/queries/remediations/v1",
    "Retrieve remediation tickets that match the provided filter criteria with scrolling enabled",
    "falcon_complete_dashboard",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
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
        "type": "string",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ]
]
