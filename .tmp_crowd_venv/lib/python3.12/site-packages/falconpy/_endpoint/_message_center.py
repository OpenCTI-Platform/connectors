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

_message_center_endpoints = [
  [
    "AggregateCases",
    "POST",
    "/message-center/aggregates/cases/GET/v1",
    "Retrieve aggregate case values based on the matched filter",
    "message_center",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCaseActivityByIds",
    "POST",
    "/message-center/entities/case-activities/GET/v1",
    "Retrieve activities for given id's",
    "message_center",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "CaseAddActivity",
    "POST",
    "/message-center/entities/case-activity/v1",
    "Add an activity to case. Only activities of type comment are allowed via API",
    "message_center",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "CaseDownloadAttachment",
    "GET",
    "/message-center/entities/case-attachment/v1",
    "retrieves an attachment for the case, given the attachment id",
    "message_center",
    [
      {
        "type": "string",
        "description": "attachment ID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CaseAddAttachment",
    "POST",
    "/message-center/entities/case-attachment/v1",
    "Upload an attachment for the case.",
    "message_center",
    [
      {
        "type": "string",
        "description": "Case ID",
        "name": "case_id",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "User UUID",
        "name": "user_uuid",
        "in": "formData",
        "required": True
      },
      {
        "type": "file",
        "description": "File Body",
        "name": "file",
        "in": "formData",
        "required": True
      }
    ]
  ],
  [
    "CreateCaseV2",
    "POST",
    "/message-center/entities/case/v2",
    "create a new case",
    "message_center",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetCaseEntitiesByIDs",
    "POST",
    "/message-center/entities/cases/GET/v1",
    "Retrieve message center cases",
    "message_center",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "QueryActivityByCaseID",
    "GET",
    "/message-center/queries/case-activities/v1",
    "Retrieve activities id's for a case",
    "message_center",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "activity.type.asc",
          "activity.type.desc",
          "activity.created_time.asc",
          "activity.created_time.desc"
        ],
        "type": "string",
        "description": "The property to sort on, followed by a dot (.), followed by the sort direction, either "
        "\"asc\" or \"desc\".",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Optional filter and sort criteria in the form of an FQL query. Allowed filters are: "
        "activity.created_time\nactivity.type",
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
        "type": "string",
        "description": "Case ID",
        "name": "case_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "QueryCasesIdsByFilter",
    "GET",
    "/message-center/queries/cases/v1",
    "Retrieve case id's that match the provided filter criteria",
    "message_center",
    [
      {
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "case.created_time.asc",
          "case.created_time.desc",
          "case.last_modified_time.asc",
          "case.last_modified_time.desc",
          "case.status.asc",
          "case.status.desc",
          "case.type.asc",
          "case.type.desc",
          "case.id.asc",
          "case.id.desc"
        ],
        "type": "string",
        "description": "The property to sort on, followed by a dot (.), followed by the sort direction, either "
        "\"asc\" or \"desc\".",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Optional filter and sort criteria in the form of an FQL query. Allowed filters are: _a "
        "ll\nactivity.body\ncase.aids\ncase.assigner.display_name\ncase.assigner.first_name\ncase.assigner.last_name\nc "
        "ase.assigner.uid\ncase.assigner.uuid\ncase.body\ncase.created_time\ncase.detections.id\ncase.hosts\ncase.id\nc "
        "ase.incidents.id\ncase.ip_addresses\ncase.key\ncase.last_modified_time\ncase.status\ncase.status\ncase.title\n "
        "case.type",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      }
    ]
  ]
]
