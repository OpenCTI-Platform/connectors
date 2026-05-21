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

_report_executions_endpoints = [
  [
    "report_executions_download_get",
    "GET",
    "/reports/entities/report-executions-download/v1",
    "Get report entity download",
    "report_executions",
    [
      {
        "type": "string",
        "description": "The report_execution id to download",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "report_executions_retry",
    "POST",
    "/reports/entities/report-executions-retry/v1",
    "This endpoint will be used to retry report executions",
    "report_executions",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "report_executions_get",
    "GET",
    "/reports/entities/report-executions/v1",
    "Retrieve report details for the provided report IDs.",
    "report_executions",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The report_execution id to get details about.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "report_executions_query",
    "GET",
    "/reports/queries/report-executions/v1",
    "Find all report execution IDs matching the query with filter",
    "report_executions",
    [
      {
        "type": "string",
        "description": "Possible order by fields: created_on, last_updated_on",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Filter term criteria: type, "
        "scheduled_report_id, status. Filter range criteria: created_on, last_updated_on, expiration_on; use any common "
        "date format, such as '2010-05-15T14:55:21.892315096Z'.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match query criteria, which includes all the filter string fields",
        "name": "q",
        "in": "query"
      },
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
      }
    ]
  ]
]
