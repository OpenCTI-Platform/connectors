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

_zero_trust_assessment_endpoints = [
  [
    "getAssessmentV1",
    "GET",
    "/zero-trust-assessment/entities/assessments/v1",
    "Get Zero Trust Assessment data for one or more hosts by providing agent IDs (AID) and a customer ID (CID).",
    "zero_trust_assessment",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more agent IDs, which you can find in the data.zta file, or the Falcon console.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getAuditV1",
    "GET",
    "/zero-trust-assessment/entities/audit/v1",
    "Get the Zero Trust Assessment audit report for one customer ID (CID).",
    "zero_trust_assessment",
    []
  ],
  [
    "getAssessmentsByScoreV1",
    "GET",
    "/zero-trust-assessment/queries/assessments/v1",
    "Get Zero Trust Assessment data for one or more hosts by providing a customer ID (CID) and a range of scores.",
    "zero_trust_assessment",
    [
      {
        "type": "string",
        "description": "FQL query specifying the filter score.",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "description": "The number of scores to return in this response (min: 1, max: 1000, default: 100). Use "
        "with the after parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an after token. On subsequent requests, provide the after token from the "
        "previous response to continue from that place in the results.",
        "name": "after",
        "in": "query"
      },
      {
        "type": "string",
        "default": "score",
        "description": "Sort accounts by their properties. A single sort field is allowed. Defaults to "
        "ascending. Supported sort option include:\n\n<ul><li>score|desc</li><li>score|asc</li></ul>",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "getCombinedAssessmentsQuery",
    "GET",
    "/configuration-assessment/combined/assessments/v1",
    "Search for assessments in your environment by providing an FQL filter and paging details. Returns a set "
    "of HostFinding entities which match the filter criteria",
    "public_assessments",
    [
      {
        "type": "string",
        "description": "A pagination token used with the `limit` parameter to manage pagination of results. On "
        " your first request, don't provide an `after` token. On subsequent requests, provide the `after` token from "
        "the previous response to continue from that place in the results.",
        "name": "after",
        "in": "query"
      },
      {
        "maximum": 5000,
        "minimum": 1,
        "type": "integer",
        "description": "The number of items to return in this response (default: 100, max: 5000). Use with the "
        "after parameter to manage pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort assessment by their properties. Common sort options "
        "include:\n\n<ul><li>created_timestamp|desc</li><li>updated_timestamp|asc</li></ul>",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter items using a query in Falcon Query Language (FQL). Wildcards * are "
        "unsupported. \n\nCommon filter options include:\n\n<ul><li>created_timestamp:>'2019-11-"
        "25T22:36:12Z'</li><li>updated_timestamp:>'2019-11-"
        "25T22:36:12Z'</li><li>aid:'8e7656b27d8c49a34a1af416424d6231'</li></ul>",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Select various details blocks to be returned for each assessment entity. Supported "
        "values:\n\n<ul><li>host</li><li>finding.rule</li></ul>",
        "name": "facet",
        "in": "query"
      }
    ]
  ]
]
