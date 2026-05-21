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

_quick_scan_endpoints = [
  [
    "GetScansAggregates",
    "POST",
    "/scanner/aggregates/scans/GET/v1",
    "Get scans aggregations as specified via json in request body.",
    "quick_scan",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetScans",
    "GET",
    "/scanner/entities/scans/v1",
    "Check the status of a volume scan. Time required for analysis increases with the number of samples in a "
    "volume but usually it should take less than 1 minute",
    "quick_scan",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "ID of a submitted scan",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ScanSamples",
    "POST",
    "/scanner/entities/scans/v1",
    "Submit a volume of files for ml scanning. Time required for analysis increases with the number of samples "
    "in a volume but usually it should take less than 1 minute",
    "quick_scan",
    [
      {
        "description": "Submit a batch of SHA256s for ml scanning. The samples must have been previously "
        "uploaded through /samples/entities/samples/v3",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "QuerySubmissionsMixin0",
    "GET",
    "/scanner/queries/scans/v1",
    "Find IDs for submitted scans by providing an FQL filter and paging details. Returns a set of volume IDs "
    "that match your criteria.",
    "quick_scan",
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
        "type": "string",
        "description": "The offset to start retrieving submissions from.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Maximum number of volume IDs to return. Max: 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort order: asc or desc.",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
