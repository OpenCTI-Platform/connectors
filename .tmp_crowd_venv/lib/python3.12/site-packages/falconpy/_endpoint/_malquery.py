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

_malquery_endpoints = [
  [
    "GetMalQueryQuotasV1",
    "GET",
    "/malquery/aggregates/quotas/v1",
    "Get information about search and download quotas in your environment",
    "malquery",
    []
  ],
  [
    "PostMalQueryFuzzySearchV1",
    "POST",
    "/malquery/combined/fuzzy-search/v1",
    "Search Falcon MalQuery quickly, but with more potential for false positives. Search for a combination of "
    "hex patterns and strings in order to identify samples based upon file content at byte level granularity.",
    "malquery",
    [
      {
        "description": "Fuzzy search parameters. See model for more details.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetMalQueryDownloadV1",
    "GET",
    "/malquery/entities/download-files/v1",
    "Download a file indexed by MalQuery. Specify the file using its SHA256. Only one file is supported at this time",
    "malquery",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "The file SHA256.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetMalQueryMetadataV1",
    "GET",
    "/malquery/entities/metadata/v1",
    "Retrieve indexed files metadata by their hash",
    "malquery",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "The file SHA256.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetMalQueryRequestV1",
    "GET",
    "/malquery/entities/requests/v1",
    "Check the status and results of an asynchronous request, such as hunt or exact-search. Supports a single "
    "request id at this time.",
    "malquery",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Identifier of a MalQuery request",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetMalQueryEntitiesSamplesFetchV1",
    "GET",
    "/malquery/entities/samples-fetch/v1",
    "Fetch a zip archive with password 'infected' containing the samples. Call this once the "
    "/entities/samples-multidownload request has finished processing",
    "malquery",
    [
      {
        "type": "string",
        "description": "Multidownload job id",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "PostMalQueryEntitiesSamplesMultidownloadV1",
    "POST",
    "/malquery/entities/samples-multidownload/v1",
    "Schedule samples for download. Use the result id with the /request endpoint to check if the download is "
    "ready after which you can call the /entities/samples-fetch to get the zip",
    "malquery",
    [
      {
        "description": "Download request. See model for more details.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PostMalQueryExactSearchV1",
    "POST",
    "/malquery/queries/exact-search/v1",
    "Search Falcon MalQuery for a combination of hex patterns and strings in order to identify samples based "
    "upon file content at byte level granularity. You can filter results on criteria such as file type, file size "
    "and first seen date. Returns a request id which can be used with the /request endpoint",
    "malquery",
    [
      {
        "description": "Exact search parameters. See model for more details.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PostMalQueryHuntV1",
    "POST",
    "/malquery/queries/hunt/v1",
    "Schedule a YARA-based search for execution. Returns a request id which can be used with the /request endpoint",
    "malquery",
    [
      {
        "description": "Hunt parameters. See model for more details.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
