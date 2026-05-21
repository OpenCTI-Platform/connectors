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

_intelligence_indicator_graph_endpoints = [
  [
    "SearchIndicators",
    "POST",
    "/intelligence/combined/indicators/v1",
    "Search indicators based on FQL filter.",
    "intelligence_indicator_graph",
    [
      {
        "type": "string",
        "description": "Parameter to specify the order(field examples: FileDetails.SHA256, URLDetails.URL, "
        "PublishDate, MaliciousConfidence) Ex: 'PublishDate|asc'.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "\nFQL query specifying the filter parameters.\n\t\t\t\t\t\t\n**Filter parameters "
        "include:** Type, LastUpdated, KillChain, MaliciousConfidence, MaliciousConfidenceValidatedTime, FirstSeen, "
        "LastSeen, \nAdversaries.Name, Adversaries.Slug, Reports.Title, Reports.Slug, Threats.FamilyName, "
        "Vulnerabilities.CVE, Sectors.Name, FileDetails.SHA256, \nFileDetails.SHA1, FileDetails.MD5, "
        "DomainDetails.Detail, IPv4Details.IPv4, IPv6Details.IPv6, URLDetails.URL and others",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Limit",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Offset",
        "name": "offset",
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
    "LookupIndicators",
    "POST",
    "/intelligence/combined/lookup-indicators/v1",
    "Get indicators based on their value.",
    "intelligence_indicator_graph",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
