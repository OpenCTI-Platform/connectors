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

_cao_hunting_endpoints = [
  [
    "AggregateHuntingGuides",
    "POST",
    "/hunting/aggregates/hunting-guides/v1",
    "Aggregate Hunting Guides",
    "cao_hunting",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateIntelligenceQueries",
    "POST",
    "/hunting/aggregates/intelligence-queries/v1",
    "Aggregate intelligence queries",
    "cao_hunting",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetArchiveExport",
    "GET",
    "/hunting/entities/archive-exports/v1",
    "Creates an Archive Export",
    "cao_hunting",
    [
      {
        "type": "string",
        "description": "The Query Language. Accepted "
        "Values:\n\n<li>cql</li><li>snort</li><li>suricata</li><li>yara</li><li>SPL <i>AI translated "
        "(Beta)</i></li><li>__all__ <i>returns a single archive with queries in all the languages</i></li> ",
        "name": "language",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The FQL Filter",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "default": "zip",
        "description": "The Archive Type can be one of 'zip' and 'gzip'",
        "name": "archive_type",
        "in": "query"
      }
    ]
  ],
  [
    "GetHuntingGuides",
    "GET",
    "/hunting/entities/hunting-guides/v1",
    "Retrieves a list of Hunting Guides",
    "cao_hunting",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Hunting Guides IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetIntelligenceQueries",
    "GET",
    "/hunting/entities/intelligence-queries/v1",
    "Retrieves the details of a list of Intelligence queries IDs",
    "cao_hunting",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Intelligence queries IDs",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The AI translated language that should be returned if it exists<br>Accepted values "
        "are: <li>SPL</li><li>\\_\\_all\\_\\_</li>",
        "name": "include_translated_content",
        "in": "query"
      }
    ]
  ],
  [
    "SearchHuntingGuides",
    "GET",
    "/hunting/queries/hunting-guides/v1",
    "Search for Hunting Guides that match the provided conditions",
    "cao_hunting",
    [
      {
        "type": "string",
        "description": "Starting index of result set from which to return IDs.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of IDs to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order by fields.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match phrase_prefix query criteria; included fields: _all (all filter string fields indexed).",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "SearchIntelligenceQueries",
    "GET",
    "/hunting/queries/intelligence-queries/v1",
    "Search for a list of intelligence queries IDs that match the provided conditions",
    "cao_hunting",
    [
      {
        "type": "string",
        "description": "Starting index of result set from which to return IDs.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of IDs to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order by fields.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match phrase_prefix query criteria; included fields: _all (all filter string fields indexed).",
        "name": "q",
        "in": "query"
      }
    ]
  ]
]
