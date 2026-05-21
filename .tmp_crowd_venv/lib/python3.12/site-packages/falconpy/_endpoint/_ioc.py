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

_ioc_endpoints = [
  [
    "indicator_get_device_count_v1",
    "GET",
    "/iocs/aggregates/indicators/device-count/v1",
    "Get the number of devices the indicator has run on",
    "ioc",
    [
      {
        "type": "string",
        "description": "\nThe type of the indicator. Valid types include:\n\nsha256: A hex-encoded sha256 hash "
        " string. Length - min: 64, max: 64.\n\nmd5: A hex-encoded md5 hash string. Length - min 32, max: "
        "32.\n\ndomain: A domain name. Length - min: 1, max: 200.\n\nipv4: An IPv4 address. Must be a valid IP "
        "address.\n\nipv6: An IPv6 address. Must be a valid IP address.\n",
        "name": "type",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The string representation of the indicator",
        "name": "value",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "indicator_aggregate_v1",
    "POST",
    "/iocs/aggregates/indicators/v1",
    "Get Indicators aggregates as specified via json in the request body.",
    "ioc",
    [
      {
        "type": "string",
        "description": "The filter to narrow down the aggregation data",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "The filter for returning either only indicators for the request customer or its MSSP parents",
        "name": "from_parent",
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
    "indicator_combined_v1",
    "GET",
    "/iocs/combined/indicator/v1",
    "Get Combined for Indicators.",
    "ioc",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from. Offset and After params are mutually "
        "exclusive. If none provided then scrolling will be used by default. To access more than 10k iocs, use the "
        "'after' parameter instead of 'offset'.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "action",
          "applied_globally",
          "metadata.av_hits",
          "metadata.company_name.raw",
          "created_by",
          "created_on",
          "expiration",
          "expired",
          "metadata.filename.raw",
          "modified_by",
          "modified_on",
          "metadata.original_filename.raw",
          "metadata.product_name.raw",
          "metadata.product_version",
          "severity_number",
          "source",
          "type",
          "value"
        ],
        "type": "string",
        "description": "The sort expression that should be used to sort the results.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an 'after' token. On subsequent requests, provide the 'after' token from the "
        " previous response to continue from that place in the results. To access more than 10k indicators, use the "
        "'after' parameter instead of 'offset'.",
        "name": "after",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "The filter for returning either only indicators for the request customer or its MSSP parents",
        "name": "from_parent",
        "in": "query"
      }
    ]
  ],
  [
    "action_get_v1",
    "GET",
    "/iocs/entities/actions/v1",
    "Get Actions by ids.",
    "ioc",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The ids of the Actions to retrieve",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "GetIndicatorsReport",
    "POST",
    "/iocs/entities/indicators-reports/v1",
    "Launch an indicators report creation job",
    "ioc",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "indicator_get_v1",
    "GET",
    "/iocs/entities/indicators/v1",
    "Get Indicators by ids.",
    "ioc",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The ids of the Indicators to retrieve",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "indicator_create_v1",
    "POST",
    "/iocs/entities/indicators/v1",
    "Create Indicators.",
    "ioc",
    [
      {
        "type": "boolean",
        "description": "Whether to submit to retrodetects",
        "name": "retrodetects",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Set to true to ignore warnings and add all IOCs",
        "name": "ignore_warnings",
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
    "indicator_update_v1",
    "PATCH",
    "/iocs/entities/indicators/v1",
    "Update Indicators.",
    "ioc",
    [
      {
        "type": "boolean",
        "description": "Whether to submit to retrodetects",
        "name": "retrodetects",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Set to true to ignore warnings and add all IOCs",
        "name": "ignore_warnings",
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
    "indicator_delete_v1",
    "DELETE",
    "/iocs/entities/indicators/v1",
    "Delete Indicators by ids.",
    "ioc",
    [
      {
        "type": "string",
        "description": "The FQL expression to delete Indicators in bulk. If both 'filter' and 'ids' are "
        "provided, then filter takes precedence and ignores ids.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The ids of the Indicators to delete. If both 'filter' and 'ids' are provided, then "
        "filter takes precedence and ignores ids",
        "name": "ids",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The comment why these indicators were deleted",
        "name": "comment",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "The filter for returning either only indicators for the request customer or its MSSP parents",
        "name": "from_parent",
        "in": "query"
      }
    ]
  ],
  [
    "action_query_v1",
    "GET",
    "/iocs/queries/actions/v1",
    "Query Actions.",
    "ioc",
    [
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
  ],
  [
    "indicator_get_devices_ran_on_v1",
    "GET",
    "/iocs/queries/indicators/devices/v1",
    "Get the IDs of devices the indicator has run on",
    "ioc",
    [
      {
        "type": "string",
        "description": "\nThe type of the indicator. Valid types include:\n\nsha256: A hex-encoded sha256 hash "
        " string. Length - min: 64, max: 64.\n\nmd5: A hex-encoded md5 hash string. Length - min 32, max: "
        "32.\n\ndomain: A domain name. Length - min: 1, max: 200.\n\nipv4: An IPv4 address. Must be a valid IP "
        "address.\n\nipv6: An IPv6 address. Must be a valid IP address.\n",
        "name": "type",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The string representation of the indicator",
        "name": "value",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The maximum number of results to return. Use with the offset parameter to manage "
        "pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The first process to return, where 0 is the latest offset. Use with the limit "
        "parameter to manage pagination of results.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "indicator_get_processes_ran_on_v1",
    "GET",
    "/iocs/queries/indicators/processes/v1",
    "Get the number of processes the indicator has run on",
    "ioc",
    [
      {
        "type": "string",
        "description": "\nThe type of the indicator. Valid types include:\n\nsha256: A hex-encoded sha256 hash "
        " string. Length - min: 64, max: 64.\n\nmd5: A hex-encoded md5 hash string. Length - min 32, max: "
        "32.\n\ndomain: A domain name. Length - min: 1, max: 200.\n\nipv4: An IPv4 address. Must be a valid IP "
        "address.\n\nipv6: An IPv6 address. Must be a valid IP address.\n",
        "name": "type",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The string representation of the indicator",
        "name": "value",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Specify a host's ID to return only processes from that host. Get a host's ID from GET "
        "/devices/queries/devices/v1, the Falcon console, or the Streaming API.",
        "name": "device_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The maximum number of results to return. Use with the offset parameter to manage "
        "pagination of results.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The first process to return, where 0 is the latest offset. Use with the limit "
        "parameter to manage pagination of results.",
        "name": "offset",
        "in": "query"
      }
    ]
  ],
  [
    "indicator_search_v1",
    "GET",
    "/iocs/queries/indicators/v1",
    "Search for Indicators.",
    "ioc",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from. Offset and After params are mutually "
        "exclusive. If none provided then scrolling will be used by default. To access more than 10k iocs, use the "
        "'after' parameter instead of 'offset'.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "action",
          "applied_globally",
          "metadata.av_hits",
          "metadata.company_name.raw",
          "created_by",
          "created_on",
          "expiration",
          "expired",
          "metadata.filename.raw",
          "modified_by",
          "modified_on",
          "metadata.original_filename.raw",
          "metadata.product_name.raw",
          "metadata.product_version",
          "severity_number",
          "source",
          "type",
          "value"
        ],
        "type": "string",
        "description": "The sort expression that should be used to sort the results.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request, don't provide an 'after' token. On subsequent requests, provide the 'after' token from the "
        " previous response to continue from that place in the results. To access more than 10k indicators, use the "
        "'after' parameter instead of 'offset'.",
        "name": "after",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "The filter for returning either only indicators for the request customer or its MSSP parents",
        "name": "from_parent",
        "in": "query"
      }
    ]
  ],
  [
    "ioc_type_query_v1",
    "GET",
    "/iocs/queries/ioc-types/v1",
    "Query IOC Types.",
    "ioc",
    [
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
  ],
  [
    "platform_query_v1",
    "GET",
    "/iocs/queries/platforms/v1",
    "Query Platforms.",
    "ioc",
    [
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
  ],
  [
    "severity_query_v1",
    "GET",
    "/iocs/queries/severities/v1",
    "Query Severities.",
    "ioc",
    [
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
