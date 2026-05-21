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

_iocs_endpoints = [
  [
    "DevicesCount",
    "GET",
    "/indicators/aggregates/devices-count/v1",
    "Number of hosts in your customer account that have observed a given custom IOC",
    "iocs",
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
    "GetIOC",
    "GET",
    "/indicators/entities/iocs/v1",
    "Get an IOC by providing a type and value. *** Deprecated - Use the new IOC Management endpoint (GET "
    "/iocs/entities/indicators/v1). ***",
    "iocs",
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
    "CreateIOC",
    "POST",
    "/indicators/entities/iocs/v1",
    "Create a new IOC. *** Deprecated - Use the new IOC Management endpoint (POST /iocs/entities/indicators/v1). ***",
    "iocs",
    [
      {
        "description": "Create a new IOC by providing a JSON object that includes these key/value "
        "pairs:\n\n**type** (required): The type of the indicator. Valid values:\n\n- sha256: A hex-encoded sha256 hash "
        " string. Length - min: 64, max: 64.\n\n- md5: A hex-encoded md5 hash string. Length - min 32, max: 32.\n\n- "
        "domain: A domain name. Length - min: 1, max: 200.\n\n- ipv4: An IPv4 address. Must be a valid IP address.\n\n-"
        " ipv6: An IPv6 address. Must be a valid IP address.\n\n**value** (required): The string representation of the "
        "indicator.\n\n**policy** (required): Action to take when a host observes the custom IOC. Values:\n\n- detect: "
        "Enable detections for this custom IOC\n\n- none: Disable detections for this custom IOC\n\n**share_level** "
        "(optional): Visibility of this custom IOC. All custom IOCs are visible only within your customer account, so "
        "only one value is valid:\n\n- red\n\n**expiration_days** (optional): Number of days this custom IOC is active. "
        " Only applies for the types `domain`, `ipv4`, and `ipv6`.\n\n**source** (optional): The source where this "
        "indicator originated. This can be used for tracking where this indicator was defined. Limit 200 "
        "characters.\n\n**description** (optional): Descriptive label for this custom IOC",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateIOC",
    "PATCH",
    "/indicators/entities/iocs/v1",
    "Update an IOC by providing a type and value. *** Deprecated - Use the new IOC Management endpoint (PATCH "
    "/iocs/entities/indicators/v1). ***",
    "iocs",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      },
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
    "DeleteIOC",
    "DELETE",
    "/indicators/entities/iocs/v1",
    "Delete an IOC by providing a type and value. *** Deprecated - Use the new IOC Management endpoint (DELETE "
    "/iocs/entities/indicators/v1). ***",
    "iocs",
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
    "DevicesRanOn",
    "GET",
    "/indicators/queries/devices/v1",
    "Find hosts that have observed a given custom IOC. For details about those hosts, use GET /devices/entities/devices/v1",
    "iocs",
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
        "description": "The first process to return, where 0 is the latest offset. Use with the offset "
        "parameter to manage pagination of results.",
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
    "QueryIOCs",
    "GET",
    "/indicators/queries/iocs/v1",
    "Search the custom IOCs in your customer account. *** Deprecated - Use the new IOC Management endpoint "
    "(GET /iocs/queries/indicators/v1). ***",
    "iocs",
    [
      {
        "type": "string",
        "description": "\nThe type of the indicator. Valid types include:\n\nsha256: A hex-encoded sha256 hash "
        " string. Length - min: 64, max: 64.\n\nmd5: A hex-encoded md5 hash string. Length - min 32, max: "
        "32.\n\ndomain: A domain name. Length - min: 1, max: 200.\n\nipv4: An IPv4 address. Must be a valid IP "
        "address.\n\nipv6: An IPv6 address. Must be a valid IP address.\n",
        "name": "types",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The string representation of the indicator",
        "name": "values",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Find custom IOCs created after this time (RFC-3339 timestamp)",
        "name": "from.expiration_timestamp",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Find custom IOCs created before this time (RFC-3339 timestamp)",
        "name": "to.expiration_timestamp",
        "in": "query"
      },
      {
        "type": "string",
        "description": "\\ndetect: Find custom IOCs that produce notifications\\n\\nnone: Find custom IOCs the "
        "particular indicator has been detected on a host. This is equivalent to turning the indicator off.\n",
        "name": "policies",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The source where this indicator originated. This can be used for tracking where this "
        "indicator was defined. Limit 200 characters.",
        "name": "sources",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The level at which the indicator will be shared. Currently only red share level (not "
        "shared) is supported, indicating that the IOC isn't shared with other FH customers.",
        "name": "share_levels",
        "in": "query"
      },
      {
        "type": "string",
        "description": "created_by",
        "name": "created_by",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The user or API client who deleted the custom IOC",
        "name": "deleted_by",
        "in": "query"
      },
      {
        "type": "string",
        "description": "\ntrue: Include deleted IOCs\n\nfalse: Don't include deleted IOCs (default)\n",
        "name": "include_deleted",
        "in": "query"
      }
    ]
  ],
  [
    "ProcessesRanOn",
    "GET",
    "/indicators/queries/processes/v1",
    "Search for processes associated with a custom IOC",
    "iocs",
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
        "description": "The first process to return, where 0 is the latest offset. Use with the offset "
        "parameter to manage pagination of results.",
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
    "entities_processes",
    "GET",
    "/processes/entities/processes/v1",
    "For the provided ProcessID retrieve the process details",
    "iocs",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "ProcessID for the running process you want to lookup",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ]
]
