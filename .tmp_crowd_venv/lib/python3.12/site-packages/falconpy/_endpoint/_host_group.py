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

_host_group_endpoints = [
  [
    "queryCombinedGroupMembers",
    "GET",
    "/devices/combined/host-group-members/v1",
    "Search for members of a Host Group in your environment by providing an FQL filter and paging details. "
    "Returns a set of host details which match the filter criteria",
    "host_group",
    [
      {
        "type": "string",
        "description": "The ID of the Host Group to search for members of",
        "name": "id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results",
        "name": "filter",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 5000,
        "minimum": 1,
        "type": "integer",
        "description": "The maximum records to return. [1-5000]",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The property to sort by",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "queryCombinedHostGroups",
    "GET",
    "/devices/combined/host-groups/v1",
    "Search for Host Groups in your environment by providing an FQL filter and paging details. Returns a set "
    "of Host Groups which match the filter criteria",
    "host_group",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results",
        "name": "filter",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 5000,
        "minimum": 1,
        "type": "integer",
        "description": "The maximum records to return. [1-5000]",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "created_by.asc",
          "created_by.desc",
          "created_timestamp.asc",
          "created_timestamp.desc",
          "group_type.asc",
          "group_type.desc",
          "modified_by.asc",
          "modified_by.desc",
          "modified_timestamp.asc",
          "modified_timestamp.desc",
          "name.asc",
          "name.desc"
        ],
        "type": "string",
        "description": "The property to sort by",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "performGroupAction",
    "POST",
    "/devices/entities/host-group-actions/v1",
    "Perform the specified action on the Host Groups specified in the request",
    "host_group",
    [
      {
        "enum": [
          "add-hosts",
          "remove-hosts"
        ],
        "type": "string",
        "description": "The action to perform",
        "name": "action_name",
        "in": "query",
        "required": True
      },
      {
        "type": "boolean",
        "default": False,
        "description": "Bool to disable hostname check on add-member",
        "name": "disable_hostname_check",
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
    "getHostGroups",
    "GET",
    "/devices/entities/host-groups/v1",
    "Retrieve a set of Host Groups by specifying their IDs",
    "host_group",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the Host Groups to return",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createHostGroups",
    "POST",
    "/devices/entities/host-groups/v1",
    "Create Host Groups by specifying details about the group to create",
    "host_group",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updateHostGroups",
    "PATCH",
    "/devices/entities/host-groups/v1",
    "Update Host Groups by specifying the ID of the group and details to update",
    "host_group",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteHostGroups",
    "DELETE",
    "/devices/entities/host-groups/v1",
    "Delete a set of Host Groups by specifying their IDs",
    "host_group",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the Host Groups to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queryGroupMembers",
    "GET",
    "/devices/queries/host-group-members/v1",
    "Search for members of a Host Group in your environment by providing an FQL filter and paging details. "
    "Returns a set of Agent IDs which match the filter criteria",
    "host_group",
    [
      {
        "type": "string",
        "description": "The ID of the Host Group to search for members of",
        "name": "id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results",
        "name": "filter",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 5000,
        "minimum": 1,
        "type": "integer",
        "description": "The maximum records to return. [1-5000]",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The property to sort by",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "queryHostGroups",
    "GET",
    "/devices/queries/host-groups/v1",
    "Search for Host Groups in your environment by providing an FQL filter and paging details. Returns a set "
    "of Host Group IDs which match the filter criteria",
    "host_group",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results",
        "name": "filter",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 5000,
        "minimum": 1,
        "type": "integer",
        "description": "The maximum records to return. [1-5000]",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "created_by.asc",
          "created_by.desc",
          "created_timestamp.asc",
          "created_timestamp.desc",
          "group_type.asc",
          "group_type.desc",
          "modified_by.asc",
          "modified_by.desc",
          "modified_timestamp.asc",
          "modified_timestamp.desc",
          "name.asc",
          "name.desc"
        ],
        "type": "string",
        "description": "The property to sort by",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
