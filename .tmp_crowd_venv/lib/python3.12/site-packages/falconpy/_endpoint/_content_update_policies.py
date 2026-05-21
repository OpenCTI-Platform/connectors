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

_content_update_policies_endpoints = [
  [
    "queryCombinedContentUpdatePolicyMembers",
    "GET",
    "/policy/combined/content-update-members/v1",
    "Search for members of a Content Update Policy in your environment by providing an FQL filter and paging "
    "details. Returns a set of host details which match the filter criteria",
    "content_update_policies",
    [
      {
        "type": "string",
        "description": "The ID of the Content Update Policy to search for members of",
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
    "queryCombinedContentUpdatePolicies",
    "GET",
    "/policy/combined/content-update/v1",
    "Search for Content Update Policies in your environment by providing an FQL filter and paging details. "
    "Returns a set of Content Update Policies which match the filter criteria",
    "content_update_policies",
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
          "enabled.asc",
          "enabled.desc",
          "modified_by.asc",
          "modified_by.desc",
          "modified_timestamp.asc",
          "modified_timestamp.desc",
          "name.asc",
          "name.desc",
          "platform_name.asc",
          "platform_name.desc",
          "precedence.asc",
          "precedence.desc"
        ],
        "type": "string",
        "description": "The property to sort by",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "performContentUpdatePoliciesAction",
    "POST",
    "/policy/entities/content-update-actions/v1",
    "Perform the specified action on the Content Update Policies specified in the request",
    "content_update_policies",
    [
      {
        "enum": [
          "add-host-group",
          "disable",
          "enable",
          "override-allow",
          "override-pause",
          "override-revert",
          "remove-host-group",
          "remove-pinned-content-version",
          "set-pinned-content-version"
        ],
        "type": "string",
        "description": "The action to perform",
        "name": "action_name",
        "in": "query",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "setContentUpdatePoliciesPrecedence",
    "POST",
    "/policy/entities/content-update-precedence/v1",
    "Sets the precedence of Content Update Policies based on the order of IDs specified in the request. The "
    "first ID specified will have the highest precedence and the last ID specified will have the lowest. You must "
    "specify all non-Default Policies when updating precedence",
    "content_update_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getContentUpdatePolicies",
    "GET",
    "/policy/entities/content-update/v1",
    "Retrieve a set of Content Update Policies by specifying their IDs",
    "content_update_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the Content Update Policies to return",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createContentUpdatePolicies",
    "POST",
    "/policy/entities/content-update/v1",
    "Create Content Update Policies by specifying details about the policy to create",
    "content_update_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updateContentUpdatePolicies",
    "PATCH",
    "/policy/entities/content-update/v1",
    "Update Content Update Policies by specifying the ID of the policy and details to update",
    "content_update_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteContentUpdatePolicies",
    "DELETE",
    "/policy/entities/content-update/v1",
    "Delete a set of Content Update Policies by specifying their IDs",
    "content_update_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the Content Update Policies to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queryContentUpdatePolicyMembers",
    "GET",
    "/policy/queries/content-update-members/v1",
    "Search for members of a Content Update Policy in your environment by providing an FQL filter and paging "
    "details. Returns a set of Agent IDs which match the filter criteria",
    "content_update_policies",
    [
      {
        "type": "string",
        "description": "The ID of the Content Update Policy to search for members of",
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
    "queryPinnableContentVersions",
    "GET",
    "/policy/queries/content-update-pin-versions/v1",
    "Search for content versions available for pinning given the category.",
    "content_update_policies",
    [
      {
        "enum": [
          "rapid_response_al_bl_listing",
          "sensor_operations",
          "system_critical",
          "vulnerability_management"
        ],
        "type": "string",
        "description": "Content category",
        "name": "category",
        "in": "query",
        "required": True
      },
      {
        "enum": [
          "deployed_timestamp.asc",
          "deployed_timestamp.desc"
        ],
        "type": "string",
        "default": "deployed_timestamp.desc",
        "description": "value to sort returned content versions by. Allowed sort values are "
        "deployed_timestamp.(asc|desc) defaulting to deployed_timestamp.desc",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "queryContentUpdatePolicies",
    "GET",
    "/policy/queries/content-update/v1",
    "Search for Content Update Policies in your environment by providing an FQL filter and paging details. "
    "Returns a set of Content Update Policy IDs which match the filter criteria",
    "content_update_policies",
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
          "enabled.asc",
          "enabled.desc",
          "modified_by.asc",
          "modified_by.desc",
          "modified_timestamp.asc",
          "modified_timestamp.desc",
          "name.asc",
          "name.desc",
          "platform_name.asc",
          "platform_name.desc",
          "precedence.asc",
          "precedence.desc"
        ],
        "type": "string",
        "description": "The property to sort by",
        "name": "sort",
        "in": "query"
      }
    ]
  ]
]
