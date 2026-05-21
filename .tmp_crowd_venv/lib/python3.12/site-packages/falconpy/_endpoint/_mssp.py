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

_mssp_endpoints = [
  [
    "getChildrenV2",
    "POST",
    "/mssp/entities/children/GET/v2",
    "Get link to child customer by child CID(s)",
    "mssp",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getChildren",
    "GET",
    "/mssp/entities/children/v1",
    "Get link to child customer by child CID(s)",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "CID of a child customer",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getCIDGroupMembersByV1",
    "GET",
    "/mssp/entities/cid-group-members/v1",
    "Deprecated : Please use getCIDGroupMembersBy. Get CID group members by CID group ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "CID group IDs to search for",
        "name": "cid_group_ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "addCIDGroupMembers",
    "POST",
    "/mssp/entities/cid-group-members/v1",
    "Add new CID group member.",
    "mssp",
    [
      {
        "description": "Both 'cid_group_id' and 'cids' fields are required.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteCIDGroupMembersV1",
    "DELETE",
    "/mssp/entities/cid-group-members/v1",
    "Deprecated: Please use deleteCIDGroupMembersV2.",
    "mssp",
    [
      {
        "description": "Both 'cid_group_id' and 'cids' fields are required.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getCIDGroupMembersBy",
    "GET",
    "/mssp/entities/cid-group-members/v2",
    "Get CID group members by CID Group ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "CID group IDs search for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "deleteCIDGroupMembers",
    "DELETE",
    "/mssp/entities/cid-group-members/v1",
    "Deprecated : Please use deleteCIDGroupMembers. Delete CID group members.",
    "mssp",
    [
      {
        "description": "Both 'cid_group_id' and 'cids' fields are required.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getCIDGroupMembersByV2",
    "GET",
    "/mssp/entities/cid-group-members/v2",
    "Get CID group members by CID Group ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "CID group IDs search for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "deleteCIDGroupMembersV2",
    "DELETE",
    "/mssp/entities/cid-group-members/v2",
    "Delete CID group members. Prevents removal of a cid group a cid group if it is only part of one cid group.",
    "mssp",
    [
      {
        "description": "Both 'cid_group_id' and 'cids' fields are required.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getCIDGroupByIdV1",
    "GET",
    "/mssp/entities/cid-groups/v1",
    "Deprecated : Please use getCIDGroupById. Get CID groups by ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "CID group IDs to be searched on",
        "name": "cid_group_ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createCIDGroups",
    "POST",
    "/mssp/entities/cid-groups/v1",
    "Create new CID groups. Name is a required field but description is an optional field. Maximum 500 CID groups allowed.",
    "mssp",
    [
      {
        "description": "Only 'name' and/or 'description' fields are required. Remaining are assigned by the system.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteCIDGroups",
    "DELETE",
    "/mssp/entities/cid-groups/v1",
    "Delete CID groups by ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "CID group ids to delete",
        "name": "cid_group_ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "updateCIDGroups",
    "PATCH",
    "/mssp/entities/cid-groups/v1",
    "Update existing CID groups. CID group ID is expected for each CID group definition provided in request "
    "body. Name is a required field but description is an optional field. Empty description will override existing "
    "value. CID group member(s) remain unaffected.",
    "mssp",
    [
      {
        "description": "'cid_group_id' field is required to identify the CID group to update along with 'name' "
        "and/or 'description' fields to be updated.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getCIDGroupById",
    "GET",
    "/mssp/entities/cid-groups/v2",
    "Get CID Groups by ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "CID group IDs to search for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getCIDGroupByIdV2",
    "GET",
    "/mssp/entities/cid-groups/v2",
    "Get CID Groups by ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "CID group IDs to search for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getRolesByID",
    "GET",
    "/mssp/entities/mssp-roles/v1",
    "Get link between user group and CID group by ID. Link ID is a string consisting of multiple components, "
    "but should be treated as opaque.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Link ID is a string consisting of multiple components, but should be treated as opaque.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "addRole",
    "POST",
    "/mssp/entities/mssp-roles/v1",
    "Create a link between user group and CID group, with zero or more additional roles. The call does not "
    "replace any existing link between them. User group ID and CID group ID have to be specified in request. ",
    "mssp",
    [
      {
        "description": "'user_group_id', 'cid_group_id' and 'role_ids' fields are required. Remaining are "
        "populated by system.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deletedRoles",
    "DELETE",
    "/mssp/entities/mssp-roles/v1",
    "Delete links or additional roles between user groups and CID groups. User group ID and CID group ID have "
    "to be specified in request. Only specified roles are removed if specified in request payload, else association "
    "between User Group and CID group is dissolved completely (if no roles specified).",
    "mssp",
    [
      {
        "description": "'user_group_id' and 'cid_group_id' fields are required. 'role_ids' field is optional. "
        "Remaining fields are ignored.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getUserGroupMembersByIDV1",
    "GET",
    "/mssp/entities/user-group-members/v1",
    "Deprecated : Please use getUserGroupMembersByID. Get user group members by user group ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "User group IDs to search for",
        "name": "user_group_ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "addUserGroupMembers",
    "POST",
    "/mssp/entities/user-group-members/v1",
    "Add new user group member. Maximum 500 members allowed per user group.",
    "mssp",
    [
      {
        "description": "Both 'user_group_id' and 'user_uuids' fields are required.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteUserGroupMembers",
    "DELETE",
    "/mssp/entities/user-group-members/v1",
    "Delete user group members entry.",
    "mssp",
    [
      {
        "description": "Both 'user_group_id' and 'user_uuids' fields are required.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getUserGroupMembersByID",
    "GET",
    "/mssp/entities/user-group-members/v2",
    "Get user group members by user group ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "User group IDs to search for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getUserGroupMembersByIDV2",
    "GET",
    "/mssp/entities/user-group-members/v2",
    "Get user group members by user group ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "User group IDs to search for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getUserGroupsByIDV1",
    "GET",
    "/mssp/entities/user-groups/v1",
    "Deprecated : Please use getUserGroupsByID. Get user groups by ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "User Group IDs to search for",
        "name": "user_group_ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createUserGroups",
    "POST",
    "/mssp/entities/user-groups/v1",
    "Create new user groups. Name is a required field but description is an optional field. Maximum 500 user "
    "groups allowed per customer.",
    "mssp",
    [
      {
        "description": "Only 'name' and/or 'description' fields are required. Remaining are assigned by the system.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteUserGroups",
    "DELETE",
    "/mssp/entities/user-groups/v1",
    "Delete user groups by ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "User group IDs to delete",
        "name": "user_group_ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "updateUserGroups",
    "PATCH",
    "/mssp/entities/user-groups/v1",
    "Update existing user group(s). User group ID is expected for each user group definition provided in "
    "request body. Name is a required field but description is an optional field. Empty description will override "
    "existing value. User group member(s) remain unaffected.",
    "mssp",
    [
      {
        "description": "'user_group_id' field is required to identify the user group to update along with "
        "'name' and/or 'description' fields to be updated.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getUserGroupsByID",
    "GET",
    "/mssp/entities/user-groups/v2",
    "Get user groups by ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "User group IDs to search for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getUserGroupsByIDV2",
    "GET",
    "/mssp/entities/user-groups/v2",
    "Get user groups by ID.",
    "mssp",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "User group IDs to search for",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queryChildren",
    "GET",
    "/mssp/queries/children/v1",
    "Query for customers linked as children",
    "mssp",
    [
      {
        "type": "string",
        "description": "Filter using a query in Falcon Query Language (FQL). Supported filters: cid",
        "name": "filter",
        "in": "query"
      },
      {
        "enum": [
          "last_modified_timestamp|asc",
          "last_modified_timestamp|desc"
        ],
        "type": "string",
        "default": "last_modified_timestamp|desc",
        "description": "The sort expression used to sort the results",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return ids",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 10,
        "description": "Number of ids to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "queryCIDGroupMembers",
    "GET",
    "/mssp/queries/cid-group-members/v1",
    "Query a CID groups members by associated CID.",
    "mssp",
    [
      {
        "type": "string",
        "description": "CID to lookup associated CID group ID",
        "name": "cid",
        "in": "query",
        "required": True
      },
      {
        "enum": [
          "last_modified_timestamp|asc",
          "last_modified_timestamp|desc"
        ],
        "type": "string",
        "default": "last_modified_timestamp|desc",
        "description": "The sort expression used to sort the results",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return id",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 10,
        "description": "Maximum number of results to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "queryCIDGroups",
    "GET",
    "/mssp/queries/cid-groups/v1",
    "Query CID groups.",
    "mssp",
    [
      {
        "type": "string",
        "description": "Name to lookup groups for",
        "name": "name",
        "in": "query"
      },
      {
        "enum": [
          "last_modified_timestamp|asc",
          "last_modified_timestamp|desc",
          "name|asc",
          "name|desc"
        ],
        "type": "string",
        "default": "name|asc",
        "description": "The sort expression used to sort the results",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return ids",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 10,
        "description": "Maximum number of results to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "queryRoles",
    "GET",
    "/mssp/queries/mssp-roles/v1",
    "Query links between user groups and CID groups. At least one of CID group ID or user group ID should also "
    "be provided. Role ID is optional.",
    "mssp",
    [
      {
        "type": "string",
        "description": "User group ID to fetch MSSP role for",
        "name": "user_group_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "CID group ID to fetch MSSP role for",
        "name": "cid_group_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Role ID to fetch MSSP role for",
        "name": "role_id",
        "in": "query"
      },
      {
        "enum": [
          "last_modified_timestamp|asc",
          "last_modified_timestamp|desc"
        ],
        "type": "string",
        "default": "last_modified_timestamp|desc",
        "description": "The sort expression used to sort the results",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return ids",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 10,
        "description": "Maximum number of results to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "queryUserGroupMembers",
    "GET",
    "/mssp/queries/user-group-members/v1",
    "Query user group member by user UUID.",
    "mssp",
    [
      {
        "type": "string",
        "description": "User UUID to lookup associated user group ID",
        "name": "user_uuid",
        "in": "query",
        "required": True
      },
      {
        "enum": [
          "last_modified_timestamp|asc",
          "last_modified_timestamp|desc"
        ],
        "type": "string",
        "default": "last_modified_timestamp|desc",
        "description": "The sort expression used to sort the results",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return ids",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 10,
        "description": "Number of ids to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "queryUserGroups",
    "GET",
    "/mssp/queries/user-groups/v1",
    "Query user groups.",
    "mssp",
    [
      {
        "type": "string",
        "description": "Name to lookup groups for",
        "name": "name",
        "in": "query"
      },
      {
        "enum": [
          "last_modified_timestamp|asc",
          "last_modified_timestamp|desc",
          "name|asc",
          "name|desc"
        ],
        "type": "string",
        "default": "name|asc",
        "description": "The sort expression used to sort the results",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 0,
        "description": "Starting index of overall result set from which to return ids",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 10,
        "description": "Maximum number of results to return",
        "name": "limit",
        "in": "query"
      }
    ]
  ]
]
