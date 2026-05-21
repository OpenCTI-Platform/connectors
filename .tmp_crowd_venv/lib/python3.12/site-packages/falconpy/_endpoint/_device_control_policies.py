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

_device_control_policies_endpoints = [
  [
    "queryCombinedDeviceControlPolicyMembers",
    "GET",
    "/policy/combined/device-control-members/v1",
    "Search for members of a Device Control Policy in your environment by providing an FQL filter and paging "
    "details. Returns a set of host details which match the filter criteria",
    "device_control_policies",
    [
      {
        "type": "string",
        "description": "The ID of the Device Control Policy to search for members of",
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
    "queryCombinedDeviceControlPolicies",
    "GET",
    "/policy/combined/device-control/v1",
    "Search for Device Control Policies in your environment by providing an FQL filter and paging details. "
    "Returns a set of Device Control Policies which match the filter criteria",
    "device_control_policies",
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
    "getDefaultDeviceControlPolicies",
    "GET",
    "/policy/entities/default-device-control/v1",
    "Retrieve the configuration for a Default Device Control Policy",
    "device_control_policies",
    []
  ],
  [
    "updateDefaultDeviceControlPolicies",
    "PATCH",
    "/policy/entities/default-device-control/v1",
    "Update the configuration for a Default Device Control Policy",
    "device_control_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "performDeviceControlPoliciesAction",
    "POST",
    "/policy/entities/device-control-actions/v1",
    "Perform the specified action on the Device Control Policies specified in the request",
    "device_control_policies",
    [
      {
        "enum": [
          "add-host-group",
          "add-rule-group",
          "disable",
          "enable",
          "remove-host-group",
          "remove-rule-group"
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
    "patchDeviceControlPoliciesClassesV1",
    "PATCH",
    "/policy/entities/device-control-classes/v1",
    "Update device control policy's classes (USB and Bluetooth)",
    "device_control_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getDefaultDeviceControlSettings",
    "GET",
    "/policy/entities/device-control-default-settings/v1",
    "Get default device control settings (USB and Bluetooth)",
    "device_control_policies",
    []
  ],
  [
    "updateDefaultDeviceControlSettings",
    "PATCH",
    "/policy/entities/device-control-default-settings/v1",
    "Update the configuration for Default Device Control Settings",
    "device_control_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "setDeviceControlPoliciesPrecedence",
    "POST",
    "/policy/entities/device-control-precedence/v1",
    "Sets the precedence of Device Control Policies based on the order of IDs specified in the request. The "
    "first ID specified will have the highest precedence and the last ID specified will have the lowest. You must "
    "specify all non-Default Policies for a platform when updating precedence",
    "device_control_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getDeviceControlPolicies",
    "GET",
    "/policy/entities/device-control/v1",
    "Retrieve a set of Device Control Policies by specifying their IDs",
    "device_control_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the Device Control Policies to return",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createDeviceControlPolicies",
    "POST",
    "/policy/entities/device-control/v1",
    "Create Device Control Policies by specifying details about the policy to create",
    "device_control_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updateDeviceControlPolicies",
    "PATCH",
    "/policy/entities/device-control/v1",
    "Update Device Control Policies by specifying the ID of the policy and details to update",
    "device_control_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteDeviceControlPolicies",
    "DELETE",
    "/policy/entities/device-control/v1",
    "Delete a set of Device Control Policies by specifying their IDs",
    "device_control_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the Device Control Policies to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getDeviceControlPoliciesV2",
    "GET",
    "/policy/entities/device-control/v2",
    "Get device control policies for the given filter criteria. (USB and Bluetooth)",
    "device_control_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the policies to get",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "postDeviceControlPoliciesV2",
    "POST",
    "/policy/entities/device-control/v2",
    "Create/clone a device control policy (USB and Bluetooth)",
    "device_control_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "patchDeviceControlPoliciesV2",
    "PATCH",
    "/policy/entities/device-control/v2",
    "Update device control policy base (USB and Bluetooth)",
    "device_control_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "queryDeviceControlPolicyMembers",
    "GET",
    "/policy/queries/device-control-members/v1",
    "Search for members of a Device Control Policy in your environment by providing an FQL filter and paging "
    "details. Returns a set of Agent IDs which match the filter criteria",
    "device_control_policies",
    [
      {
        "type": "string",
        "description": "The ID of the Device Control Policy to search for members of",
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
    "queryDeviceControlPolicies",
    "GET",
    "/policy/queries/device-control/v1",
    "Search for Device Control Policies in your environment by providing an FQL filter and paging details. "
    "Returns a set of Device Control Policy IDs which match the filter criteria",
    "device_control_policies",
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
