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

_sensor_update_policies_endpoints = [
  [
    "revealUninstallToken",
    "POST",
    "/policy/combined/reveal-uninstall-token/v1",
    "Reveals an uninstall token for a specific device. To retrieve the bulk maintenance token pass the value "
    "'MAINTENANCE' as the value for 'device_id'",
    "sensor_update_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "queryCombinedSensorUpdateBuilds",
    "GET",
    "/policy/combined/sensor-update-builds/v1",
    "Retrieve available builds for use with Sensor Update Policies",
    "sensor_update_policies",
    [
      {
        "enum": [
          "windows",
          "mac",
          "linux",
          "linuxarm64",
          "zlinux"
        ],
        "type": "string",
        "description": "The platform to return builds for",
        "name": "platform",
        "in": "query"
      },
      {
        "enum": [
          "prod",
          "early_adopter"
        ],
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The stages to return builds for",
        "name": "stage",
        "in": "query"
      }
    ]
  ],
  [
    "queryCombinedSensorUpdateKernels",
    "GET",
    "/policy/combined/sensor-update-kernels/v1",
    "Retrieve kernel compatibility info for Sensor Update Builds",
    "sensor_update_policies",
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
        "maximum": 500,
        "minimum": 1,
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "queryCombinedSensorUpdatePolicyMembers",
    "GET",
    "/policy/combined/sensor-update-members/v1",
    "Search for members of a Sensor Update Policy in your environment by providing an FQL filter and paging "
    "details. Returns a set of host details which match the filter criteria",
    "sensor_update_policies",
    [
      {
        "type": "string",
        "description": "The ID of the Sensor Update Policy to search for members of",
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
    "queryCombinedSensorUpdatePolicies",
    "GET",
    "/policy/combined/sensor-update/v1",
    "Search for Sensor Update Policies in your environment by providing an FQL filter and paging details. "
    "Returns a set of Sensor Update Policies which match the filter criteria",
    "sensor_update_policies",
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
    "queryCombinedSensorUpdatePoliciesV2",
    "GET",
    "/policy/combined/sensor-update/v2",
    "Search for Sensor Update Policies with additional support for uninstall protection in your environment by "
    " providing an FQL filter and paging details. Returns a set of Sensor Update Policies which match the filter "
    "criteria",
    "sensor_update_policies",
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
    "performSensorUpdatePoliciesAction",
    "POST",
    "/policy/entities/sensor-update-actions/v1",
    "Perform the specified action on the Sensor Update Policies specified in the request",
    "sensor_update_policies",
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
    "setSensorUpdatePoliciesPrecedence",
    "POST",
    "/policy/entities/sensor-update-precedence/v1",
    "Sets the precedence of Sensor Update Policies based on the order of IDs specified in the request. The "
    "first ID specified will have the highest precedence and the last ID specified will have the lowest. You must "
    "specify all non-Default Policies for a platform when updating precedence",
    "sensor_update_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getSensorUpdatePolicies",
    "GET",
    "/policy/entities/sensor-update/v1",
    "Retrieve a set of Sensor Update Policies by specifying their IDs",
    "sensor_update_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the Sensor Update Policies to return",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createSensorUpdatePolicies",
    "POST",
    "/policy/entities/sensor-update/v1",
    "Create Sensor Update Policies by specifying details about the policy to create",
    "sensor_update_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updateSensorUpdatePolicies",
    "PATCH",
    "/policy/entities/sensor-update/v1",
    "Update Sensor Update Policies by specifying the ID of the policy and details to update",
    "sensor_update_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteSensorUpdatePolicies",
    "DELETE",
    "/policy/entities/sensor-update/v1",
    "Delete a set of Sensor Update Policies by specifying their IDs",
    "sensor_update_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the Sensor Update Policies to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getSensorUpdatePoliciesV2",
    "GET",
    "/policy/entities/sensor-update/v2",
    "Retrieve a set of Sensor Update Policies with additional support for uninstall protection by specifying their IDs",
    "sensor_update_policies",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the Sensor Update Policies to return",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createSensorUpdatePoliciesV2",
    "POST",
    "/policy/entities/sensor-update/v2",
    "Create Sensor Update Policies by specifying details about the policy to create with additional support "
    "for uninstall protection",
    "sensor_update_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updateSensorUpdatePoliciesV2",
    "PATCH",
    "/policy/entities/sensor-update/v2",
    "Update Sensor Update Policies by specifying the ID of the policy and details to update with additional "
    "support for uninstall protection",
    "sensor_update_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "querySensorUpdateKernelsDistinct",
    "GET",
    "/policy/queries/sensor-update-kernels/{}/v1",
    "Retrieve kernel compatibility info for Sensor Update Builds",
    "sensor_update_policies",
    [
      {
        "type": "string",
        "description": "The field name to get distinct values for",
        "name": "distinct-field",
        "in": "path",
        "required": True
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
        "maximum": 500,
        "minimum": 1,
        "type": "integer",
        "description": "The maximum records to return. [1-500]",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "querySensorUpdatePolicyMembers",
    "GET",
    "/policy/queries/sensor-update-members/v1",
    "Search for members of a Sensor Update Policy in your environment by providing an FQL filter and paging "
    "details. Returns a set of Agent IDs which match the filter criteria",
    "sensor_update_policies",
    [
      {
        "type": "string",
        "description": "The ID of the Sensor Update Policy to search for members of",
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
    "querySensorUpdatePolicies",
    "GET",
    "/policy/queries/sensor-update/v1",
    "Search for Sensor Update Policies in your environment by providing an FQL filter and paging details. "
    "Returns a set of Sensor Update Policy IDs which match the filter criteria",
    "sensor_update_policies",
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
