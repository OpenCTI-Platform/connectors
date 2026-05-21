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

_workflows_endpoints = [
  [
    "WorkflowActivitiesCombined",
    "GET",
    "/workflows/combined/activities/v1",
    "Search for activities by name. Returns all supported activities if no filter specified",
    "workflows",
    [
      {
        "type": "string",
        "description": "FQL query specifying filter parameters.",
        "name": "filter",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "string",
        "description": "Starting pagination offset of records to return.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Maximum number of records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "pattern": "^\\w+(\\.asc|\\.desc)?(,\\w+(\\.asc|\\.desc)?)*$",
        "type": "string",
        "description": "Sort items by providing a comma separated list of property and direction (eg "
        "name.desc,time.asc). If direction is omitted, defaults to descending.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "WorkflowActivitiesContentCombined",
    "GET",
    "/workflows/combined/activity-content/v1",
    "Search for activities by name. Returns all supported activities if no filter specified",
    "workflows",
    [
      {
        "type": "string",
        "description": "FQL query specifying filter parameters.",
        "name": "filter",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "string",
        "description": "Starting pagination offset of records to return.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Maximum number of records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "pattern": "^\\w+(\\.asc|\\.desc)?(,\\w+(\\.asc|\\.desc)?)*$",
        "type": "string",
        "description": "Sort items by providing a comma separated list of property and direction (eg "
        "name.desc,time.asc). If direction is omitted, defaults to descending.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "WorkflowDefinitionsCombined",
    "GET",
    "/workflows/combined/definitions/v1",
    "Search workflow definitions based on the provided filter. NOTE: this API has a large response payload. "
    "Click on `Wait` if the page is unresponsive during loading",
    "workflows",
    [
      {
        "type": "string",
        "description": "FQL query specifying filter parameters.",
        "name": "filter",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "string",
        "description": "Starting pagination offset of records to return.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Maximum number of records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "pattern": "^\\w+(\\.asc|\\.desc)?(,\\w+(\\.asc|\\.desc)?)*$",
        "type": "string",
        "description": "Sort items by providing a comma separated list of property and direction (eg "
        "name.desc,time.asc). If direction is omitted, defaults to descending.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "WorkflowExecutionsCombined",
    "GET",
    "/workflows/combined/executions/v1",
    "Search workflow executions based on the provided filter",
    "workflows",
    [
      {
        "type": "string",
        "description": "FQL query specifying filter parameters.",
        "name": "filter",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "string",
        "description": "Starting pagination offset of records to return.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Maximum number of records to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "pattern": "^\\w+(\\.asc|\\.desc)?(,\\w+(\\.asc|\\.desc)?)*$",
        "type": "string",
        "description": "Sort items by providing a comma separated list of property and direction (eg "
        "name.desc,time.asc). If direction is omitted, defaults to descending.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "WorkflowTriggersCombined",
    "GET",
    "/workflows/combined/triggers/v1",
    "Search for triggers by namespaced identifier, i.e. FalconAudit, Detection, or "
    "FalconAudit/Detection/Status. Returns all triggers if no filter specified",
    "workflows",
    [
      {
        "type": "string",
        "description": "FQL query specifying filter parameters.",
        "name": "filter",
        "in": "query",
        "allowEmptyValue": True
      }
    ]
  ],
  [
    "WorkflowDefinitionsAction",
    "POST",
    "/workflows/entities/definition-actions/v1",
    "Enable or disable a workflow definition, or stop all executions for a definition. When a definition is "
    "disabled it will not execute against any new trigger events.",
    "workflows",
    [
      {
        "type": "string",
        "description": "Specify one of these actions:\n  enable: enable the workflow(s) specified in ids.  "
        "disable: disable the workflow(s) specified in ids.  cancel: cancel all in-flight executions for the workflow "
        "specified in ids",
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
    "WorkflowDefinitionsExport",
    "GET",
    "/workflows/entities/definitions/export/v1",
    "Exports a workflow definition for the given definition ID",
    "workflows",
    [
      {
        "maxLength": 40,
        "minLength": 32,
        "type": "string",
        "description": "ID of workflow definitions to return details for",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "boolean",
        "default": True,
        "description": "whether or not to sanitize PII from workflow before it's exported",
        "name": "sanitize",
        "in": "query"
      }
    ]
  ],
  [
    "WorkflowDefinitionsImport",
    "POST",
    "/workflows/entities/definitions/import/v1",
    "Imports a workflow definition based on the provided model",
    "workflows",
    [
      {
        "type": "file",
        "x-mimetype": "application/yaml",
        "description": "A workflow definition in YAML format to import",
        "name": "data_file",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "Workflow name to override",
        "name": "name",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "When enabled, prevents saving workflow after validating",
        "name": "validate_only",
        "in": "query"
      }
    ]
  ],
  [
    "WorkflowDefinitionsUpdate",
    "PUT",
    "/workflows/entities/definitions/v1",
    "Updates a workflow definition based on the provided model",
    "workflows",
    [
      {
        "type": "boolean",
        "default": False,
        "description": "When enabled, prevents saving workflow after validating",
        "name": "validate_only",
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
    "WorkflowExecuteInternal",
    "POST",
    "/workflows/entities/execute/internal/v1",
    "Executes an on-demand Workflow - internal workflows permitted, the body is JSON used to trigger the "
    "execution, the response the execution ID(s)",
    "workflows",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "CID(s) to execute on. This can be a child if this is a flight control enabled "
        "definition. If unset the definition CID is used.",
        "name": "execution_cid",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Definition ID to execute, either a name or an ID can be specified.",
        "name": "definition_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Workflow name to execute, either a name or an ID can be specified.",
        "name": "name",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Key used to help deduplicate executions, if unset a new UUID is used",
        "name": "key",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Used to record the execution depth to help limit execution loops when a workflow "
        "triggers another. The maximum depth is 4.",
        "name": "depth",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Used to set the batchSize, if unset the default batchSize is used",
        "name": "batch_size",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Used to record a URL to the source that led to triggering this workflow",
        "name": "source_event_url",
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
    "WorkflowExecute",
    "POST",
    "/workflows/entities/execute/v1",
    "Executes an on-demand Workflow, the body is JSON used to trigger the execution, the response the execution ID(s)",
    "workflows",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "CID(s) to execute on. This can be a child if this is a flight control enabled "
        "definition. If unset the definition CID is used.",
        "name": "execution_cid",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Definition ID to execute, either a name or an ID can be specified.",
        "name": "definition_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Workflow name to execute, either a name or an ID can be specified.",
        "name": "name",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Key used to help deduplicate executions, if unset a new UUID is used",
        "name": "key",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Used to record the execution depth to help limit execution loops when a workflow "
        "triggers another. The maximum depth is 4.",
        "name": "depth",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Used to record a URL to the source that led to triggering this workflow",
        "name": "source_event_url",
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
    "WorkflowExecutionsAction",
    "POST",
    "/workflows/entities/execution-actions/v1",
    "Allows a user to resume/retry a failed workflow execution, or cancel/stop a currently running workflow execution",
    "workflows",
    [
      {
        "enum": [
          "resume",
          "cancel"
        ],
        "type": "string",
        "description": "Specify one of these actions:\n  resume: resume/retry the workflow execution(s) "
        "specified in ids\n  cancel: cancel/stop the workflow execution specified in ids",
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
    "WorkflowExecutionResults",
    "GET",
    "/workflows/entities/execution-results/v1",
    "Get execution result of a given execution",
    "workflows",
    [
      {
        "maxItems": 500,
        "minItems": 1,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "workflow execution id to return results for.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "WorkflowGetHumanInputV1",
    "GET",
    "/workflows/entities/human-inputs/v1",
    "Gets one or more specific human inputs by their IDs.",
    "workflows",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "IDs of human inputs to read",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "WorkflowUpdateHumanInputV1",
    "PATCH",
    "/workflows/entities/human-inputs/v1",
    "Provides an input in response to a human input action. Depending on action configuration, one or more of "
    "Approve, Decline, and/or Escalate are permitted.",
    "workflows",
    [
      {
        "maxLength": 32,
        "minLength": 32,
        "type": "string",
        "description": "ID of human input to provide an input to",
        "name": "id",
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
    "WorkflowMockExecute",
    "POST",
    "/workflows/entities/mock-executions/v1",
    "Executes a workflow definition with mocks",
    "workflows",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "CID(s) to execute on. This can be a child if this is a flight control enabled "
        "definition. If unset the definition CID is used.",
        "name": "execution_cid",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Definition ID to execute, either a name or an ID, or the definition itself in the "
        "request body, can be specified.",
        "name": "definition_id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Workflow name to execute, either a name or an ID, or the definition itself in the "
        "request body, can be specified.",
        "name": "name",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Key used to help deduplicate executions, if unset a new UUID is used",
        "name": "key",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Used to record the execution depth to help limit execution loops when a workflow "
        "triggers another. The maximum depth is 4.",
        "name": "depth",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Used to record a URL to the source that led to triggering this workflow",
        "name": "source_event_url",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "When enabled, prevents execution after validating mocks from the request body against "
        "the mocked entity's output schema. Mocks provided in the definition by reference are not validated in any "
        "case.",
        "name": "validate_only",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "When enabled, skips validating mocks from the request body against the mocked entity's "
        "output schema. Mocks provided in the definition by reference are not validated in any case.",
        "name": "skip_validation",
        "in": "query"
      },
      {
        "type": "boolean",
        "default": False,
        "description": "When enabled, treats all activity mocks in the definition as disabled for this mock "
        "execution. Mocks provided in the request body are treated normally.",
        "name": "ignore_activity_mock_references",
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
    "WorkflowSystemDefinitionsDeProvision",
    "POST",
    "/workflows/system-definitions/deprovision/v1",
    "Deprovisions a system definition that was previously provisioned on the target CID",
    "workflows",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "WorkflowSystemDefinitionsPromote",
    "POST",
    "/workflows/system-definitions/promote/v1",
    "Promotes a version of a system definition for a customer. The customer must already have been "
    "provisioned. This allows the caller to apply an updated template version to a specific cid and expects all "
    "parameters to be supplied. If the template supports multi-instance the customer scope definition ID must be "
    "supplied to determine which customer workflow should be updated.",
    "workflows",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "WorkflowSystemDefinitionsProvision",
    "POST",
    "/workflows/system-definitions/provision/v1",
    "Provisions a system definition onto the target CID by using the template and provided parameters",
    "workflows",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
