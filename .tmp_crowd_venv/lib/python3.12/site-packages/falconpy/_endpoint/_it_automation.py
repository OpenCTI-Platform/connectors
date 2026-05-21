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
# pylint: disable=C0302

_it_automation_endpoints = [
  [
    "ITAutomationGetAssociatedTasks",
    "GET",
    "/it-automation/combined/associated-tasks/v1",
    "Retrieve tasks associated with the provided file id",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The ID of the file to fetch associated tasks for",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [access_type, created_by, created_time, last_run_time, modified_by, modified_time, name, runs, task_type] "
        "Example: example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[name]. Sort either asc (ascending) or desc (descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationCombinedScheduledTasks",
    "GET",
    "/it-automation/combined/scheduled-tasks/v1",
    "Returns full details of scheduled tasks matching the filter query parameter.",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [created_by, created_time, end_time, is_active, last_run, modified_by, modified_time, start_time, task_id, "
        "task_name, task_type] Example: "
        "example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[created_by, created_time, end_time, last_run, modified_by, modified_time, start_time, task_id, task_name, "
        "task_type]. Sort either asc (ascending) or desc (descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationGetTaskExecutionsByQuery",
    "GET",
    "/it-automation/combined/task-executions/v1",
    "Returns the list of task executions (and their details) matching the filter query parameter. This "
    "endpoint will return the same output as if you ran ITAutomationSearchTaskExecutions and "
    "ITAutomationGetTaskExecution",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [end_time, run_by, run_type, start_time, status, task_id, task_name, task_type] Example: "
        "example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[end_time, run_by, run_type, start_time, status, task_id, task_name, task_type]. Sort either asc (ascending) "
        "or desc (descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationGetTaskGroupsByQuery",
    "GET",
    "/it-automation/combined/task-groups/v1",
    "Returns full details of task groups matching the filter query parameter.",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [access_type, created_by, created_time, modified_by, modified_time, name] Example: "
        "example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[access_type, created_by, created_time, modified_by, modified_time, name]. Sort either asc (ascending) or desc "
        "(descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationGetTasksByQuery",
    "GET",
    "/it-automation/combined/tasks/v1",
    "Returns full details of tasks matching the filter query parameter.",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [access_type, created_by, created_time, last_run_time, modified_by, modified_time, name, runs, task_type] "
        "Example: example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[access_type, created_by, created_time, last_run_time, modified_by, modified_time, name, runs, task_type]. "
        "Sort either asc (ascending) or desc (descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationGetUserGroup",
    "GET",
    "/it-automation/entities/it-user-groups/v1",
    "Returns user groups for each provided id",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Comma separated values of user group ids to fetch",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationCreateUserGroup",
    "POST",
    "/it-automation/entities/it-user-groups/v1",
    "Creates a user group from the given request",
    "it_automation",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationUpdateUserGroup",
    "PATCH",
    "/it-automation/entities/it-user-groups/v1",
    "Update a user group for a given id",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The id of the user groups to update",
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
    "ITAutomationDeleteUserGroup",
    "DELETE",
    "/it-automation/entities/it-user-groups/v1",
    "Deletes user groups for each provided ids",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Comma separated values of user group ids to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationRunLiveQuery",
    "POST",
    "/it-automation/entities/live-query-execution/v1",
    "Starts a new task execution from the provided query data in the request and returns the initiated task executions",
    "it_automation",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationUpdatePolicyHostGroups",
    "PATCH",
    "/it-automation/entities/policies-host-groups/v1",
    "Manage host groups assigned to a policy.",
    "it_automation",
    [
      {
        "description": "Describes the requested policy, host groups, and action",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationUpdatePoliciesPrecedence",
    "PATCH",
    "/it-automation/entities/policies-precedence/v1",
    "Updates the policy precedence for all policies of a specific platform.",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The policy platform for which to set the precedence order, must be one of Windows, Linux or Mac.",
        "name": "platform",
        "in": "query",
        "required": True
      },
      {
        "description": "Precedence of the policies for the provided platform",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationGetPolicies",
    "GET",
    "/it-automation/entities/policies/v1",
    "Retrieves the configuration for 1 or more policies.",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) policy ids in the form of ids=ID1&ids=ID2",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationCreatePolicy",
    "POST",
    "/it-automation/entities/policies/v1",
    "Creates a new policy of the specified type. New policies are always added at the end of the precedence "
    "list for the provided policy type.",
    "it_automation",
    [
      {
        "description": "Create an existing policy.\n\n * name must be between 1 and 100 characters.\n\n * "
        "description can be between 0 and 500 characters.\n\n * platform must be one of Windows, Linux, or Mac\n\n * "
        "config.execution.enable_script_execution enables or disables script execution.\n\n * "
        "config.execution.enable_python_execution enables or disables Python execution.\n\n * "
        "config.execution.enable_os_query enables or disables OS Query.\n\n * config.execution.execution_timeout "
        "specifies the timeout value for executions.\n\n * config.execution.execution_timeout_unit must be one of Hours "
        " or Minutes.\n\n * config.resources.cpu_throttle specifies the CPU throttle value.\n\n * "
        "config.resources.cpu_scheduling sets priority to determine the order in which a query process will run on a "
        "host's CPU.\n\n * config.resources.memory_pressure_level sets memory pressure level to control system resource "
        " allocation during task execution.\n\n * config.resources.memory_allocation specifies the memory allocation "
        "value.\n\n * config.resources.memory_allocation_unit must be one of MB or GB.\n\n * "
        "config.concurrency.concurrent_host_limit specifies the maximum number of concurrent hosts.\n\n * "
        "config.concurrency.concurrent_task_limit specifies the maximum number of concurrent tasks.\n\n * "
        "config.concurrency.concurrent_host_file_transfer_limit specifies the maximum number of concurrent file "
        "transfers.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationUpdatePolicies",
    "PATCH",
    "/it-automation/entities/policies/v1",
    "Updates a new policy of the specified type.",
    "it_automation",
    [
      {
        "description": "Update an existing policy.\n\n * id is required and must be a valid policy ID "
        "representing the policy to be updated.\n\n * name must be between 1 and 100 characters.\n\n * description can "
        "be between 0 and 500 characters.\n\n * is_enabled controls whether the policy is active.\n\n * "
        "config.execution.enable_script_execution enables or disables script execution.\n\n * "
        "config.execution.enable_python_execution enables or disables Python execution.\n\n * "
        "config.execution.enable_os_query enables or disables OS Query.\n\n * config.execution.execution_timeout "
        "specifies the timeout value for executions.\n\n * config.execution.execution_timeout_unit must be one of Hours "
        " or Minutes.\n\n * config.resources.cpu_throttle specifies the CPU throttle value.\n\n * "
        "config.resources.cpu_scheduling sets priority to determine the order in which a query process will run on a "
        "host's CPU.\n\n * config.resources.memory_pressure_level sets memory pressure level to control system resource "
        " allocation during task execution.\n\n * config.resources.memory_allocation specifies the memory allocation "
        "value.\n\n * config.resources.memory_allocation_unit must be one of MB or GB.\n\n * "
        "config.concurrency.concurrent_host_limit specifies the maximum number of concurrent hosts.\n\n * "
        "config.concurrency.concurrent_task_limit specifies the maximum number of concurrent tasks.\n\n * "
        "config.concurrency.concurrent_host_file_transfer_limit specifies the maximum number of concurrent file "
        "transfers.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationDeletePolicy",
    "DELETE",
    "/it-automation/entities/policies/v1",
    "Deletes 1 or more policies.",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "list of task ids to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationGetScheduledTasks",
    "GET",
    "/it-automation/entities/scheduled-tasks/v1",
    "Returns scheduled tasks for each provided id",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Scheduled task IDs to fetch. Use ITAutomationSearchScheduledTasks to fetch scheduled task IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationCreateScheduledTask",
    "POST",
    "/it-automation/entities/scheduled-tasks/v1",
    "Creates a scheduled task from the given request",
    "it_automation",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationUpdateScheduledTask",
    "PATCH",
    "/it-automation/entities/scheduled-tasks/v1",
    "Update an existing scheduled task with the supplied info",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The id of the scheduled task to update",
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
    "ITAutomationDeleteScheduledTasks",
    "DELETE",
    "/it-automation/entities/scheduled-tasks/v1",
    "Delete one or more scheduled tasks by providing the scheduled tasks IDs",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Comma separated values of scheduled task IDs to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationCancelTaskExecution",
    "POST",
    "/it-automation/entities/task-execution-cancel/v1",
    "Cancel a task execution specified in the request",
    "it_automation",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationGetTaskExecutionHostStatus",
    "GET",
    "/it-automation/entities/task-execution-host-status/v1",
    "Get the status of host executions by providing the execution IDs",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Task execution IDs to get statuses for. Use ITAutomationSearchTaskExecutions to fetch execution IDs",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [end_time, start_time, status, total_results] Example: "
        "example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[end_time, start_time, status, total_results]. Sort either asc (ascending) or desc (descending). Example: "
        "example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationRerunTaskExecution",
    "POST",
    "/it-automation/entities/task-execution-rerun/v1",
    "Rerun the task execution specified in the request",
    "it_automation",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationGetExecutionResultsSearchStatus",
    "GET",
    "/it-automation/entities/task-execution-results-search/v1",
    "Get the status of an async task execution results. \n\nLook for `is_pending: False` to know search is complete.",
    "it_automation",
    [
      {
        "type": "string",
        "description": "Search Job ID to fetch. UseITAutomationStartExecutionResultsSearch to get the job id",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationStartExecutionResultsSearch",
    "POST",
    "/it-automation/entities/task-execution-results-search/v1",
    "Starts an async task execution results search. Poll ITAutomationGetExecutionResultsSearchStatus to check "
    "if the search is complete. You must retrieve the results using ITAutomationGetExecutionResults within 30 "
    "seconds of completion, or the job will be deleted.",
    "it_automation",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationGetExecutionResults",
    "GET",
    "/it-automation/entities/task-execution-results/v1",
    "Get the task execution results from an async search.  \n\nUse the ITAutomationStartExecutionResultsSearch "
    " command to start the async search. You can retrieve the results again for up to 24 hours, after which they "
    "will be deleted.",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The Job ID to fetch. Use the value returned from ITAutomationStartExecutionResultsSearch",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "default": 500,
        "description": "The maximum number of event results to return",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort results by one of the fields in the event results, either asc (ascending) or desc "
        "(descending)\n\nFor example, to sort by hostname ascending: hostname.asc",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationGetTaskExecution",
    "GET",
    "/it-automation/entities/task-executions/v1",
    "Get the task execution for the provided task execution IDs",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Task execution IDs to fetch. Use ITAutomationSearchTaskExecutions to get the execution id",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationStartTaskExecution",
    "POST",
    "/it-automation/entities/task-executions/v1",
    "Starts a new task execution from an existing task provided in the request and returns the initiated task executions",
    "it_automation",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationGetTaskGroups",
    "GET",
    "/it-automation/entities/task-groups/v1",
    "Returns task groups for each provided id",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Comma separated values of task group ids to fetch",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationCreateTaskGroup",
    "POST",
    "/it-automation/entities/task-groups/v1",
    "Creates a task group from the given request",
    "it_automation",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationUpdateTaskGroup",
    "PATCH",
    "/it-automation/entities/task-groups/v1",
    "Update a task group for a given id",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The id of the task group to update",
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
    "ITAutomationDeleteTaskGroups",
    "DELETE",
    "/it-automation/entities/task-groups/v1",
    "Delete one or more task groups by providing the task group IDs",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Comma separated values of task group IDs to delete",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationGetTasks",
    "GET",
    "/it-automation/entities/tasks/v1",
    "Returns tasks for each provided ID",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of tasks to fetch. Use ITAutomationSearchTasks to fetch IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationCreateTask",
    "POST",
    "/it-automation/entities/tasks/v1",
    "Creates a task with details from the given request.",
    "it_automation",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationUpdateTask",
    "PATCH",
    "/it-automation/entities/tasks/v1",
    "Update a task with details from the given request.",
    "it_automation",
    [
      {
        "type": "string",
        "description": "ID of the task to update. Use ITAutomationSearchTasks to fetch IDs",
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
    "ITAutomationDeleteTask",
    "DELETE",
    "/it-automation/entities/tasks/v1",
    "Deletes tasks for each provided ID",
    "it_automation",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of tasks to delete. Use ITAutomationSearchTasks to fetch IDs",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationSearchUserGroup",
    "GET",
    "/it-automation/queries/it-user-groups/v1",
    "Returns the list of user group ids matching the filter query parameter. It can be used together with the "
    "entities endpoint to retrieve full information on user groups",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [created_by, created_time, description, modified_by, modified_time, name] Example: "
        "example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[created_by, created_time, modified_by, modified_time, name]. Sort either asc (ascending) or desc "
        "(descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationQueryPolicies",
    "GET",
    "/it-automation/queries/policies/v1",
    "Returns the list of policy ids matching the filter query parameter.",
    "it_automation",
    [
      {
        "minimum": 0,
        "type": "integer",
        "description": "The offset to start retrieving records from. Defaults to 0 if not specified.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of ids to return. Defaults to 100 if not specified. The maximum "
        "number of results that can be returned in a single call is 500.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort the returned ids based on one of the following properties:\n\nprecedence, "
        "created_timestamp or modified_timestamp\n\n Sort either asc (ascending) or desc (descending);  for example: "
        "precedence|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "enum": [
          "Windows",
          "Mac",
          "Linux"
        ],
        "type": "string",
        "description": "The platform of policies to retrieve",
        "name": "platform",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ITAutomationSearchScheduledTasks",
    "GET",
    "/it-automation/queries/scheduled-tasks/v1",
    "Returns the list of scheduled task IDs matching the filter query parameter",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [created_by, created_time, end_time, is_active, last_run, modified_by, modified_time, start_time, task_id, "
        "task_name, task_type] Example: "
        "example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[created_by, created_time, end_time, last_run, modified_by, modified_time, start_time, task_id, task_name, "
        "task_type]. Sort either asc (ascending) or desc (descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationSearchTaskExecutions",
    "GET",
    "/it-automation/queries/task-executions/v1",
    "Returns the list of task execution IDs matching the filter query parameter. Can be used together with the "
    "entities endpoint to retrieve full information on executions",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [end_time, run_by, run_type, start_time, status, task_id, task_name, task_type] Example: "
        "example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[end_time, run_by, run_type, start_time, status, task_id, task_name, task_type]. Sort either asc (ascending) "
        "or desc (descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationSearchTaskGroups",
    "GET",
    "/it-automation/queries/task-groups/v1",
    "Returns the list of task group ids matching the filter query parameter",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [access_type, created_by, created_time, modified_by, modified_time, name] Example: "
        "example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[access_type, created_by, created_time, modified_by, modified_time, name]. Sort either asc (ascending) or desc "
        "(descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ],
  [
    "ITAutomationSearchTasks",
    "GET",
    "/it-automation/queries/tasks/v1",
    "Returns the list of task IDs matching the filter query parameter.",
    "it_automation",
    [
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Allowed filter fields: "
        " [access_type, created_by, created_time, last_run_time, modified_by, modified_time, name, runs, task_type] "
        "Example: example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results. Allowed sort fields: "
        "[access_type, created_by, created_time, last_run_time, modified_by, modified_time, name, runs, task_type]. "
        "Sort either asc (ascending) or desc (descending). Example: example_field|asc",
        "name": "sort",
        "in": "query"
      },
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "Starting index for record retrieval. Example: 100",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
        "default": 100,
        "description": "The maximum records to return. Example: 50",
        "name": "limit",
        "in": "query"
      }
    ]
  ]
]
