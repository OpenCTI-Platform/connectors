"""Internal payload handling library - IT Automation.

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


def task_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted task or task group create or update payload.

    {
        "access_type": "Public",
        "add_assigned_user_group_ids": [
            "string"
        ],
        "add_assigned_user_ids": [
            "string"
        ],
        "add_task_ids": [
            "string"
        ],
        "assigned_user_group_ids": [
            "string"
        ],
        "assigned_user_ids": [
            "string"
        ],
        "description": "string",
        "name": "string",
        "os_query": "string",
        "output_parser_config": {
            "columns": [
                {
                    "name": "string"
                }
            ],
            "default_group_by": boolean,
            "delimiter": "string"
        },
        "queries": {
            "linux": {
                "action_type": "script",
                "args": "string",
                "content": "string",
                "file_ids": [
                    "string"
                ],
                "language": "bash",
                "script_file_id": "string"
            },
            "mac": {
                "action_type": "script",
                "args": "string",
                "content": "string",
                "file_ids": [
                    "string"
                ],
                "language": "bash",
                "script_file_id": "string"
            },
            "windows": {
                "action_type": "script",
                "args": "string",
                "content": "string",
                "file_ids": [
                    "string"
                ],
                "language": "bash",
                "script_file_id": "string"
            }
        },
        "remediations": {
            "linux": {
                "action_type": "script",
                "args": "string",
                "content": "string",
                "file_ids": [
                    "string"
                ],
                "language": "bash",
                "script_file_id": "string"
            },
            "mac": {
                "action_type": "script",
                "args": "string",
                "content": "string",
                "file_ids": [
                    "string"
                ],
                "language": "bash",
                "script_file_id": "string"
            },
            "windows": {
                "action_type": "script",
                "args": "string",
                "content": "string",
                "file_ids": [
                    "string"
                ],
                "language": "bash",
                "script_file_id": "string"
            }
        },
        "remove_assigned_user_group_ids": [
            "string"
        ],
        "remove_assigned_user_ids": [
            "string"
        ],
        "remove_task_ids": [
            "string"
        ],
        "target": "string",
        "task_ids": [
            "string"
        ],
        "task_group_id": "string",
        "task_parameters": [
            {
                "custom_validation_message": "string",
                "custom_validation_regex": "string",
                "default_value": "string",
                "input_type": "text",
                "key": "string",
                "label": "string",
                "options": [
                    {
                        "key": "string",
                        "value": "string"
                    }
                ],
                "validation_type": "text"
            }
        ],
        "task_type": "query",
        "trigger_condition": [
            {
                "groups": [
                    null
                ],
                "operator": "AND",
                "statements": [
                    {
                        "data_comparator": "LessThan",
                        "data_type": "StringType",
                        "key": "string",
                        "task_id": "string",
                        "value": "string"
                    }
                ]
            }
        ],
        "verification_condition": [
            {
                "groups": [
                    null
                ],
                "operator": "AND",
                "statements": [
                    {
                        "data_comparator": "LessThan",
                        "data_type": "StringType",
                        "key": "string",
                        "task_id": "string",
                        "value": "string"
                    }
                ]
            }
        ]
    }
    """
    returned_payload = {}
    keys = ["access_type", "add_assigned_user_group_ids", "add_assigned_user_ids", "description",
            "name", "os_query", "output_parser_config", "task_parameters", "queries",
            "remediations", "removed_assigned_user_group_ids", "remove_assigned_user_ids",
            "target", "task_group_id", "trigger_condition", "task_type", "verification_condition"
            ]
    list_keys = ["add_assigned_user_group_ids", "add_assigned_user_ids", "add_task_ids",
                 "removed_assigned_user_group_ids", "removed_assigned_user_ids", "remove_task_ids",
                 "assigned_user_group_ids", "assigned_user_ids", "task_ids"
                 ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            key_value = passed_keywords.get(key, None)
            if key in list_keys and isinstance(key_value, str):
                key_value = key_value.split(",")
            returned_payload[key] = key_value

    return returned_payload


def task_execution_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted task execution payload.

    {
        "arguments": {
            "additionalProp1": "string",
            "additionalProp2": "string",
            "additionalProp3": "string"
        },
        "discover_new_hosts": boolean,
        "discover_offline_hosts": boolean,
        "distribute": boolean,
        "expiration_interval": "string",
        "guardrails": {
            "run_time_limit_millis": 0
        },
        "target": "string",
        "task_id": "string",
        "trigger_condition": [
            {
                "groups": [
                    null
                ],
                "operator": "AND",
                "statements": [
                    {
                        "data_comparator": "LessThan",
                        "data_type": "StringType",
                        "key": "string",
                        "task_id": "string",
                        "value": "string"
                    }
                ]
            }
        ]
    }
    """
    returned_payload = {}
    keys = ["arguments", "discover_new_hosts", "discover_offline_hosts", "distribute",
            "expiration_interval", "guardrails", "target", "task_id", "trigger_condition"
            ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload


def execution_results_search_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted execution results search payload.

    {
        "end": "string",
        "filter_expressions": [
            "string"
        ],
        "group_by_fields": [
            "string"
        ],
        "start": "string",
        "task_execution_id": "string"
    }
    """
    returned_payload = {}
    keys = ["end", "filter_expressions", "group_by_fields", "start", "task_execution_id"]
    list_keys = ["filter_expressions", "group_by_fields"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            key_value = passed_keywords.get(key, None)
            if key in list_keys and isinstance(key_value, str):
                key_value = key_value.split(",")
            returned_payload[key] = key_value

    return returned_payload


def rerun_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted rerun task payload.

    {
        "run_type": "string",
        "task_execution_id": "string"
    }
    """
    returned_payload = {}
    keys = ["run_type", "task_execution_id"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload


def scheduled_task_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted scheduled task payload.

    {
        "discover_new_hosts": boolean,
        "discover_offline_hosts": boolean,
        "distribute": boolean,
        "expiration_interval": "string",
        "execution_args": {
            "additionalProp1": "string",
            "additionalProp2": "string",
            "additionalProp3": "string"
        },
        "guardrails": {
            "run_time_limit_millis": 0
        },
        "is_active": boolean,
        "schedule": {
            "day_of_month": 0,
            "days_of_week": [
                "string"
            ],
            "end_time": "2025-07-13T13:39:00.637Z",
            "frequency": "One-Time",
            "interval": 0,
            "start_time": "2025-07-13T13:39:00.637Z",
            "time": "string",
            "timezone": "string"
        },
        "target": "string",
        "task_id": "string",
        "trigger_condition": [
            {
                "groups": [
                    null
                ],
                "operator": "AND",
                "statements": [
                    {
                        "data_comparator": "LessThan",
                        "data_type": "StringType",
                        "key": "string",
                        "task_id": "string",
                        "value": "string"
                    }
                ]
            }
        ]
    }
    """
    returned_payload = {}
    keys = ["execution_args", "discover_new_hosts", "discover_offline_hosts", "distribute",
            "expiration_interval", "guardrails", "is_active", "schedule", "target", "task_id",
            "trigger_condition"
            ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload


def automation_policy_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted automation policy payload.

    {
        "config": {
            "concurrency": {
                "concurrent_host_file_transfer_limit": 0,
                "concurrent_host_limit": 0,
                "concurrent_task_limit": 0
            },
            "execution": {
                "enable_os_query": boolean,
                "enable_python_execution": boolean,
                "enable_script_execution": boolean,
                "execution_timeout": 0,
                "execution_timeout_unit": "string"
            },
            "resources": {
                "cpu_scheduling": "string",
                "cpu_throttle": 0,
                "memory_allocation": 0,
                "memory_allocation_unit": "string",
                "memory_pressure_level": "string"
            }
        },
        "description": "string",
        "id": "string",
        "is_enabled": boolean,
        "name": "string",
        "platform": "string"
    }
    """
    returned_payload = {}
    keys = ["config", "description", "id", "is_enabled", "name", "platform"]
    branch_keys = ["concurrency", "execution", "resources"]
    branches = {
        "concurrency": ["concurrent_host_file_transfer_limit", "concurrent_host_limit",
                        "concurrent_task_limit"
                        ],
        "execution": ["enable_os_query", "enable_python_execution", "enable_script_execution",
                      "execution_timeout", "execution_timeout_unit"
                      ],
        "resources": ["cpu_scheduling", "cpu_throttle", "memory_allocation", "memory_allocation_unit",
                      "memory_pressure_level"
                      ]
        }
    keys.extend(branch_keys)
    for _, value_list in branches.items():
        keys.extend(value_list)
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            key_value = None
            for branch_key, branch_list in branches.items():
                if key in branch_list:
                    key_value = passed_keywords.get(key, None)
                    if branch_key not in returned_payload:
                        returned_payload[branch_key] = {}
                    returned_payload[branch_key][key] = key_value
            if not key_value:
                returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload


def policy_host_group_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted policy host group payload.

    {
        "action": "string",
        "host_group_ids": [
            "string"
        ],
        "policy_id": "string"
    }
    """
    returned_payload = {}
    keys = ["action", "host_group_ids", "policy_id"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            key_value = passed_keywords.get(key, None)
            if key == "host_group_ids" and isinstance(key_value, str):
                key_value = key_value.split(",")
            returned_payload[key] = key_value

    return returned_payload


def automation_user_group_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted user group payload.

    {
        "add_user_ids": [
            "string"
        ],
        "description": "string",
        "name": "string",
        "remove_user_ids": [
            "string"
        ]
    }
    """
    returned_payload = {}
    keys = ["add_user_ids", "description", "name", "remove_user_ids"]
    list_keys = ["add_user_ids", "remove_user_ids"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            key_value = passed_keywords.get(key, None)
            if key in list_keys and isinstance(key_value, str):
                key_value = key_value.split(",")
            returned_payload[key] = key_value

    return returned_payload


def automation_live_query_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted live query payload.

    {
        "discover_new_hosts": boolean,
        "discover_offline_hosts": boolean,
        "distribute": boolean,
        "expiration_interval": "string",
        "guardrails": {
            "run_time_limit_millis": 0
        },
        "osquery": "string",
        "output_parser_config": {
            "columns": [
                {
                    "name": "string"
                }
            ],
            "default_group_by": boolean,
            "delimiter": "string"
        },
        "queries": {
            "linux": {
                "action_type": "script",
                "args": "string",
                "content": "string",
                "file_ids": [
                    "string"
                ],
                "language": "bash",
                "script_file_id": "string"
            },
            "mac": {
                "action_type": "script",
                "args": "string",
                "content": "string",
                "file_ids": [
                    "string"
                ],
                "language": "bash",
                "script_file_id": "string"
            },
                "windows": {
                "action_type": "script",
                "args": "string",
                "content": "string",
                "file_ids": [
                    "string"
                ],
                "language": "bash",
                "script_file_id": "string"
            }
        },
        "target": "string"
    }
    """
    returned_payload = {}
    keys = ["discover_new_hosts", "discover_offline_hosts", "distribute", "expiration_interval",
            "guardrails", "osquery", "output_parser_config", "queries", "target"
            ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload
