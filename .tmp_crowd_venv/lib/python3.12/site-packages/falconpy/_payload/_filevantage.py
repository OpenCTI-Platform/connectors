"""Internal payload handling library - Falcon X Sandbox.

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


def filevantage_rule_group_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted FileVantage rule group body payload.

    {
        "description": "string",
        "id": "string",
        "name": "string",
        "type": "string"
    }
    """
    returned = {}
    keys = ["description", "id", "name", "type"]
    for key in keys:
        if passed_keywords.get(key, None):
            returned[key] = passed_keywords.get(key, None)

    return returned


def filevantage_policy_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted FileVantage policy body payload.

    {
        "description": "string",
        "id": "string",
        "name": "string",
        "platform": "string",
        "enabled": boolean
    }
    """
    returned = {}
    keys = ["description", "id", "name", "platform"]
    for key in keys:
        if passed_keywords.get(key, None):
            returned[key] = passed_keywords.get(key, None)

    if passed_keywords.get("enabled", None) is not None:
        returned[key] = passed_keywords.get("enabled", None)

    return returned


def filevantage_start_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted FileVantage policy body payload.

    {
        "change_ids": [
            "string"
        ],
        "comment": "string",
        "operation": "string"
    }
    """
    returned = {}
    keys = ["change_ids", "comment", "operation"]
    for key in keys:
        if passed_keywords.get(key, None):
            if key == "change_ids":
                changes = passed_keywords.get(key, None)
                if isinstance(changes, str):
                    changes = changes.split(",")
                returned[key] = changes
            else:
                returned[key] = passed_keywords.get(key, None)

    return returned


def filevantage_scheduled_exclusion_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted FileVantage scheduled exclusion body payload.

    {
        "description": "string",
        "name": "string",
        "policy_id": "string",
        "processes": "string",
        "repeated": {
            "all_day": boolean,
            "end_time": "string",
            "frequency": "string",
            "monthly_days": [
                integer
            ],
            "occurrence": "string",
            "start_time": "string",
            "weekly_days": [
                "string"
            ]
        },
        "schedule_end": "string",
        "schedule_start": "string",
        "timezone": "string",
        "users": "string"
    }
    """
    returned = {}
    keys = ["description", "id", "name", "policy_id", "processes",
            "schedule_end", "schedule_start", "users", "timezone", "repeated"
            ]
    for key in keys:
        if passed_keywords.get(key, None):
            returned[key] = passed_keywords.get(key, None)

    return returned


def filevantage_rule_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted FileVantage rule body payload.

    {
        "created_timestamp": "string",
        "depth": "string",
        "description": "string",
        "exclude": "string",
        "exclude_processes": "string",
        "exclude_users": "string",
        "id": "string",
        "include": "string",
        "include_processes": "string",
        "include_users": "string",
        "content_files": "string",
        "content_registry_values": "string",
        "enable_content_capture": boolean,
        "enable_hash_capture": boolean,
        "modified_timestamp": "string",
        "path": "string",
        "precedence": integer,
        "rule_group_id": "string",
        "severity": "string",
        "type": "string",
        "watch_attributes_directory_changes": boolean,
        "watch_attributes_file_changes": boolean,
        "watch_create_directory_changes": boolean,
        "watch_create_file_changes": boolean,
        "watch_create_key_changes": boolean,
        "watch_delete_directory_changes": boolean,
        "watch_delete_file_changes": boolean,
        "watch_delete_key_changes": boolean,
        "watch_delete_value_changes": boolean,
        "watch_permissions_directory_changes": boolean,
        "watch_permissions_file_changes": boolean,
        "watch_rename_directory_changes": boolean,
        "watch_rename_file_changes": boolean,
        "watch_rename_key_changes": boolean,
        "watch_set_value_changes": boolean,
        "watch_write_file_changes": boolean
    }
    """
    returned = {}
    keys = ["created_timestamp", "depth", "description", "exclude", "exclude_processes",
            "exclude_users", "id", "include", "include_processes", "include_users",
            "modified_timestamp", "path", "rule_group_id", "severity", "type",
            "content_files", "content_registry_values"
            ]
    bool_int_keys = ["watch_attributes_directory_changes", "watch_attributes_file_changes",
                     "watch_create_directory_changes", "watch_create_file_changes",
                     "watch_create_key_changes", "watch_delete_directory_changes",
                     "watch_delete_file_changes", "watch_delete_key_changes",
                     "watch_delete_value_changes", "watch_permissions_directory_changes",
                     "watch_permissions_file_changes", "watch_rename_directory_changes",
                     "watch_rename_file_changes", "watch_rename_key_changes",
                     "watch_set_value_changes", "watch_write_file_changes", "precedence",
                     "enable_content_capture", "enable_hash_capture"
                     ]
    for key in keys:
        if passed_keywords.get(key, None):
            returned[key] = passed_keywords.get(key, None)
    for key in bool_int_keys:
        if passed_keywords.get(key, None) is not None:
            returned[key] = passed_keywords.get(key, None)

    return returned
