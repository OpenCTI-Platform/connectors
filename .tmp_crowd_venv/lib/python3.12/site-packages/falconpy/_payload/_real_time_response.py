"""Internal payload handling library - Real Time Response.

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


def command_payload(passed_keywords: dict) -> dict:  # pylint: disable=R0912  # noqa: C901
    """Create a properly formatted payload for RTR command.

    {
        "base_command": "string",
        "batch_id": "string",
        "command_string": "string",
        "optional_hosts": [
            "string"
        ],
        "file_path": "string",
        "persist_all": true,
        "existing_batch_id": "string",
        "host_ids": [
            "string"
        ],
        "queue_offline": true,
        "hosts_to_remove": [
            "string"
        ]
        "device_id": "string",
        "id": integer,
        "persist": boolean,
        "session_id": "string",
        "origin": "string"
    }
    """
    # flake8 / pylint both complain about complexity due to the number of if statements.
    # Ignoring the complaint as this is just running through the potential passed keywords.
    returned_payload = {}

    keys = [
        "base_command", "batch_id", "command_string", "file_path",
        "existing_batch_id", "device_id", "session_id", "origin"
        ]
    for key in keys:
        if passed_keywords.get(key, None):
            returned_payload[key] = passed_keywords.get(key, None)

    bool_keys = ["persist_all", "queue_offline", "persist"]
    for boolean in bool_keys:
        if passed_keywords.get(boolean, None) is not None:
            returned_payload[boolean] = passed_keywords.get(boolean, None)

    if passed_keywords.get("id", -1) > -1:
        returned_payload["id"] = passed_keywords.get("id", None)

    list_keys = ["optional_hosts", "host_ids", "hosts_to_remove"]
    for list_key in list_keys:
        passed_list = passed_keywords.get(list_key, None)
        if passed_list:
            if isinstance(passed_list, str):
                passed_list = passed_list.split(",")
            returned_payload[list_key] = passed_list

    return returned_payload


def data_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted formData payload for RTR file uploads.

    {
        "id": "string",
        "description": "string",
        "name": "string",
        "comments_for_audit_log": "string",
        "content": "string",
        "platform": "string",
        "permission_type": "string"
    }
    """
    returned_payload = {}
    keys = [
        "id", "description", "name", "comments_for_audit_log",
        "content", "platform", "permission_type"
        ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload
