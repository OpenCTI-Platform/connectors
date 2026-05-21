"""Internal payload handling library - Generic Payloads.

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


def workflow_deprovision_payload(passed_keywords: dict):
    """Create a valid workflow deprovisioning payload from provided keywords.

    {
        "definition_id": "string",
        "deprovision_all": boolean,
        "template_id": "string",
        "template_name": "string"
    }
    """
    returned_payload = {}
    keys = ["definition_id", "template_id", "deprovision_all", "template_name"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key)

    return returned_payload


def workflow_template_payload(passed_keywords: dict):
    """Create a properly formatted workflow template payload.

    {
        "customer_definition_id": "string",
        "name": "string",
        "parameters": {
            "activities": {
                "configuration": [
                    {
                        "node_id": "string",
                        "properties": {}
                    }
                ],
                "selection": [
                    {
                        "id": "string",
                        "properties": {},
                        "source": "string"
                    }
                ]
            },
            "conditions": [
                {
                    "fields": [
                        {
                            "name": "string",
                            "operator": "string"
                        }
                    ],
                    "node_id": "string"
                }
            ],
            "trigger": {
                "fields": {
                    "additionalProp1": {
                        "properties": {},
                        "required": true
                    },
                    "additionalProp2": {
                        "properties": {},
                        "required": true
                    },
                    "additionalProp3": {
                        "properties": {},
                        "required": true
                    }
                },
                "node_id": "string"
            }
        },
        "template_id": "string",
        "template_name": "string",
        "template_version": "string"
    }
    """
    returned_payload = {}
    keys = ["customer_definition_id", "name", "parameters",
            "template_id", "template_name", "template_version"
            ]

    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key)

    # Providing a parameters dictionary will override the activities, conditions & trigger branches
    if "parameters" not in returned_payload:
        param_branch = {}
        for key in ["activities", "conditions", "trigger"]:
            if passed_keywords.get(key, None) is not None:
                param_branch[key] = passed_keywords.get(key)
        if param_branch:
            returned_payload["parameters"] = param_branch

    return returned_payload


def workflow_definition_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted workflow definition payload.

    {
        "Definition": {},
        "change_log": "string",
        "enabled": true,
        "flight_control": {
            "all_cids": true,
            "excluded_cids": [
                "string"
            ],
            "include_parent_cid": true,
            "selected_cids": [
                "string"
            ]
        },
        "id": "string"
    }
    """
    returned_payload = {}
    keys = ["definition", "change_log", "enabled", "flight_control", "id"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            keystr = "Definition" if key == "definition" else key
            returned_payload[keystr] = passed_keywords.get(key, None)

    return returned_payload


def workflow_human_input(passed_keywords: dict) -> dict:
    """Craft a properly formatted human input payload.

    {
        "input": "string",
        "note": "string"
    }
    """
    returned_payload = {}
    keys = ["input", "note"]
    for key in keys:
        if passed_keywords.get(key, None):
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload


def workflow_mock_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted mock execution payload.

    {
        "definition" {
            Workflow schema
        },
        "mocks": "string",
        "on_demand_trigger": "string"
    }
    """
    returned_payload = {}
    keys = ["definition", "mocks", "on_demand_trigger"]
    for key in keys:
        if passed_keywords.get(key, None):
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload
