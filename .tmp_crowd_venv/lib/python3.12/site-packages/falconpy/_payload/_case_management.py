"""Internal payload handling library - Case Management.

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

from typing import Dict, List, Union


def case_management_notification_groups_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Get notification groups aggregations.

    [
        {
            "date_ranges": [
            {
                "from": "string",
                "to": "string"
            }
            ],
            "field": "string",
            "filter": "string",
            "from": 0,
            "name": "string",
            "size": 0,
            "sort": "string",
            "type": "terms"
        }
    ]
    """
    body = {}
    returned_payload = []

    body_keys = ["field", "filter", "from", "name", "size", "sort", "type", "date_ranges"]
    for key in body_keys:
        if passed_keywords.get(key, None) is not None:
            provided = passed_keywords.get(key, None)
            if key == "date_ranges" and isinstance(provided, dict):
                provided = [provided]
            body[key] = provided

    returned_payload.append(body)

    return returned_payload


def case_management_create_notification_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Create notification group.

    {
        "channels": [
            {
            "config_id": "string",
            "config_name": "string",
            "recipients": [
                "string"
            ],
            "severity": "string",
            "type": "email"
            }
        ],
        "description": "string",
        "name": "string",
        "id": "string"
        }
    """
    returned_payload = {}

    keys = ["description", "name", "id", "channels"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            provided = passed_keywords.get(key, None)
            if key == "channels" and isinstance(provided, dict):
                provided = [provided]
            returned_payload[key] = provided

    return returned_payload


def case_management_sla_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Create SLA.

    {
        "description": "string",
        "goals": [
            {
            "duration_seconds": 0,
            "escalation_policy": {
                "steps": [
                {
                    "escalate_after_seconds": 0,
                    "notification_group_id": "string"
                }
                ]
            },
            "type": "string"
            }
        ],
        "name": "string"
    }
    """
    returned_payload = {}

    keys = ["description", "name", "id", "goals"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            provided = passed_keywords.get(key, None)
            if key == "goals" and isinstance(provided, dict):
                provided = [provided]
            returned_payload[key] = provided

    return returned_payload


def case_management_template_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Craft a properly formatted template payload.

    {
        "description": "string",
        "fields": [
            {
            "data_type": "string",
            "default_value": "string",
            "id"
            "input_type": "string",
            "multivalued": true,
            "name": "string",
            "options": [
                {
                "id": "string"
                "value": "string"
                }
            ],
            "required": true
            }
        ],
        "id": "string"
        "name": "string",
        "sla_id": "string"
    }
    """
    returned_payload = {}

    keys = ["description", "name", "sla_id", "id", "fields"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            provided = passed_keywords.get(key, None)
            if key == "fields" and isinstance(provided, dict):
                provided = [provided]
            returned_payload[key] = provided
    return returned_payload


def specified_case_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Specify case payload handler.

    {
        "alerts": [
            {
            "id": "string"
            }
        ],
        "tags": [
            "string"
        ],
        "id": "string"
    }
    """
    returned_payload = {}
    keys = ["alerts", "id", "tags"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            provided = passed_keywords.get(key, None)
            if key == "alerts" and isinstance(provided, dict):
                provided = [provided]
            returned_payload[key] = provided

    return returned_payload


def case_manage_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Case manage payload handler.

    {
        "assigned_to_user_uuid": "string",
        "description": "string",
        "evidence": {
            "alerts": [
            {
                "id": "string"
            }
            ],
            "events": [
            {
                "id": "string"
            }
            ],
            "leads": [
            {
                "id": "string"
            }
            ]
        },
        "name": "string",
        "severity": 0,
        "status": "string",
        "tags": [
            "string"
        ],
        "template": {
            "id": "string"
        }
    }
    """
    returned_payload = {}

    keys = ["assigned_to_user_uuid", "description",
            "evidence", "name",
            "severity", "status",
            "tags", "template"
            ]

    for key in keys:
        if passed_keywords.get(key, None) is not None:
            provided = passed_keywords.get(key, None)
            returned_payload[key] = provided

    return returned_payload


def update_case_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Update case payload handler.

    {
        "expected_consistency_version": 0,
        "expected_version": 0,
        "fields": {
            "assigned_to_user_uuid": "string",
            "custom_fields": [
            {
                "id": "string",
                "values": [
                "string"
                ]
            }
            ],
            "description": "string",
            "name": "string",
            "remove_user_assignment": true,
            "severity": 0,
            "slas_active": true,
            "status": "string",
            "template": {
            "id": "string"
            }
        },
        "id": "string"
    }
    """
    returned_payload = {}

    keys = ["expected_consistency_version", "expected_version", "fields", "id"]

    for key in keys:
        if passed_keywords.get(key, None) is not None:
            provided = passed_keywords.get(key, None)
            returned_payload[key] = provided

    return returned_payload


def case_evidence_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Case evidence payload handler.

    {
        "events": [
            {
            "id": "string"
            }
        ],
        "id": "string"
    }
    """
    returned_payload = {}

    keys = ["events", "id"]

    for key in keys:
        if passed_keywords.get(key, None) is not None:
            provided = passed_keywords.get(key, None)
            returned_payload[key] = provided

    return returned_payload
