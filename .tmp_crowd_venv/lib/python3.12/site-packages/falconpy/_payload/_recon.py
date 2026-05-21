"""Internal payload handling library - Recon.

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
from typing import List, Dict


def handle_recon_rule_params(inbound: dict) -> dict:
    """Handle the payload formatting for a single rule object."""
    returned_dict = {}
    keys = ["filter", "id", "name", "permissions", "priority", "topic"]
    bool_keys = ["breach_monitoring_enabled", "substring_matching_enabled"]
    for key in keys:
        if inbound.get(key, None):
            returned_dict[key] = inbound.get(key, None)
    for key in bool_keys:
        if inbound.get(key, None) is not None:
            returned_dict[key] = inbound.get(key, None)

    return returned_dict


def recon_rules_payload(passed_keywords: dict) -> List[Dict[str, str]]:
    """Create a properly formatted payload for recon rule handling.

    Creates a list of dictionaries.
    [
        {
            "breach_monitoring_enabled": true,
            "filter": "string",
            "id": "string",
            "name": "string",
            "permissions": "string",
            "priority": "string",
            "substring_matching_enabled": true,
            "topic": "string"
        }
    ]
    """
    returned_rules = []
    provided_rules = passed_keywords.get("rules", None)
    if provided_rules:
        # Not entirely sure why you wouldn't just pass the body
        if isinstance(provided_rules, list):
            for rule in passed_keywords.get("rules", None):
                returned_rules.append(handle_recon_rule_params(rule))
        else:
            # Fall back to a single rule
            returned_rules.append(handle_recon_rule_params(passed_keywords))
    else:
        # Only one rule was provided, use the keywords
        returned_rules.append(handle_recon_rule_params(passed_keywords))

    return returned_rules


def recon_notifications_payload(passed_keywords: dict) -> List[Dict[str, str]]:
    """Recon notification payload handler.

    Creates a properly formatted payload for a recon notification
    payload. Generates a list of dictionaries, but is designed to handle
    just one notification. (For multiple notifications use the body
    payload keyword.)
    [
        {
            "assigned_to_uuid": "string",
            "id": "string",
            "status": "string"
        }
    ]
    """
    returned_payload = []
    notification = {}
    if passed_keywords.get("assigned_to_uuid", None):
        notification["assigned_to_uuid"] = passed_keywords.get("assigned_to_uuid", None)
    if passed_keywords.get("id", None):
        notification["id"] = passed_keywords.get("id", None)
    if passed_keywords.get("status", None):
        notification["status"] = passed_keywords.get("status", None)

    returned_payload.append(notification)

    return returned_payload


def recon_action_update_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted payload for handling recon actions.

    {
        "content_format": "string",
        "frequency": "string",
        "id": "string",
        "recipients": [
            "string"
        ],
        "trigger_matchless": true,
        "status": "string"
    }
    """
    returned_payload = {}
    keys = ["content_format", "frequency", "id", "status"]
    for key in keys:
        if passed_keywords.get(key, None):
            returned_payload[key] = passed_keywords.get(key, None)

    recip_list = passed_keywords.get("recipients", None)
    if recip_list:
        if isinstance(recip_list, str):
            recip_list = recip_list.split(",")
        returned_payload["recipients"] = recip_list

    if passed_keywords.get("trigger_matchless", None) is not None:
        returned_payload["trigger_matchless"] = passed_keywords.get("trigger_matchless", None)

    return returned_payload


def recon_action_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted payload for attaching recon actions to a monitoring rule.

    {
        "actions": [
            {
                "content_format": "string",
                "frequency": "string",
                "recipients": [
                    "string"
                ],
                "trigger_matchless": true,
                "type": "string"
            }
        ],
        "rule_id": "string"
    }
    """
    returned_payload = {}
    returned_payload["rule_id"] = passed_keywords.get("rule_id", None)
    if passed_keywords.get("actions", None):
        returned_payload["actions"] = passed_keywords.get("actions", None)
    else:
        keys = ["content_format", "frequency", "type"]
        action = {}
        for key in keys:
            if passed_keywords.get(key, None):
                action[key] = passed_keywords.get(key, None)
        recip_list = passed_keywords.get("recipients", None)
        if recip_list:
            if isinstance(recip_list, str):
                recip_list = recip_list.split(",")
            action["recipients"] = recip_list

        if passed_keywords.get("trigger_matchless", None) is not None:
            action["trigger_matchless"] = passed_keywords.get("trigger_matchless", None)
        returned_payload["actions"] = []
        returned_payload["actions"].append(action)

    return returned_payload


def recon_rule_preview_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted payload for retrieving a rule preview from recon.

    {
        "filter": "string",
        "topic": "string"
    }
    """
    returned_payload = {}
    if passed_keywords.get("filter", None):
        returned_payload["filter"] = passed_keywords.get("filter", None)
    if passed_keywords.get("topic", None):
        returned_payload["topic"] = passed_keywords.get("topic", None)

    return returned_payload


def recon_export_job_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted export job creation payload.

    [
        {
            "entity": "string",
            "export_type": "string",
            "filter": "string",
            "human_readable": true,
            "sort": "string"
        }
    ]
    """
    returned_payload = []
    keys = ["entity", "export_type", "filter", "human_readable", "sort"]
    _job = {}
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            _job[key] = passed_keywords.get(key)
    if _job:
        returned_payload.append(_job)

    return returned_payload
