"""Internal payload handling library - Cloud Policies.

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


def cloud_policies_rule_assign_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Assign rules to a compliance control (full replace).

    {
        "rule_ids": [
            "string"
        ]
    }
    """
    returned_payload = {}
    if passed_keywords.get("rule_ids", None) is not None:
        returned_payload["rule_ids"] = passed_keywords.get("rule_ids", None)
    return returned_payload


def cloud_policies_compliance_control_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Body payload generator for compliance control operations.

    {
        "active": boolean,
        "description": "string",
        "framework_id": "string",
        "name": "string",
        "section_name": "string"
    }
    """
    returned_payload = {}
    keys = ["active", "description", "framework_id", "name", "section_name"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)
    return returned_payload


def cloud_policies_evaluation_payload(passed_keywords: dict) -> Dict[str, Union[dict, str]]:
    """Get evaluation results based on the provided rule.

    {
        "input": {},
        "logic": "string"
    }
    """
    returned_payload = {}
    keys = ["input", "logic"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)
    return returned_payload


def cloud_policies_rule_override_payload(passed_keywords: dict) -> Dict[str, Union[dict, str]]:
    """Create a new rule override.

    {
        "overrides": [
            {
                "comment": "string",
                "crn": "string",
                "expires_at": "2025-11-10T21:16:14.315Z",
                "override_type": "string",
                "overrides_details": "string",
                "reason": "string",
                "rule_id": "string",
                "target_region": "string"
            }
        ]
    }
    """
    returned_payload = {}
    if passed_keywords.get("overrides", None):
        provided = passed_keywords.get("overrides", None)
        if isinstance(provided, dict):
            provided = [provided]
        returned_payload["overrides"] = provided

    return returned_payload


def cloud_policies_rule_create_payload(passed_keywords: dict) -> Dict[str, Union[dict, str]]:
    """Create a new rule.

    {
        "alert_info": "string",
        "attack_types": "string",
        "controls": [
            {
                "Authority": "string",
                "Code": "string"
            }
        ],
        "description": "string",
        "domain": "string",
        "logic": "string",
        "name": "string",
        "parent_rule_id": "string",
        "platform": "string",
        "provider": "string",
        "remediation_info": "string",
        "remediation_url": "string",
        "resource_type": "string",
        "severity": 0,
        "subdomain": "string"
    }
    """
    returned_payload = {}
    if passed_keywords.get("controls", None) is not None:
        returned_payload["controls"] = passed_keywords.get("controls", None)
    control = {}
    control_keys = ["Authority", "Code"]
    for key in control_keys:
        if passed_keywords.get(key, None) is not None:
            control[key] = passed_keywords.get(key, None)
    returned_payload["controls"] = [control]
    keys = ["alert_info", "attack_types", "description", "domain", "logic",
            "name", "parent_rule_id", "platform", "provider", "remediation_info",
            "remediation_url", "resource_type", "severity", "subdomain"
            ]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)

    return returned_payload


def cloud_policies_rule_update_payload(passed_keywords: dict) -> Dict[str, Union[dict, str, int, list]]:
    """Update a rule.

    {
        "alert_info": "string",
        "attack_types": [
                "string"
        ],
        "category": "string",
        "controls": [
            {
                "authority": "string",
                "code": "string"
            }
        ],
        "description": "string",
        "name": "string",
        "rule_logic_list": [
            {
                "logic": "string",
                "platform": "string",
                "remediation_info": "string",
                "remediation_url": "string"
            }
        ],
        "severity": 0,
        "uuid": "string"
    }
    """
    returned_payload = {}

    simple_keys = ["alert_info", "category", "description", "name", "severity", "uuid", "rule_logic_list"]
    for key in simple_keys:
        if passed_keywords.get(key, None) is not None:
            provided = passed_keywords.get(key, None)
            if provided == "rule_logic_list" and isinstance(provided, dict):
                provided = [provided]
            returned_payload[key] = provided

    if passed_keywords.get("attack_types", None) is not None:
        returned_payload["attack_types"] = passed_keywords.get("attack_types", None)

    if passed_keywords.get("controls", None) is not None:
        returned_payload["controls"] = passed_keywords.get("controls", None)
    else:
        control = {}
        control_keys = ["authority", "code"]
        for key in control_keys:
            if passed_keywords.get(key, None) is not None:
                control[key] = passed_keywords.get(key, None)
        if control:
            returned_payload["controls"] = [control]

    return returned_payload
