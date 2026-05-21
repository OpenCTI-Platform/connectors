"""Internal payload handling library - IOA Payloads.

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


def ioa_exclusion_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted exclusion payload.

    {
        "cl_regex": "string",
        "comment": "string",
        "description": "string",
        "detection_json": "string",
        "groups": [
            "string"
        ],
        "ifn_regex": "string",
        "name": "string",
        "pattern_id": "string",
        "pattern_name": "string"
    }
    """
    returned_payload = {}

    keys = [
        "cl_regex", "comment", "description", "detection_json",
        "ifn_regex", "name", "pattern_id", "pattern_name"
        ]
    for key in keys:
        if passed_keywords.get(key, None):
            returned_payload[key] = passed_keywords.get(key, None)

    passed_list = passed_keywords.get("groups", None)
    if passed_list:
        if isinstance(passed_list, str):
            passed_list = passed_list.split(",")
        returned_payload["groups"] = passed_list

    return returned_payload


def ioa_custom_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted custom IOA payload.

    {
        "comment": "string",
        "description": "string",
        "name": "string",
        "platform": "string",
        "enabled": true,
        "id": "string",
        "rulegroup_version": 0,
        "disposition_id": 0,
        "field_values": [
            {
                "final_value": "string",
                "label": "string",
                "name": "string",
                "type": "string",
                "value": "string",
                "values": [
                    {
                        "label": "string",
                        "value": "string"
                    }
                ]
            }
        ],
        "pattern_severity": "string",
        "rulegroup_id": "string",
        "ruletype_id": "string",
        "rule_updates": [
            {
                "description": "string",
                "disposition_id": 0,
                "enabled": true,
                "field_values": [
                    {
                        "final_value": "string",
                        "label": "string",
                        "name": "string",
                        "type": "string",
                        "value": "string",
                        "values": [
                            {
                                "label": "string",
                                "value": "string"
                            }
                        ]
                    }
                ],
                "instance_id": "string",
                "name": "string",
                "pattern_severity": "string",
                "rulegroup_version": 0
            }
        ]
    }
    """
    returned_payload = {}
    keys = [
        "comment", "description", "name", "platform", "id", "pattern_severity",
        "rulegroup_id", "ruletype_id"
        ]
    for key in keys:
        if passed_keywords.get(key, None):
            returned_payload[key] = passed_keywords.get(key, None)

    if passed_keywords.get("enabled", None) is not None:
        returned_payload["enabled"] = passed_keywords.get("enabled", None)
    if passed_keywords.get("rulegroup_version", -1) >= 0:
        returned_payload["rulegroup_version"] = passed_keywords.get("rulegroup_version", None)
    if passed_keywords.get("disposition_id", -1) >= 0:
        returned_payload["disposition_id"] = passed_keywords.get("disposition_id", None)
    if passed_keywords.get("field_values", None):
        field_values = passed_keywords.get("field_values")
        if isinstance(field_values, dict):  # Issue 916
            returned_payload["field_values"] = [field_values]
        else:
            returned_payload["field_values"] = field_values
    if passed_keywords.get("rule_updates", None):
        rule_updates = passed_keywords.get("rule_updates")
        if isinstance(rule_updates, dict):  # Issue 916
            returned_payload["rule_updates"] = [rule_updates]
        else:
            returned_payload["rule_updates"] = rule_updates

    return returned_payload
