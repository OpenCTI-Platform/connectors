"""Internal payload handling library - Host Group Payloads.

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
from typing import Dict, List


def host_group_create_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, str]]]:
    """Create a properly formatted payload for host group operations.

    Create operations are supported. `id` and `group_type`
    values should be added by the calling method after creating this payload.
    {
        "resources": [
            {
                "assignment_rule": "string",
                "description": "string",
                "group_type": "string",
                "name": "string"
            }
        ]
    }
    """
    returned_payload: Dict[str, List[Dict[str, str]]] = {}
    returned_payload["resources"] = []
    host_group_item = {}
    if passed_keywords.get("assignment_rule", None):
        host_group_item["assignment_rule"] = passed_keywords.get("assignment_rule", None)
    if passed_keywords.get("description", None):
        host_group_item["description"] = passed_keywords.get("description", None)
    if passed_keywords.get("group_type", None):
        host_group_item["group_type"] = passed_keywords.get("group_type", None)
    if passed_keywords.get("name", None):
        host_group_item["name"] = passed_keywords.get("name", None)
    if host_group_item:
        returned_payload["resources"].append(host_group_item)

    return returned_payload


def host_group_update_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, str]]]:
    """Create a properly formatted payload for host group operations.

    Update operations are supported. `id` and `group_type`
    values should be added by the calling method after creating this payload.
    {
        "resources": [
            {
                "assignment_rule": "string",
                "description": "string",
                "id": "string",
                "name": "string"
            }
        ]
    }
    """
    returned_payload: Dict[str, List[Dict[str, str]]] = {}
    returned_payload["resources"] = []
    host_group_item = {}
    if passed_keywords.get("assignment_rule", None):
        host_group_item["assignment_rule"] = passed_keywords.get("assignment_rule", None)
    if passed_keywords.get("description", None):
        host_group_item["description"] = passed_keywords.get("description", None)
    if passed_keywords.get("id", None):
        host_group_item["id"] = passed_keywords.get("id", None)
    if passed_keywords.get("name", None):
        host_group_item["name"] = passed_keywords.get("name", None)
    if host_group_item:
        returned_payload["resources"].append(host_group_item)

    return returned_payload
