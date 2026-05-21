"""Internal payload handling library - Content Update Policy Payloads.

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


def content_update_policy_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted content update policy payload.

    {
        "resources": [
            {
                "description": "string",
                "name": "string",
                "id": "string",
                "settings": {
                    "ring_assignment_settings": [
                        {
                            "delay_hours": "string",
                            "id": "string",
                            "ring_assignment": "string"
                        }
                    ]
                }
            }
        ]
    }
    """
    returned_payload = {}
    resources = []
    item = {}
    keys = ["description", "name", "settings", "id"]
    for key in keys:
        if passed_keywords.get(key, None):
            item[key] = passed_keywords.get(key, None)

    resources.append(item)
    returned_payload["resources"] = resources

    return returned_payload


def content_update_policy_action_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int]]]]:
    """Craft a properly formatted content update policy action payload.

    {
        "action_parameters": [
            {
                "name": "string",
                "value": "string"
            }
        ],
        "ids": [
            "string"
        ]
    }
    """
    returned = {}
    for key in ["action_parameters", "ids"]:
        if passed_keywords.get(key, None):
            provided = passed_keywords.get(key, None)
            if key == "ids" and isinstance(provided, str):
                provided = provided.split(",")
            if key == "action_parameters" and isinstance(provided, dict):
                provided = [provided]
            returned[key] = provided

    return returned
