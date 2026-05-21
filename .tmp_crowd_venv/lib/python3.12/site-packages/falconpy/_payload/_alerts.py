"""Internal payload handling library - Alerts.

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


def update_alerts_payload(current_payload: dict,
                          passed_keywords: dict
                          ) -> Dict[str, List[Dict[str, Union[str, int, bool, Dict]]]]:
    """Update the provided payload with any viable parameters provided as keywords.

    {
        "ids": [
            "string"
        ],
        "request": {
            "action_parameters": [
                {
                    "name": "string",
                    "value": "string"
                }
            ]
        }
    }
    """
    keys = ["remove_tag", "assign_to_user_id", "unassign", "new_behavior_processed",
            "update_status", "assign_to_uuid", "add_tag", "remove_tags_by_prefix",
            "append_comment", "assign_to_name", "show_in_ui"]
    act_params = []
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            param = {}
            param["name"] = key
            param["value"] = passed_keywords.get(key, None)
            act_params.append(param)

    current_payload["action_parameters"] = act_params

    return current_payload


def combined_alerts_payload(passed_keywords: dict) -> Dict[str, List[Dict[str, Union[str, int, bool, Dict]]]]:
    """Craft a properly formatted alerts combined search payload.

    {
        "after": "string",
        "filter": "string",
        "limit": integer,
        "sort": "string"
    }
    """
    returned = {}
    keys = ["after", "filter", "limit", "sort"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned[key] = passed_keywords.get(key, None)

    return returned
