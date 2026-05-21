"""Internal payload handling library - Falcon Flight Control (MSSP).

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


def mssp_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted Flight Control payload.

    {
        "resources": [
            {
                "cid": "string",
                "cid_group_id": "string",
                "description": "string",
                "name": "string"
                "id": "string",
                "role_ids": [
                    "string"
                ],
                "user_group_id": "string"
            }
        ]
    }
    """
    returned_payload = {}
    resources_item = {}
    keys = [
        "cid", "cid_group_id", "description", "name", "id",
        "user_group_id", "user_uuids"
        ]
    for key in keys:
        if passed_keywords.get(key, None):
            resources_item[key] = passed_keywords.get(key, None)

    passed_role_ids = passed_keywords.get("role_ids", None)
    if passed_role_ids:
        if isinstance(passed_role_ids, str):
            passed_role_ids = passed_role_ids.split(",")
        resources_item["role_ids"] = passed_role_ids

    if resources_item:
        returned_payload["resources"] = [resources_item]

    return returned_payload
