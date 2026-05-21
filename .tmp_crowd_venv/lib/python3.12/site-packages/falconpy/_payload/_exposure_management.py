"""Internal payload handling library - Exposure Management.

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


def fem_asset_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted exposure management asset update payload.

    {
        "assets": [
            {
                "cid": "string",
                "criticality": "string",
                "criticality_description": "string",
                "id": "string",
                "triage": {
                    "action": "string",
                    "assigned_to": "string",
                    "description": "string",
                    "status": "string"
                }
            }
        ]
    }
    """
    returned = {
        "assets": []
    }
    keys = ["cid", "criticality", "criticality_description", "id",
            "action", "assigned_to", "description", "status"
            ]
    triage_keys = ["action", "assigned_to", "description", "status"]
    item = {}
    for key in keys:
        if passed_keywords.get(key, None):
            if key in triage_keys:
                if "triage" not in item:
                    item["triage"] = {}
                item["triage"][key] = passed_keywords.get(key, None)
            else:
                item[key] = passed_keywords.get(key, None)
    returned["assets"].append(item)

    return returned


def fem_add_asset_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted add asset payload.

    {
        "data": [
            {
                "assets": [
                    {
                        "id": "string",
                        "value": "string"
                    }
                ],
                "subsidiary_id": "string"
            }
        ]
    }
    """
    returned = {}
    returned["data"] = []
    item = {}
    item["assets"] = []
    asset_item = {}
    keys = ["assets", "id", "value", "subsidiary_id"]
    for key in keys:
        if passed_keywords.get(key, None):
            if key in ["id", "value"]:
                asset_item[key] = passed_keywords.get(key, None)
            else:
                item[key] = passed_keywords.get(key, None)
    if asset_item:
        item["assets"].append(asset_item)
    if item:
        returned["data"].append(item)

    return returned
