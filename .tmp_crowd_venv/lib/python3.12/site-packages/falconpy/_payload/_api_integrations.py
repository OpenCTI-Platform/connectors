"""Internal payload handling library - API Integrations.

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


def api_plugin_command_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted plugin execution command payload.

    {
        "resources": [
            {
            "config_auth_type": "string",
            "config_id": "string",
            "definition_id": "string",
            "id": "string",
            "operation_id": "string",
            "request": {
                "data": "string",
                "description": "string",
                "params": {
                    "cookie": {},
                    "header": {},
                    "path": {},
                    "query": {}
                },
                "x-www-form-urlencoded": {}
            },
            "version": integer
            }
        ]
    }
    """
    returned = {}
    returned["resources"] = []
    item = {}
    keys = ["config_auth_type", "config_id", "definition_id", "id", "operation_id",
            "description", "version"
            ]
    for key in keys:
        if passed_keywords.get(key, None):
            if key == "description":
                item["request"] = {"description": passed_keywords.get(key)}
            else:
                item[key] = passed_keywords.get(key)

    # Request
    rkeys = ["data", "description", "params"]
    ritem = {}
    for key in rkeys:
        if passed_keywords.get(key, None):
            ritem[key] = passed_keywords.get(key)

    # Request params
    rpkeys = ["cookie", "header", "path", "query"]
    for key in rpkeys:
        if passed_keywords.get(key, None):
            if "param" not in ritem:
                ritem["params"] = {}
            ritem["params"][key] = passed_keywords.get(key)
    if ritem:
        item["request"] = ritem

    returned["resources"].append(item)

    return returned
