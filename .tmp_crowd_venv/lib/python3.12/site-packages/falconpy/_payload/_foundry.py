"""Internal payload handling library - Foundry Payloads.

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


def foundry_dynamic_search_payload(passed_keywords: dict):
    """Create a properly formatted dynamic execute search payload.

    {
        "end": "string",
        "repo_or_view": "string",
        "search_query": "string",
        "search_query_args": {},
        "start": "string"
    }
    """
    returned_payload = {}
    keys = ["end", "repo_or_view", "search_query", "search_query_args", "start"]
    for key in keys:
        if passed_keywords.get(key, None):
            returned_payload[key] = passed_keywords.get(key)

    return returned_payload


def foundry_execute_search_payload(passed_keywords: dict):
    """Create a properly formatted saved search execute payload.

    {
        "end": "string",
        "id": "string",
        "mode": "string",
        "name": "string",
        "parameters": {},
        "start": "string",
        "version": "string",
        "with_in": {
            "field": "string",
            "values": [
                "string"
            ]
        },
        "with_limit": {
            "from": "string",
            "limit": 0
        },
        "with_renames": [
            {
                "as": "string",
                "field": "string"
            }
        ],
        "with_sort": {
            "fields": [
                "string"
            ],
            "limit": 0,
            "order": [
                "string"
            ],
            "reverse": true,
            "type": [
                "string"
            ]
        }
    }
    """
    returned_payload = {}
    keys = ["end", "id", "mode", "name", "search_parameters", "start", "version"
            "with_in", "with_limit", "with_renames", "with_sort"
            ]
    for key in keys:
        if passed_keywords.get(key, None):
            if key == "search_parameters":
                returned_payload["parameters"] = passed_keywords.get(key)
            else:
                returned_payload[key] = passed_keywords.get(key)

    return returned_payload
