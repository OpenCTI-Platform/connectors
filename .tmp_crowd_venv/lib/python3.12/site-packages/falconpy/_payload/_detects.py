"""Internal payload handling library - Detects.

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


def update_detects_payload(current_payload: dict, passed_keywords: dict) -> dict:
    """Update the provided payload with any viable parameters provided as keywords.

    {
        "assigned_to_uuid": "string",
        "comment": "string",
        "ids": [
            "string"
        ],
        "new_behaviors_processed": [
            "string"
        ]
        "show_in_ui": true,
        "status": "string"
    }
    """
    keys = ["assigned_to_uuid", "comment", "status"]
    for key in keys:
        if passed_keywords.get(key, None):
            current_payload[key] = passed_keywords.get(key, None)

    if passed_keywords.get("show_in_ui", None) is not None:
        current_payload["show_in_ui"] = passed_keywords.get("show_in_ui", None)

    list_keys = ["ids", "new_behaviors_processed"]
    for key in list_keys:
        if passed_keywords.get(key, None):
            provided = passed_keywords.get(key, None)
            if isinstance(provided, str):
                provided = provided.split(",")
            current_payload[key] = provided

    return current_payload
