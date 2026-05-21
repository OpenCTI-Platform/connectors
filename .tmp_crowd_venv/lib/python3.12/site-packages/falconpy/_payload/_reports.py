"""Internal payload handling library - Reports Payloads.

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
from typing import Union, List, Optional


def reports_payload(passed_keywords: dict, passed_arguments: Optional[tuple] = None) -> List[dict]:
    """Create a properly formatted payload for report execution / scheduling.

    [
        {
            "id": "string"
        }
    ]
    """
    returned_payload = []
    submitted: Union[str, list] = ""
    if passed_keywords.get("ids", None):
        key: Union[str, list] = passed_keywords.get("ids", None)
        if isinstance(key, list):
            submitted = key
        else:
            submitted = key.split(",")
    elif passed_arguments:
        key = passed_arguments[0]
        if isinstance(key, list):
            submitted = key
        else:
            submitted = key.split(",")

    for submitted_id in submitted:
        item = {}
        item["id"] = submitted_id
        returned_payload.append(item)

    return returned_payload
