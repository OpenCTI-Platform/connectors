"""Internal payload handling library - MalQuery.

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


def malquery_fuzzy_payload(passed_keywords: dict) -> dict:
    """Generate a properly formatted MalQuery fuzzy search payload.

    {
        "options": {
            "filter_meta": [
                "string"
            ],
            "limit": 0
        },
        "patterns": [
            {
            "type": "string",
            "value": "string"
            }
        ]
    }
    """
    returned_payload: dict = {}
    filters = passed_keywords.get("filter_meta", None)
    limit = passed_keywords.get("limit", 0)
    if filters or limit:
        returned_payload["options"] = {}
    if filters:
        if isinstance(filters, str):
            filters = filters.split(",")
        returned_payload["options"]["filter_meta"] = filters
    if limit:
        returned_payload["options"]["limit"] = limit
    patterns = passed_keywords.get("patterns", None)
    if patterns:
        returned_payload["patterns"] = patterns

    return returned_payload


def handle_malquery_search_params(passed_params: dict) -> dict:
    """Create the base payload used by exact_search and hunt."""
    returned_base: dict = {}
    filters = passed_params.get("filter_filetypes", None)
    filter_meta = passed_params.get("filter_meta", None)
    limit = passed_params.get("limit", 0)
    max_date = passed_params.get("max_date", None)
    max_size = passed_params.get("max_size", None)
    min_date = passed_params.get("min_date", None)
    min_size = passed_params.get("min_size", None)
    if any([filters, filter_meta, limit, max_date, max_size, min_date, min_size]):
        returned_base["options"] = {}
    if filters:
        if isinstance(filters, str):
            filters = filters.split(",")
        returned_base["options"]["filter_filetypes"] = filters
    if filter_meta:
        if isinstance(filter_meta, str):
            filter_meta = filter_meta.split(",")
        returned_base["options"]["filter_meta"] = filter_meta
    if limit:
        returned_base["options"]["limit"] = limit
    if max_date:
        returned_base["options"]["max_date"] = max_date
    if min_date:
        returned_base["options"]["min_date"] = min_date
    if max_size:
        returned_base["options"]["max_size"] = max_size
    if min_size:
        returned_base["options"]["min_size"] = min_size

    return returned_base


def malquery_exact_search_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted payload for performing a MalQuery exact search request.

    {
    "options": {
        "filter_filetypes": [
            "string"
        ],
        "filter_meta": [
            "string"
        ],
        "limit": 0,
        "max_date": "string",
        "max_size": "string",
        "min_date": "string",
        "min_size": "string"
    },
    "patterns": [
        {
        "type": "string",
        "value": "string"
        }
    ]
    }
    """
    returned_payload = handle_malquery_search_params(passed_params=passed_keywords)
    if passed_keywords.get("patterns", None):
        returned_payload["patterns"] = passed_keywords.get("patterns", None)

    return returned_payload


def malquery_hunt_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted payload for performing a MalQuery hunt request.

    {
        "options": {
            "filter_filetypes": [
                "string"
            ],
            "filter_meta": [
                "string"
            ],
            "limit": 0,
            "max_date": "string",
            "max_size": "string",
            "min_date": "string",
            "min_size": "string"
        },
        "yara_rule": "string"
    }
    """
    returned_payload = handle_malquery_search_params(passed_params=passed_keywords)
    if passed_keywords.get("yara_rule", None):
        returned_payload["yara_rule"] = passed_keywords.get("yara_rule", None)

    return returned_payload
