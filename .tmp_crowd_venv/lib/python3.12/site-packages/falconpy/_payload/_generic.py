"""Internal payload handling library - Generic Payloads.

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


def generic_payload_list(submitted_keywords: dict,
                         payload_value: str,
                         submitted_arguments: list = None
                         ) -> dict:
    """Handle a generic list payload.

    Creates a standardized BODY payload based upon the
    requested payload value and passed keywords.

    Resulting payload provides passed keywords values in list format.

    Creates the following payload:
    {
      "payload_value": [
        "keyword provided values"
      ]
    }
    """
    returned_payload = {}
    submitted_values = submitted_keywords.get(payload_value, None)
    if submitted_values:
        if not isinstance(submitted_values, list):
            submitted_values = submitted_values.split(",")
        returned_payload[payload_value] = submitted_values
    else:
        if submitted_arguments:
            if isinstance(submitted_arguments[0], dict):
                # They're passing us a full payload
                returned_payload = submitted_arguments[0]
            else:
                # They're just passing us values
                submitted_values = submitted_arguments[0]
                if not isinstance(submitted_values, list):
                    submitted_values = submitted_values.split(",")
                returned_payload[payload_value] = submitted_values

    return returned_payload


def aggregate_payload(submitted_keywords: dict) -> dict:  # pylint: disable=R0912
    """Create the standardized BODY payload necessary for aggregate operations.

    Creates the following payload, no parameters shown below are required:
    {
        "date_ranges": [
            {
                "from": "string",
                "to": "string"
            }
        ],
        "exclude": "string",
        "extended_bounds": {
            "max": "string",
            "min": "string"
        },
        "field": "string",
        "filter": "string",
        "from": integer,
        "include": "string",
        "interval": "string",
        "max_doc_count": integer,
        "min_doc_count": integer,
        "missing": "string",
        "name": "string",
        "percents": [
        integer
        ],
        "q": "string",
        "ranges": [
            {
                "From": integer,
                "To": integer
            }
        ],
        "size": integer,
        "sort": "string",
        "sub_aggregates": [
            null
        ],
        "time_zone": "string",
        "type": "string"
    }
    """
    returned_payload = {}

    keys = ["date_ranges", "exclude", "include", "field", "filter", "interval", "missing",
            "name", "q", "ranges", "sort", "sub_aggregates", "time_zone", "type", "extended_bounds"
            "filters_spec", "percents"
            ]

    int_keys = ["from", "max_doc_count", "min_doc_count", "size"]

    for key in keys:
        if submitted_keywords.get(key, None):
            returned_payload[key] = submitted_keywords.get(key, None)

    for key in int_keys:
        if submitted_keywords.get(key, -1) >= 0:
            returned_payload[key] = submitted_keywords.get(key, -1)

    return returned_payload


def exclusion_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted exclusion payload.

    {
        "comment": "string",
        "excluded_from": [
            "string"
        ],
        "groups": [
            "string"
        ],
        "id": "string",
        "is_descendant_process": boolean,
        "value": "string"
    }
    """
    returned_payload = {}
    keys = ["comment", "id", "is_descendant_process", "value"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key, None)
    group_list = passed_keywords.get("groups", None)
    if group_list:
        if isinstance(group_list, str):
            group_list = group_list.split(",")
        returned_payload["groups"] = group_list
    exclude_list = passed_keywords.get("excluded_from", None)
    if exclude_list:
        if isinstance(exclude_list, str):
            exclude_list = exclude_list.split(",")
        returned_payload["excluded_from"] = exclude_list

    return returned_payload


def installation_token_payload(passed_keywords: dict) -> dict:
    """Create a properly formatted payload for handling installation tokens.

    {
        "expires_timestamp": "2021-09-22T02:28:11.762Z",
        "label": "string",
        "type": "string",            [CREATE only]
        "revoked": boolean           [UPDATE only]
    }
    """
    returned_payload = {}
    if passed_keywords.get("expires_timestamp", None):
        returned_payload["expires_timestamp"] = passed_keywords.get("expires_timestamp", None)
    if passed_keywords.get("label", None):
        returned_payload["label"] = passed_keywords.get("label", None)

    return returned_payload


def simple_action_parameter(passed_keywords: dict, existing_payload: dict = None) -> dict:
    """Create a properly formatted action parameter body payload.

    {
        "action_parameters": [
            {
                "name": "string",
                "value": "string"
            }
        ]
    }
    """
    returned_payload = {}
    if existing_payload:
        returned_payload = existing_payload
    returned_payload["action_parameters"] = []
    _single = {}
    for key in ["name", "value"]:
        if passed_keywords.get(key, None):
            _single[key] = passed_keywords.get(key)
    if "name" in _single and "value" in _single:
        returned_payload["action_parameters"].append(_single)

    if passed_keywords.get("action_parameters", None):
        # Overrides provided name / value keywords
        returned_payload["action_parameters"] = passed_keywords.get("action_parameters")

    return returned_payload


def token_settings_payload(passed_keywords: dict) -> dict:
    """Craft a properly formatted installation token settings payload.

    {
        "max_active_tokens": 0,
        "tokens_required": true
    }
    """
    returned_payload = {}
    keys = ["max_active_tokens", "tokens_required"]
    for key in keys:
        if passed_keywords.get(key, None) is not None:
            returned_payload[key] = passed_keywords.get(key)

    return returned_payload
