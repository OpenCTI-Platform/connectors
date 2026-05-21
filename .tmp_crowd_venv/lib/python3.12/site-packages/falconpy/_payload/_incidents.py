"""Internal payload handling library - Incident Payloads.

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


def incident_action_parameters(passed_keywords: dict) -> list:
    """Create a properly formatted action_parameters branch for incident action payload operations.

    Available keywords
    add_comment - Adds the associated value as a new comment on all the incidents in the ids list.
    add_tag - Adds the associated value as a new tag on all the incidents of the ids list.
              Multiple tags may be provided as a list or comma delimited string.
    delete_tag - Deletes tags matching the value from all the incidents in the ids list.
                 Multiple tags may be provided as a list or a comma delimited string.
    unassign - Unassigns all users from all of the incidents in the ids list. Boolean.
               This action does not require a value parameter. For example:
               "action_parameters": [
                    {
                        "name": "unassign"
                    }
                ]
    update_name - Updates the name to the parameter value of all the incidents in the ids list. String.
    update_assigned_to_v2 - Assigns the user matching the UUID in the parameter value to all of
                            the incidents in the ids list. String.
                            For information on getting the UUID of a user, see Find existing users.
    update_description - Updates the description to the parameter value of all the incidents listed
                         in the ids list. String.
    update_status - Updates the status to the parameter value of all the incidents in the ids list.
                    Integer string. Valid status values are 20, 25, 30, or 40:
                        20: New
                        25: Reopened
                        30: In Progress
                        40: Closed
    [
        {
            "name": "string",
            "value": "string"
        },
        {
            "name": "string",
            "value": "string"
        },
        etc.
    ]
    """
    returned_payload = []
    valid_keywords = [
        "add_tag", "delete_tag", "unassign", "update_name", "update_assigned_to_v2",
        "update_description", "update_status", "add_comment"
        ]
    for key, val in passed_keywords.items():
        if key in valid_keywords and key != "unassign":
            if key in ["add_tag", "delete_tag"]:
                if isinstance(val, str):
                    val = val.split(",")
                for tag_val in val:
                    returned_payload.append({
                        "name": key,
                        "value": tag_val
                    })
            else:
                returned_payload.append({
                    "name": key,
                    "value": val
                })
        if key == "unassign":
            if val:
                returned_payload.append({
                    "name": key
                })

    return returned_payload
