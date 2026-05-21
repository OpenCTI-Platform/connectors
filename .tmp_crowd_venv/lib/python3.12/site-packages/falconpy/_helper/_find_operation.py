"""API Operation lookup helper.

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
from .._endpoint import api_endpoints
from .._error import (
    InvalidOperation,
    InvalidServiceCollection,
    InvalidRoute,
    InvalidOperationSearch
    )


def find_operation(search_for: str,  # pylint: disable=R0912
                   search_by: str = "id",
                   exact: bool = True
                   ) -> Union[str, List[Dict[str, str]]]:
    """Search for API operation details by ID, Collection or Route."""
    if search_by.lower() == "id":
        searched = {}
        for op in api_endpoints:
            searched[op[0]] = {
                "operation": op[0],
                "method": op[1],
                "route": op[2],
                "description": op[3],
                "collection": op[4]
            }
    elif search_by.lower() == "collection":
        searched = {}
        for op in api_endpoints:
            if op[4] not in searched:
                searched[op[4]] = []
            searched[op[4]].append({
                "operation": op[0],
                "method": op[1],
                "route": op[2],
                "description": op[3],
                "collection": op[4]
            })
    elif search_by.lower() == "route":
        searched = {}
        for op in api_endpoints:
            searched[op[2]] = {
                "operation": op[0],
                "method": op[1],
                "route": op[2],
                "description": op[3],
                "collection": op[4]
            }
    else:
        raise InvalidOperationSearch

    try:
        if exact:
            if search_by == "collection":
                search_for = search_for.lower()
            returned = searched[search_for]
        else:
            returned = []
            for op_id, op_val in searched.items():
                if search_for.lower() in op_id.lower():
                    returned.append(op_val)
            if not returned:
                raise KeyError
    except KeyError as bad_search:
        if search_by.lower() == "id":
            raise InvalidOperation from bad_search
        if search_by.lower() == "collection":
            raise InvalidServiceCollection from bad_search
        if search_by.lower() == "route":
            raise InvalidRoute from bad_search

    return returned
