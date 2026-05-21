"""FalconPy Service Class helper methods.

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
from typing import Union


def service_override_payload(caller: object,
                             meth: str,
                             rte: str,
                             body_p: dict,
                             param_p: dict,
                             file_p: list,
                             data_p: Union[dict, bytes],
                             exp: bool
                             ) -> dict:
    """Create the necessary arguments for a direct call to process_request."""
    return {
        "method": meth,
        "endpoint": f"{caller.base_url}{rte}",
        "body": body_p,
        "data": data_p,
        "params": param_p,
        "headers": caller.headers,
        "files": file_p,
        "verify": caller.ssl_verify,
        "proxy": caller.proxy,
        "timeout": caller.timeout,
        "user_agent": caller.user_agent,
        "expand_result": exp,
        "container": False,     # Does not currently support container operations
        "log_util": caller.log,
        "debug_record_count": caller.debug_record_count,
        "sanitize": caller.sanitize_log,
        "pythonic": caller.pythonic
    }
