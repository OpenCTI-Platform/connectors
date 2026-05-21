"""API Response formatting class.

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
# pylint: disable=R0903
from typing import Tuple, Dict, Union


class ExpandedResult:
    """Callable subsclass to handle parsing of expanded result client output.

    DEPRECATED
    ---
    This class is deprecated and maintained for backwards compatibility purposes only.

    Please move all code over to use Result.tupled.

    Examples: tupled_response: Result = falcon.query_detects(pythonic=True).tupled
              tupled_response: Result = Result(full=falcon.query_detects()).tupled
    """

    def __call__(self,
                 status_code: int,
                 headers: Dict[str, str],
                 content: Union[str, bytes, Dict[str, Dict]]
                 ) -> Tuple[str, Dict[str, str], Dict[str, Dict]]:
        """Format ingested values into a properly formatted expanded result object."""
        content_result = content
        if isinstance(content, dict):
            content_result = content["body"]

        return (status_code, dict(headers), content_result)
