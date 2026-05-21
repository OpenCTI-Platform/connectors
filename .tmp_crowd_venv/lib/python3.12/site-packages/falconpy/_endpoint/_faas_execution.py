"""Internal API endpoint constant library.

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

_faas_execution_endpoints = [
  [
    "ReadRequestBody",
    "GET",
    "/faas-gateway/entities/execution-request-body/v2",
    "retrieve a large request body, such as a file, that has spilled into object storage",
    "faas_execution",
    [
      {
        "type": "string",
        "description": "Execution ID",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "function ref; form of $fn_id:$fn_version",
        "name": "fn",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "filename to be retrieved",
        "name": "filename",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "sha256 checksum for file to be retrieved",
        "name": "sha256",
        "in": "query",
        "required": True
      }
    ]
  ]
]
