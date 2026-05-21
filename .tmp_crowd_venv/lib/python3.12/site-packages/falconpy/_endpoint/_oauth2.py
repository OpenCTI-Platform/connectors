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

_oauth2_endpoints = [
  [
    "oauth2RevokeToken",
    "POST",
    "/oauth2/revoke",
    "Revoke a previously issued OAuth2 access token before the end of its standard 30-minute lifespan.",
    "oauth2",
    [
      {
        "type": "string",
        "description": "The OAuth2 client ID you are revoking the token for.",
        "name": "client_id",
        "in": "formData"
      },
      {
        "type": "string",
        "description": "The OAuth2 access token you want to revoke.\n\nInclude your API client ID and secret "
        "in basic auth format (Authorization: basic <encoded API client ID and secret>) in your request header.",
        "name": "token",
        "in": "formData",
        "required": True
      }
    ]
  ],
  [
    "oauth2AccessToken",
    "POST",
    "/oauth2/token",
    "Generate an OAuth2 access token",
    "oauth2",
    [
      {
        "type": "string",
        "description": "The API client ID to authenticate your API requests. For information on generating API "
        " clients, see [API documentation inside "
        "Falcon](https://falcon.crowdstrike.com/support/documentation/1/crowdstrike-api-introduction-for-developers).",
        "name": "client_id",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "The API client secret to authenticate your API requests. For information on generating "
        " API clients, see [API documentation inside "
        "Falcon](https://falcon.crowdstrike.com/support/documentation/1/crowdstrike-api-introduction-for-developers).",
        "name": "client_secret",
        "in": "formData",
        "required": True
      },
      {
        "type": "string",
        "description": "For MSSP Master CIDs, optionally lock the token to act on behalf of this member CID",
        "name": "member_cid",
        "in": "formData"
      }
    ]
  ]
]
