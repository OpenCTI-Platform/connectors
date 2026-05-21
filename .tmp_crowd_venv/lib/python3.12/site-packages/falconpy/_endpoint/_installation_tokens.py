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

_installation_tokens_endpoints = [
  [
    "audit_events_read",
    "GET",
    "/installation-tokens/entities/audit-events/v1",
    "Gets the details of one or more audit events by id.",
    "installation_tokens",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of audit events to retrieve details for",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "customer_settings_read",
    "GET",
    "/installation-tokens/entities/customer-settings/v1",
    "Check current installation token settings.",
    "installation_tokens",
    []
  ],
  [
    "customer_settings_update",
    "PATCH",
    "/installation-tokens/entities/customer-settings/v1",
    "Update installation token settings.",
    "installation_tokens",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "tokens_read",
    "GET",
    "/installation-tokens/entities/tokens/v1",
    "Gets the details of one or more tokens by id.",
    "installation_tokens",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of tokens to retrieve details for",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "tokens_create",
    "POST",
    "/installation-tokens/entities/tokens/v1",
    "Creates a token.",
    "installation_tokens",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "tokens_update",
    "PATCH",
    "/installation-tokens/entities/tokens/v1",
    "Updates one or more tokens. Use this endpoint to edit labels, change expiration, revoke, or restore.",
    "installation_tokens",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "The token ids to update.",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "tokens_delete",
    "DELETE",
    "/installation-tokens/entities/tokens/v1",
    "Deletes a token immediately. To revoke a token, use PATCH /installation-tokens/entities/tokens/v1 instead.",
    "installation_tokens",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "The token ids to delete.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "audit_events_query",
    "GET",
    "/installation-tokens/queries/audit-events/v1",
    "Search for audit events by providing an FQL filter and paging details.",
    "installation_tokens",
    [
      {
        "type": "integer",
        "description": "The offset to start retrieving records from.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return. [1-1000]. Defaults to 50.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The property to sort by (e.g. timestamp.desc).",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results (e.g., action:'token_create').",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "tokens_query",
    "GET",
    "/installation-tokens/queries/tokens/v1",
    "Search for tokens by providing an FQL filter and paging details.",
    "installation_tokens",
    [
      {
        "type": "integer",
        "description": "The offset to start retrieving records from.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return. [1-1000]. Defaults to 50.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The property to sort by (e.g. created_timestamp.desc).",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results (e.g., status:'valid').",
        "name": "filter",
        "in": "query"
      }
    ]
  ]
]
