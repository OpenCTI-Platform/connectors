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

_custom_storage_endpoints = [
  [
    "ListCollections",
    "GET",
    "/customobjects/v1/collections",
    "List available collection names in alphabetical order",
    "custom_storage",
    [
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The end key to end listing to",
        "name": "end",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "integer",
        "description": "The limit of results to return",
        "name": "limit",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The start key to start listing from",
        "name": "start",
        "in": "query",
        "allowEmptyValue": True
      }
    ]
  ],
  [
    "DescribeCollections",
    "PUT",
    "/customobjects/v1/collections",
    "Fetch metadata about one or more existing collections",
    "custom_storage",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "A set of collection names",
        "name": "names",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "DescribeCollection",
    "GET",
    "/customobjects/v1/collections/{collection_name}",
    "Fetch metadata about an existing collection",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "ListObjects",
    "GET",
    "/customobjects/v1/collections/{collection_name}/objects",
    "List the object keys in the specified collection in alphabetical order",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The end key to end listing to",
        "name": "end",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "integer",
        "description": "The limit of results to return",
        "name": "limit",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The start key to start listing from",
        "name": "start",
        "in": "query",
        "allowEmptyValue": True
      }
    ]
  ],
  [
    "SearchObjects",
    "POST",
    "/customobjects/v1/collections/{collection_name}/objects",
    "Search for objects that match the specified filter criteria (returns metadata, not actual objects)",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The filter to limit the returned results.",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "description": "The limit of results to return",
        "name": "limit",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "integer",
        "description": "The offset of results to return",
        "name": "offset",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The sort order for the returned results.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "GetObject",
    "GET",
    "/customobjects/v1/collections/{collection_name}/objects/{object_key}",
    "Get the bytes for the specified object",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The object key",
        "name": "object_key",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "PutObject",
    "PUT",
    "/customobjects/v1/collections/{collection_name}/objects/{object_key}",
    "Put the specified new object at the given key or overwrite an existing object at the given key",
    "custom_storage",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      },
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "type": "boolean",
        "description": "If false, run the operation as normal.  If true, validate that the request *would* "
        "succeed, but don't execute it.",
        "name": "dry_run",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The object key",
        "name": "object_key",
        "in": "path",
        "required": True
      },
      {
        "minLength": 1,
        "type": "string",
        "description": "The version of the collection schema",
        "name": "schema_version",
        "in": "query"
      }
    ]
  ],
  [
    "DeleteObject",
    "DELETE",
    "/customobjects/v1/collections/{collection_name}/objects/{object_key}",
    "Delete the specified object",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "type": "boolean",
        "description": "If false, run the operation as normal.  If true, validate that the request *would* "
        "succeed, but don't execute it.",
        "name": "dry_run",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The object key",
        "name": "object_key",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "GetObjectMetadata",
    "GET",
    "/customobjects/v1/collections/{collection_name}/objects/{object_key}/metadata",
    "Get the metadata for the specified object",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The object key",
        "name": "object_key",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "ListSchemas",
    "GET",
    "/customobjects/v1/collections/{collection_name}/schemas",
    "Get the list of schemas for the requested collection in reverse version order (latest first)",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The end key to end listing to",
        "name": "end",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "integer",
        "description": "The limit of results to return",
        "name": "limit",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The start key to start listing from",
        "name": "start",
        "in": "query",
        "allowEmptyValue": True
      }
    ]
  ],
  [
    "GetSchema",
    "GET",
    "/customobjects/v1/collections/{collection_name}/schemas/{schema_version}",
    "Get the bytes of the specified schema of the requested collection",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "minLength": 1,
        "type": "string",
        "description": "The version of the collection schema or 'latest' for the latest version",
        "name": "schema_version",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "GetSchemaMetadata",
    "GET",
    "/customobjects/v1/collections/{collection_name}/schemas/{schema_version}/metadata",
    "Get the metadata for the specified schema of the requested collection",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "minLength": 1,
        "type": "string",
        "description": "The version of the collection schema or 'latest' for the latest version",
        "name": "schema_version",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "ListObjectsByVersion",
    "GET",
    "/customobjects/v1/collections/{collection_name}/{collection_version}/objects",
    "List the object keys in the specified collection in alphabetical order",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 20,
        "minLength": 1,
        "type": "string",
        "description": "The version of the collection",
        "name": "collection_version",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The end key to end listing to",
        "name": "end",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "integer",
        "description": "The limit of results to return",
        "name": "limit",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The start key to start listing from",
        "name": "start",
        "in": "query",
        "allowEmptyValue": True
      }
    ]
  ],
  [
    "SearchObjectsByVersion",
    "POST",
    "/customobjects/v1/collections/{collection_name}/{collection_version}/objects",
    "Search for objects that match the specified filter criteria (returns metadata, not actual objects)",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 20,
        "minLength": 1,
        "type": "string",
        "description": "The version of the collection",
        "name": "collection_version",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The filter to limit the returned results.",
        "name": "filter",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "description": "The limit of results to return",
        "name": "limit",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "type": "integer",
        "description": "The offset of results to return",
        "name": "offset",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The sort order for the returned results.",
        "name": "sort",
        "in": "query"
      }
    ]
  ],
  [
    "GetVersionedObject",
    "GET",
    "/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}",
    "Get the bytes for the specified object",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 20,
        "minLength": 1,
        "type": "string",
        "description": "The version of the collection",
        "name": "collection_version",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The object key",
        "name": "object_key",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "PutObjectByVersion",
    "PUT",
    "/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}",
    "Put the specified new object at the given key or overwrite an existing object at the given key",
    "custom_storage",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      },
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 20,
        "minLength": 1,
        "type": "string",
        "description": "The version of the collection",
        "name": "collection_version",
        "in": "path",
        "required": True
      },
      {
        "type": "boolean",
        "description": "If false, run the operation as normal.  If true, validate that the request *would* "
        "succeed, but don't execute it.",
        "name": "dry_run",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The object key",
        "name": "object_key",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "DeleteVersionedObject",
    "DELETE",
    "/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}",
    "Delete the specified versioned object",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 20,
        "minLength": 1,
        "type": "string",
        "description": "The version of the collection",
        "name": "collection_version",
        "in": "path",
        "required": True
      },
      {
        "type": "boolean",
        "description": "If false, run the operation as normal.  If true, validate that the request *would* "
        "succeed, but don't execute it.",
        "name": "dry_run",
        "in": "query",
        "allowEmptyValue": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The object key",
        "name": "object_key",
        "in": "path",
        "required": True
      }
    ]
  ],
  [
    "GetVersionedObjectMetadata",
    "GET",
    "/customobjects/v1/collections/{collection_name}/{collection_version}/objects/{object_key}/metadata",
    "Get the metadata for the specified object",
    "custom_storage",
    [
      {
        "maxLength": 255,
        "minLength": 1,
        "type": "string",
        "description": "The name of the collection",
        "name": "collection_name",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 20,
        "minLength": 1,
        "type": "string",
        "description": "The version of the collection",
        "name": "collection_version",
        "in": "path",
        "required": True
      },
      {
        "maxLength": 1000,
        "minLength": 1,
        "type": "string",
        "description": "The object key",
        "name": "object_key",
        "in": "path",
        "required": True
      }
    ]
  ]
]
