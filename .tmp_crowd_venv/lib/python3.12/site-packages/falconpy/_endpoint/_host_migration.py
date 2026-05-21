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

_host_migration_endpoints = [
  [
    "HostMigrationAggregatesV1",
    "POST",
    "/host-migration/aggregates/host-migrations/v1",
    "Get host migration aggregates as specified via json in request body.",
    "host_migration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "MigrationAggregatesV1",
    "POST",
    "/host-migration/aggregates/migrations/v1",
    "Get migration aggregates as specified via json in request body.",
    "host_migration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "HostMigrationsActionsV1",
    "POST",
    "/host-migration/entities/host-migrations-actions/v1",
    "Perform an action on host migrations.",
    "host_migration",
    [
      {
        "type": "string",
        "description": "The migration job to perform actions on",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "enum": [
          "remove_hosts",
          "remove_host_groups",
          "add_host_groups"
        ],
        "type": "string",
        "description": "The action to perform",
        "name": "action_name",
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
    "GetHostMigrationsV1",
    "POST",
    "/host-migration/entities/host-migrations/GET/v1",
    "Get host migration details.",
    "host_migration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetMigrationDestinationsV1",
    "POST",
    "/host-migration/entities/migration-destinations/GET/v1",
    "Get destinations for a migration.",
    "host_migration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "MigrationsActionsV1",
    "POST",
    "/host-migration/entities/migrations-actions/v1",
    "Perform an action on a migration job.",
    "host_migration",
    [
      {
        "enum": [
          "delete_migration",
          "rename_migration",
          "start_migration",
          "cancel_migration"
        ],
        "type": "string",
        "description": "The action to perform",
        "name": "action_name",
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
    "GetMigrationsV1",
    "GET",
    "/host-migration/entities/migrations/v1",
    "Get migration job details.",
    "host_migration",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The migration jobs of interest.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateMigrationV1",
    "POST",
    "/host-migration/entities/migrations/v1",
    "Create a device migration job.",
    "host_migration",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetHostMigrationIDsV1",
    "GET",
    "/host-migration/queries/host-migrations/v1",
    "Query host migration IDs.",
    "host_migration",
    [
      {
        "type": "string",
        "description": "The migration job to query",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return. [1-10000]",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "groups|asc",
          "groups|desc",
          "groups",
          "hostname|asc",
          "hostname|desc",
          "hostname",
          "status|asc",
          "status|desc",
          "status",
          "created_time|asc",
          "created_time|desc",
          "created_time",
          "host_migration_id|asc",
          "host_migration_id|desc",
          "host_migration_id",
          "hostgroups|asc",
          "hostgroups|desc",
          "hostgroups",
          "static_host_groups|asc",
          "static_host_groups|desc",
          "static_host_groups",
          "target_cid|asc",
          "target_cid|desc",
          "target_cid",
          "source_cid|asc",
          "source_cid|desc",
          "source_cid",
          "migration_id|asc",
          "migration_id|desc",
          "migration_id",
          "id|asc",
          "id|desc",
          "id"
        ],
        "type": "string",
        "description": "The property to sort by.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Valid fields: "
        "created_time, host_migration_id, hostgroups, static_host_groups, target_cid, source_cid, migration_id, id, "
        "groups, hostname, status",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "GetMigrationIDsV1",
    "GET",
    "/host-migration/queries/migrations/v1",
    "Query migration jobs.",
    "host_migration",
    [
      {
        "type": "integer",
        "description": "The offset to start retrieving records from",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum records to return. [1-10000]",
        "name": "limit",
        "in": "query"
      },
      {
        "enum": [
          "status|asc",
          "status|desc",
          "status",
          "migration_status|asc",
          "migration_status|desc",
          "migration_status",
          "created_by|asc",
          "created_by|desc",
          "created_by",
          "created_time|asc",
          "created_time|desc",
          "created_time",
          "name|asc",
          "name|desc",
          "name",
          "id|asc",
          "id|desc",
          "id",
          "migration_id|asc",
          "migration_id|desc",
          "migration_id",
          "target_cid|asc",
          "target_cid|desc",
          "target_cid"
        ],
        "type": "string",
        "description": "The property to sort by.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The filter expression that should be used to limit the results. Valid fields: name, "
        "id, migration_id, target_cid, status, migration_status, created_by, created_time",
        "name": "filter",
        "in": "query"
      }
    ]
  ]
]
