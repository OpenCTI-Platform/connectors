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

_recon_endpoints = [
  [
    "AggregateNotificationsExposedDataRecordsV1",
    "POST",
    "/recon/aggregates/notifications-exposed-data-records/GET/v1",
    "Get notification exposed data record aggregates as specified via JSON in request body. The valid "
    "aggregation fields are: [cid notification_id created_date rule.id rule.name rule.topic source_category site "
    "author file.name credential_status bot.operating_system.hardware_id bot.bot_id]",
    "recon",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "AggregateNotificationsV1",
    "POST",
    "/recon/aggregates/notifications/GET/v1",
    "Get notification aggregates as specified via JSON in request body.",
    "recon",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "PreviewRuleV1",
    "POST",
    "/recon/aggregates/rules-preview/GET/v1",
    "Preview rules notification count and distribution. This will return aggregations on: channel, count, site.",
    "recon",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetActionsV1",
    "GET",
    "/recon/entities/actions/v1",
    "Get actions based on their IDs. IDs can be retrieved using the GET /queries/actions/v1 endpoint.",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Action IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateActionsV1",
    "POST",
    "/recon/entities/actions/v1",
    "Create actions for a monitoring rule. Accepts a list of actions that will be attached to the monitoring rule.",
    "recon",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateActionV1",
    "PATCH",
    "/recon/entities/actions/v1",
    "Update an action for a monitoring rule.",
    "recon",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteActionV1",
    "DELETE",
    "/recon/entities/actions/v1",
    "Delete an action from a monitoring rule based on the action ID.",
    "recon",
    [
      {
        "type": "string",
        "description": "ID of the action.",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetFileContentForExportJobsV1",
    "GET",
    "/recon/entities/export-files/v1",
    "Download the file associated with a job ID.",
    "recon",
    [
      {
        "type": "string",
        "description": "Export Job ID.",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetExportJobsV1",
    "GET",
    "/recon/entities/exports/v1",
    "Get the status of export jobs based on their IDs. Export jobs can be launched by calling POST "
    "/entities/exports/v1. When a job is complete, use the job ID to download the file(s) associated with it using "
    "GET entities/export-files/v1.",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Export Job IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateExportJobsV1",
    "POST",
    "/recon/entities/exports/v1",
    "Launch asynchronous export job. Use the job ID to poll the status of the job using GET /entities/exports/v1.",
    "recon",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteExportJobsV1",
    "DELETE",
    "/recon/entities/exports/v1",
    "Delete export jobs (and their associated file(s)) based on their IDs.",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Export Job IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetNotificationsDetailedTranslatedV1",
    "GET",
    "/recon/entities/notifications-detailed-translated/v1",
    "Get detailed notifications based on their IDs. These include the translated raw intelligence content that "
    "generated the match or part of it. ",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Notification IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetNotificationsDetailedV1",
    "GET",
    "/recon/entities/notifications-detailed/v1",
    "Get detailed notifications based on their IDs. These include the raw intelligence content that generated "
    "the match or part of it. ",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Notification IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetNotificationsExposedDataRecordsV1",
    "GET",
    "/recon/entities/notifications-exposed-data-records/v1",
    "Get notifications exposed data records based on their IDs. IDs can be retrieved using the GET "
    "/queries/notifications-exposed-data-records/v1 endpoint. The associate notification can be fetched using the "
    "/entities/notifications/v* endpoints",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Notification exposed records IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetNotificationsTranslatedV1",
    "GET",
    "/recon/entities/notifications-translated/v1",
    "Get notifications based on their IDs. IDs can be retrieved using the GET /queries/notifications/v1 "
    "endpoint. This endpoint will return translated notification content. The only target language available is "
    "English.",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Notification IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetNotificationsV1",
    "GET",
    "/recon/entities/notifications/v1",
    "Get notifications based on their IDs. IDs can be retrieved using the GET /queries/notifications/v1 endpoint.",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Notification IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "UpdateNotificationsV1",
    "PATCH",
    "/recon/entities/notifications/v1",
    "Update notification status or assignee. Accepts bulk requests",
    "recon",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteNotificationsV1",
    "DELETE",
    "/recon/entities/notifications/v1",
    "Delete notifications based on IDs. Notifications cannot be recovered after they are deleted.",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Notifications IDs.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetRulesV1",
    "GET",
    "/recon/entities/rules/v1",
    "Get monitoring rules based on their IDs. IDs can be retrieved using the GET /queries/rules/v1 endpoint.",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of rules.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "CreateRulesV1",
    "POST",
    "/recon/entities/rules/v1",
    "Create monitoring rules.",
    "recon",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdateRulesV1",
    "PATCH",
    "/recon/entities/rules/v1",
    "Update monitoring rules.",
    "recon",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeleteRulesV1",
    "DELETE",
    "/recon/entities/rules/v1",
    "Delete monitoring rules.",
    "recon",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "IDs of rules.",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "boolean",
        "description": "Whether we should delete the notifications generated by this rule or not",
        "name": "notificationsDeletionRequested",
        "in": "query"
      }
    ]
  ],
  [
    "QueryActionsV1",
    "GET",
    "/recon/queries/actions/v1",
    "Query actions based on provided criteria. Use the IDs from this response to get the action entities on "
    "GET /entities/actions/v1.",
    "recon",
    [
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return IDs.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 500,
        "minimum": 1,
        "type": "integer",
        "description": "Number of IDs to return. Offset + limit should NOT be above 10K.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Possible order by fields: created_timestamp, updated_timestamp. Ex: 'updated_timestamp|desc'.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query to filter actions by. Possible filter properties are: [id cid user_uuid "
        "rule_id type frequency content_format trigger_matchless recipients status created_timestamp "
        "updated_timestamp]",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Free text search across all indexed fields",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "QueryNotificationsExposedDataRecordsV1",
    "GET",
    "/recon/queries/notifications-exposed-data-records/v1",
    "Query notifications exposed data records based on provided criteria. Use the IDs from this response to "
    "get the notification +entities on GET /entities/notifications-exposed-data-records/v1",
    "recon",
    [
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return ids.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 500,
        "minimum": 1,
        "type": "integer",
        "description": "Number of IDs to return. Offset + limit should NOT be above 10K.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Possible order by fields: created_date, updated_date. Ex: 'updated_date|desc'.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query to filter notifications by. Possible filter properties are: [id cid "
        "user_uuid created_date exposure_date rule.id rule.name rule.topic notification_id source_category site site_id "
        " author author_id user_id user_name credentials_url credentials_domain credentials_ip email domain hash_type "
        "display_name full_name user_ip phone_number company job_position file.name file.complete_data_set "
        "file.download_urls location.postal_code location.city location.state location.federal_district "
        "location.federal_admin_region location.country_code social.twitter_id social.facebook_id social.vk_id "
        "social.vk_token social.aim_id social.icq_id social.msn_id social.instagram_id social.skype_id "
        "financial.credit_card financial.bank_account financial.crypto_currency_addresses login_id credential_status "
        "_all bot.operating_system.hardware_id bot.bot_id]",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Free text search across all indexed fields.",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "QueryNotificationsV1",
    "GET",
    "/recon/queries/notifications/v1",
    "Query notifications based on provided criteria. Use the IDs from this response to get the notification "
    "+entities on GET /entities/notifications/v1, GET /entities/notifications-detailed/v1, +GET "
    "/entities/notifications-translated/v1 or GET /entities/notifications-detailed-translated/v1.",
    "recon",
    [
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return IDs.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 500,
        "minimum": 1,
        "type": "integer",
        "description": "Number of IDs to return. Offset + limit should NOT be above 10K.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Possible order by fields: created_date, updated_date. Ex: updated_date|desc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query to filter notifications by. Possible filter properties are: [id cid "
        "user_uuid status rule_id rule_name rule_topic rule_priority item_type item_site typosquatting.id "
        "typosquatting.unicode_format typosquatting.punycode_format typosquatting.parent_domain.id "
        "typosquatting.parent_domain.unicode_format typosquatting.parent_domain.punycode_format "
        "typosquatting.base_domain.id typosquatting.base_domain.unicode_format "
        "typosquatting.base_domain.punycode_format typosquatting.base_domain.is_registered "
        "typosquatting.base_domain.whois.registrar.name typosquatting.base_domain.whois.registrar.status "
        "typosquatting.base_domain.whois.registrant.email typosquatting.base_domain.whois.registrant.name "
        "typosquatting.base_domain.whois.registrant.org typosquatting.base_domain.whois.name_servers created_date "
        "updated_date assigned_to_uuid breach_summary.credential_statuses breach_summary.is_retroactively_deduped]",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Free text search across all indexed fields.",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "QueryRulesV1",
    "GET",
    "/recon/queries/rules/v1",
    "Query monitoring rules based on provided criteria. Use the IDs from this response to fetch the rules on "
    "/entities/rules/v1.",
    "recon",
    [
      {
        "type": "integer",
        "description": "Starting index of overall result set from which to return IDs.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 500,
        "minimum": 1,
        "type": "integer",
        "description": "Number of IDs to return. Offset + limit should NOT be above 10K.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Possible order by fields: "
        "created_timestamp,last_updated_timestamp,permissions,priority,template_priority,topic. Ex: "
        "last_updated_timestamp|desc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query to filter rules by. Possible filter properties are: [id cid user_uuid topic "
        "priority permissions status filter breach_monitoring_enabled substring_matching_enabled created_timestamp "
        "last_updated_timestamp].",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Free text search across all indexed fields.",
        "name": "q",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Possible order by fields: "
        "created_timestamp,last_updated_timestamp,permissions,priority,template_priority,topic. Ex: "
        "last_updated_timestamp|desc.",
        "name": "secondarySort",
        "in": "query"
      }
    ]
  ]
]
