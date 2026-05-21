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

_intel_endpoints = [
  [
    "QueryIntelActorEntities",
    "GET",
    "/intel/combined/actors/v1",
    "Get info about actors that match provided FQL filters.",
    "intel",
    [
      {
        "type": "integer",
        "description": "Set the starting row number to return actors from. Defaults to 0.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Set the number of actors to return. The value must be between 1 and 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order fields in ascending or descending order.\n\nEx: created_date|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter your query by specifying FQL filter parameters. Filter parameters "
        "include:\n\nactor_type, animal_classifier, capabilities, capability, capability.id, capability.slug, "
        "capability.value, created_date, description, ecrime_kill_chain.attribution, ecrime_kill_chain.crimes, "
        "ecrime_kill_chain.customers, ecrime_kill_chain.marketing, ecrime_kill_chain.monetization, "
        "ecrime_kill_chain.services_offered, ecrime_kill_chain.services_used, ecrime_kill_chain.technical_tradecraft, "
        "ecrime_kill_chain.victims, first_activity_date, group, group.id, group.slug, group.value, id, "
        "kill_chain.actions_and_objectives, kill_chain.actions_on_objectives, kill_chain.command_and_control, "
        "kill_chain.delivery, kill_chain.exploitation, kill_chain.installation, kill_chain.objectives, "
        "kill_chain.reconnaissance, kill_chain.weaponization, known_as, last_activity_date, last_modified_date, "
        "motivations, motivations.id, motivations.slug, motivations.value, name, objectives, origins, origins.id, "
        "origins.slug, origins.value, region, region.id, region.slug, region.value, short_description, slug, status, "
        "target_countries, target_countries.id, target_countries.slug, target_countries.value, target_industries, "
        "target_industries.id, target_industries.slug, target_industries.value, target_regions, target_regions.id, "
        "target_regions.slug, target_regions.value.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Perform a generic substring search across all fields.",
        "name": "q",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The fields to return, or a predefined set of fields in the form of the collection name "
        " surrounded by two underscores like:\n\n\\_\\_\\<collection\\>\\_\\_.\n\nEx: slug "
        "\\_\\_full\\_\\_.\n\nDefaults to \\_\\_basic\\_\\_.",
        "name": "fields",
        "in": "query"
      }
    ]
  ],
  [
    "QueryIntelIndicatorEntities",
    "GET",
    "/intel/combined/indicators/v1",
    "Get info about indicators that match provided FQL filters.",
    "intel",
    [
      {
        "type": "integer",
        "description": "Set the starting row number to return indicators from. Defaults to 0.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Set the number of indicators to return. The number must be between 1 and 10000",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order fields in ascending or descending order.\n\nEx: published_date|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter your query by specifying FQL filter parameters. Filter parameters "
        "include:\n\n_marker, actors, deleted, domain_types, id, indicator, ip_address_types, kill_chains, labels, "
        "labels.created_on, labels.last_valid_on, labels.name, last_updated, malicious_confidence, malware_families, "
        "published_date, reports, reports.slug, scope, targets, threat_types, type, vulnerabilities.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Perform a generic substring search across all fields.",
        "name": "q",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "If true, include both published and deleted indicators in the response. Defaults to false.",
        "name": "include_deleted",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "If true, include related indicators in the response. Defaults to true.",
        "name": "include_relations",
        "in": "query"
      }
    ]
  ],
  [
    "QueryMalwareEntities",
    "GET",
    "/intel/combined/malware/v1",
    "Get malware entities that match provided FQL filters.",
    "intel",
    [
      {
        "type": "integer",
        "description": "Set the starting row number to return malware IDs from. Defaults to 0.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Set the number of malware IDs to return. The value must be between 1 and 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order fields in ascending or descending order.\n\nEx: created_date|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter your query by specifying FQL filter parameters.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Perform a generic substring search across all fields.",
        "name": "q",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The fields to return",
        "name": "fields",
        "in": "query"
      }
    ]
  ],
  [
    "QueryIntelReportEntities",
    "GET",
    "/intel/combined/reports/v1",
    "Get info about reports that match provided FQL filters.",
    "intel",
    [
      {
        "type": "integer",
        "description": "Set the starting row number to return reports from. Defaults to 0.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Set the number of reports to return. The value must be between 1 and 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order fields in ascending or descending order. Ex: created_date|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter your query by specifying FQL filter parameters. Filter parameters "
        "include:\n\nactors, actors.animal_classifier, actors.id, actors.name, actors.slug, actors.url, created_date, "
        "description, id, last_modified_date, malware, malware.community_identifiers, malware.family_name, "
        "malware.slug, motivations, motivations.id, motivations.slug, motivations.value, name, name.raw, "
        "short_description, slug, sub_type, sub_type.id, sub_type.name, sub_type.slug, summary, tags, tags.id, "
        "tags.slug, tags.value, target_countries, target_countries.id, target_countries.slug, target_countries.value, "
        "target_industries, target_industries.id, target_industries.slug, target_industries.value, type, type.id, "
        "type.name, type.slug, url.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Perform a generic substring search across all fields.",
        "name": "q",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The fields to return, or a predefined set of fields in the form of the collection name "
        " surrounded by two underscores like:\n\n\\_\\_\\<collection\\>\\_\\_.\n\nEx: slug "
        "\\_\\_full\\_\\_.\n\nDefaults to \\_\\_basic\\_\\_.",
        "name": "fields",
        "in": "query"
      }
    ]
  ],
  [
    "GetIntelActorEntities",
    "GET",
    "/intel/entities/actors/v1",
    "Retrieve specific actors using their actor IDs.",
    "intel",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the actors you want to retrieve.",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The fields to return, or a predefined set of fields in the form of the collection name "
        " surrounded by two underscores like:\n\n\\_\\_\\<collection\\>\\_\\_.\n\nEx: slug "
        "\\_\\_full\\_\\_.\n\nDefaults to \\_\\_basic\\_\\_.",
        "name": "fields",
        "in": "query"
      }
    ]
  ],
  [
    "GetIntelIndicatorEntities",
    "POST",
    "/intel/entities/indicators/GET/v1",
    "Retrieve specific indicators using their indicator IDs.",
    "intel",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetMalwareMitreReport",
    "GET",
    "/intel/entities/malware-mitre-reports/v1",
    "Export Mitre ATT&CK information for a given malware family.",
    "intel",
    [
      {
        "type": "string",
        "description": "Malware family name in lower case with spaces replaced with dashes",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Supported report formats: CSV, JSON or JSON_NAVIGATOR",
        "name": "format",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetMalwareEntities",
    "GET",
    "/intel/entities/malware/v1",
    "Get malware entities for specified ids.",
    "intel",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Malware family name in lower case with spaces, dots and slashes replaced with dashes",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetMitreReport",
    "GET",
    "/intel/entities/mitre-reports/v1",
    "Export Mitre ATT&CK information for a given actor.",
    "intel",
    [
      {
        "type": "string",
        "description": "Actor ID(derived from the actor's name)",
        "name": "actor_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Supported report formats: CSV or JSON",
        "name": "format",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "PostMitreAttacks",
    "POST",
    "/intel/entities/mitre/v1",
    "Retrieves report and observable IDs associated with the given actor and attacks",
    "intel",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "GetIntelReportPDF",
    "GET",
    "/intel/entities/report-files/v1",
    "Return a Report PDF attachment",
    "intel",
    [
      {
        "type": "string",
        "description": "The ID of the report you want to download as a PDF.",
        "name": "id",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The ID of the report you want to download as a PDF. This parameter is used only if no "
        "id parameter given.",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "GetIntelReportEntities",
    "GET",
    "/intel/entities/reports/v1",
    "Retrieve specific reports using their report IDs.",
    "intel",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The IDs of the reports you want to retrieve.",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The fields to return, or a predefined set of fields in the form of the collection name "
        " surrounded by two underscores like:\n\n\\_\\_\\<collection\\>\\_\\_.\n\nEx: slug "
        "\\_\\_full\\_\\_.\n\nDefaults to \\_\\_basic\\_\\_.",
        "name": "fields",
        "in": "query"
      }
    ]
  ],
  [
    "GetIntelRuleFile",
    "GET",
    "/intel/entities/rules-files/v1",
    "Download earlier rule sets.",
    "intel",
    [
      {
        "type": "string",
        "description": "Choose the format you want the rule set in.",
        "name": "Accept",
        "in": "header"
      },
      {
        "type": "integer",
        "description": "The ID of the rule set.",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Choose the format you want the rule set in. Valid formats are zip and gzip. Defaults to zip.",
        "name": "format",
        "in": "query"
      }
    ]
  ],
  [
    "GetLatestIntelRuleFile",
    "GET",
    "/intel/entities/rules-latest-files/v1",
    "Download the latest rule set.",
    "intel",
    [
      {
        "type": "string",
        "description": "Choose the format you want the rule set in.",
        "name": "Accept",
        "in": "header"
      },
      {
        "type": "string",
        "description": "Download the latest rule set only if it doesn't have an ETag matching the given ones.",
        "name": "If-None-Match",
        "in": "header"
      },
      {
        "type": "string",
        "description": "Download the latest rule set only if the rule was modified after this date. http, "
        "ANSIC and RFC850 formats accepted",
        "name": "If-Modified-Since",
        "in": "header"
      },
      {
        "type": "string",
        "description": "The rule news report type. Accepted values:\n\nsnort-suricata-master\n\nsnort-"
        "suricata-update\n\nsnort-suricata-changelog\n\nyara-master\n\nyara-update\n\nyara-changelog\n\ncommon-event-"
        "format\n\nnetwitness\n\ncql-master\n\ncql-update\n\ncql-changelog",
        "name": "type",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Choose the format you want the rule set in. Valid formats are zip and gzip. Defaults to zip.",
        "name": "format",
        "in": "query"
      }
    ]
  ],
  [
    "GetIntelRuleEntities",
    "GET",
    "/intel/entities/rules/v1",
    "Retrieve details for rule sets for the specified ids.",
    "intel",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The ids of rules to return.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "GetVulnerabilities",
    "POST",
    "/intel/entities/vulnerabilities/GET/v1",
    "Get vulnerabilities",
    "intel",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "QueryIntelActorIds",
    "GET",
    "/intel/queries/actors/v1",
    "Get actor IDs that match provided FQL filters.",
    "intel",
    [
      {
        "type": "integer",
        "description": "Set the starting row number to return actors IDs from. Defaults to 0.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Set the number of actor IDs to return. The value must be between 1 and 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order fields in ascending or descending order.\n\nEx: created_date|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter your query by specifying FQL filter parameters. Filter parameters "
        "include:\n\nactor_type, animal_classifier, capabilities, capability, capability.id, capability.slug, "
        "capability.value, created_date, description, ecrime_kill_chain.attribution, ecrime_kill_chain.crimes, "
        "ecrime_kill_chain.customers, ecrime_kill_chain.marketing, ecrime_kill_chain.monetization, "
        "ecrime_kill_chain.services_offered, ecrime_kill_chain.services_used, ecrime_kill_chain.technical_tradecraft, "
        "ecrime_kill_chain.victims, first_activity_date, group, group.id, group.slug, group.value, id, "
        "kill_chain.actions_and_objectives, kill_chain.actions_on_objectives, kill_chain.command_and_control, "
        "kill_chain.delivery, kill_chain.exploitation, kill_chain.installation, kill_chain.objectives, "
        "kill_chain.reconnaissance, kill_chain.weaponization, known_as, last_activity_date, last_modified_date, "
        "motivations, motivations.id, motivations.slug, motivations.value, name, objectives, origins, origins.id, "
        "origins.slug, origins.value, region, region.id, region.slug, region.value, short_description, slug, status, "
        "target_countries, target_countries.id, target_countries.slug, target_countries.value, target_industries, "
        "target_industries.id, target_industries.slug, target_industries.value, target_regions, target_regions.id, "
        "target_regions.slug, target_regions.value.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Perform a generic substring search across all fields.",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "QueryIntelIndicatorIds",
    "GET",
    "/intel/queries/indicators/v1",
    "Get indicators IDs that match provided FQL filters.",
    "intel",
    [
      {
        "type": "integer",
        "description": "Set the starting row number to return indicator IDs from. Defaults to 0.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Set the number of indicator IDs to return. The number must be between 1 and 10000",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order fields in ascending or descending order.\n\nEx: published_date|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter your query by specifying FQL filter parameters. Filter parameters "
        "include:\n\n_marker, actors, deleted, domain_types, id, indicator, ip_address_types, kill_chains, labels, "
        "labels.created_on, labels.last_valid_on, labels.name, last_updated, malicious_confidence, malware_families, "
        "published_date, reports, reports.slug, scope, targets, threat_types, type, vulnerabilities.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Perform a generic substring search across all fields.",
        "name": "q",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "If true, include both published and deleted indicators in the response. Defaults to false.",
        "name": "include_deleted",
        "in": "query"
      },
      {
        "type": "boolean",
        "description": "If true, include related indicators in the response. Defaults to true.",
        "name": "include_relations",
        "in": "query"
      }
    ]
  ],
  [
    "QueryMalware",
    "GET",
    "/intel/queries/malware/v1",
    "Get malware family names that match provided FQL filters.",
    "intel",
    [
      {
        "type": "integer",
        "description": "Set the starting row number to return malware IDs from. Defaults to 0.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Set the number of malware IDs to return. The value must be between 1 and 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order fields in ascending or descending order.\n\nEx: created_date|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter your query by specifying FQL filter parameters.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Perform a generic substring search across all fields.",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "QueryMitreAttacksForMalware",
    "GET",
    "/intel/queries/mitre-malware/v1",
    "Gets MITRE tactics and techniques for the given malware",
    "intel",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Malware family name in lower case with spaces replaced with dashes",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "QueryMitreAttacks",
    "GET",
    "/intel/queries/mitre/v1",
    "Gets MITRE tactics and techniques for the given actor, returning concatenation of id and tactic and "
    "technique ids, example: fancy-bear_TA0011_T1071",
    "intel",
    [
      {
        "type": "string",
        "description": "The actor ID(derived from the actor's name) for which to retrieve a list of attacks, "
        "for example: fancy-bear. Only one value is allowed",
        "name": "id",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "The actor ID(derived from the actor's name) for which to retrieve a list of attacks, "
        "for example: fancy-bear. Multiple values are allowed",
        "name": "ids",
        "in": "query"
      }
    ]
  ],
  [
    "QueryIntelReportIds",
    "GET",
    "/intel/queries/reports/v1",
    "Get report IDs that match provided FQL filters.",
    "intel",
    [
      {
        "type": "integer",
        "description": "Set the starting row number to return report IDs from. Defaults to 0.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Set the number of report IDs to return. The value must be between 1 and 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order fields in ascending or descending order.\n\nEx: created_date|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter your query by specifying FQL filter parameters. Filter parameters "
        "include:\n\nactors, actors.animal_classifier, actors.id, actors.name, actors.slug, actors.url, created_date, "
        "description, id, last_modified_date, malware, malware.community_identifiers, malware.family_name, "
        "malware.slug, motivations, motivations.id, motivations.slug, motivations.value, name, name.raw, "
        "short_description, slug, sub_type, sub_type.id, sub_type.name, sub_type.slug, summary, tags, tags.id, "
        "tags.slug, tags.value, target_countries, target_countries.id, target_countries.slug, target_countries.value, "
        "target_industries, target_industries.id, target_industries.slug, target_industries.value, type, type.id, "
        "type.name, type.slug, url.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Perform a generic substring search across all fields.",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "QueryIntelRuleIds",
    "GET",
    "/intel/queries/rules/v1",
    "Search for rule IDs that match provided filter criteria.",
    "intel",
    [
      {
        "type": "integer",
        "description": "Set the starting row number to return reports from. Defaults to 0.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The number of rule IDs to return. Defaults to 10.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order fields in ascending or descending order.\n\nEx: created_date|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Search by rule title.",
        "name": "name",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The rule news report type. Accepted values:\n\nsnort-suricata-master\n\nsnort-"
        "suricata-update\n\nsnort-suricata-changelog\n\nyara-master\n\nyara-update\n\nyara-changelog\n\ncommon-event-"
        "format\n\nnetwitness\n\ncql-master\n\ncql-update\n\ncql-changelog",
        "name": "type",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Substring match on description field.",
        "name": "description",
        "in": "query"
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "csv",
        "description": "Search for rule tags.",
        "name": "tags",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Filter results to those created on or after a certain date.",
        "name": "min_created_date",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter results to those created on or before a certain date.",
        "name": "max_created_date",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Perform a generic substring search across all fields.",
        "name": "q",
        "in": "query"
      }
    ]
  ],
  [
    "QueryVulnerabilities",
    "GET",
    "/intel/queries/vulnerabilities/v1",
    "Get vulnerabilities IDs",
    "intel",
    [
      {
        "type": "string",
        "description": "Starting index of result set from which to return IDs.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "Number of IDs to return.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Order by fields.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "FQL query specifying the filter parameters. Filter parameters include:\n\n_all, "
        "affected_products.product, affected_products.vendor, community_identifiers, cve, cvss_v3_base, "
        "cvss_v3_base.score, cvss_v3_base.severity, exploit_status, publish_date, related_actors, "
        "related_actors.animal_classifier, related_actors.name, related_reports.serial_id, related_reports.title, "
        "related_threats, related_threats.name, severity, updated_timestamp.",
        "name": "filter",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Match phrase_prefix query criteria; included fields: _all (all filter string fields indexed).",
        "name": "q",
        "in": "query"
      }
    ]
  ]
]
