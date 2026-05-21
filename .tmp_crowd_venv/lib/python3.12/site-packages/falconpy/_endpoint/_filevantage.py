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

_filevantage_endpoints = [
  [
    "getActionsMixin0",
    "GET",
    "/filevantage/entities/actions/v1",
    "Retrieves the processing results for 1 or more actions.",
    "filevantage",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more actions ids in the form of ids=ID1&ids=ID2",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "startActions",
    "POST",
    "/filevantage/entities/actions/v1",
    "Initiates the specified action on the provided change ids",
    "filevantage",
    [
      {
        "description": "Create a new action.\n\n * operation must be one of the suppress, unsuppress, or "
        "purge\n\n * change_ids represent the ids of the changes the operation will perform; limited to 100 ids per "
        "action\n\n * comment optional comment to describe the reason for the action",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "getContents",
    "GET",
    "/filevantage/entities/change-content/v1",
    "Retrieves the content captured for the provided change id",
    "filevantage",
    [
      {
        "type": "string",
        "description": "ID of the change in the form of id=ID1",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "Providing the value of gzip compresses the response, otherwise the content is returned uncompressed.",
        "name": "Accept-Encoding",
        "in": "header"
      }
    ]
  ],
  [
    "getChanges",
    "GET",
    "/filevantage/entities/changes/v2",
    "Retrieve information on changes",
    "filevantage",
    [
      {
        "maxItems": 500,
        "minItems": 1,
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more change ids in the form of ids=ID1&ids=ID2. The maximum number of ids that "
        "can be requested at once is 500.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "updatePolicyHostGroups",
    "PATCH",
    "/filevantage/entities/policies-host-groups/v1",
    "Manage host groups assigned to a policy.",
    "filevantage",
    [
      {
        "type": "string",
        "description": "The id of the policy for which to perform the action.",
        "name": "policy_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The action to perform with the provided ids, must be one of: assign or unassign.",
        "name": "action",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more host group ids in the form of ids=ID1&ids=ID2",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "updatePolicyPrecedence",
    "PATCH",
    "/filevantage/entities/policies-precedence/v1",
    "Updates the policy precedence for all policies of a specific type.",
    "filevantage",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "Precedence of the policies for the provided type in the form of ids=ID1&ids=ID2",
        "name": "ids",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The policy type for which to set the precedence order, must be one of Windows, Linux or Mac.",
        "name": "type",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "updatePolicyRuleGroups",
    "PATCH",
    "/filevantage/entities/policies-rule-groups/v1",
    "Manage the rule groups assigned to the policy or set the rule group precedence for all rule groups within the policy.",
    "filevantage",
    [
      {
        "type": "string",
        "description": "The id of the policy for which to perform the action.",
        "name": "policy_id",
        "in": "query",
        "required": True
      },
      {
        "type": "string",
        "description": "The action to perform with the provided ids, must be one of: assign, unassign, or precedence.",
        "name": "action",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more rule group ids in the form of ids=ID1&ids=ID2. Note, for the precedence "
        "action, precedence is controlled by the order of the ids as they are specified in the request.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getPolicies",
    "GET",
    "/filevantage/entities/policies/v1",
    "Retrieves the configuration for 1 or more policies.",
    "filevantage",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) policy ids in the form of ids=ID1&ids=ID2",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createPolicies",
    "POST",
    "/filevantage/entities/policies/v1",
    "Creates a new policy of the specified type. New policies are always added at the end of the precedence "
    "list for the provided policy type.",
    "filevantage",
    [
      {
        "description": "Create a new policy.\n\n * name must be between 1 and 100 characters.\n\n * "
        "description can be between 0 and 500 characters.\n\n * platform must be one of Windows, Linux, or Mac\n\n Rule "
        "and host group assignment and policy precedence setting is performed via their respective patch end-points.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updatePolicies",
    "PATCH",
    "/filevantage/entities/policies/v1",
    "Updates the general information of the provided policy.",
    "filevantage",
    [
      {
        "description": "Enables updates to the following fields for an existing policy. \n\n * id of the "
        "policy to update.\n\n * name must be between 1 and 100 characters.\n\n * description can be between 0 and 500 "
        "characters.\n\n * platform may not be modified after the policy is created.\n\n * enabled must be one of true "
        "or false.\n\n Rule and host group assignment and policy precedence setting is performed via their respective "
        "patch end-points.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deletePolicies",
    "DELETE",
    "/filevantage/entities/policies/v1",
    "Deletes 1 or more policies.",
    "filevantage",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) policy ids in the form of ids=ID1&ids=ID2",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getScheduledExclusions",
    "GET",
    "/filevantage/entities/policy-scheduled-exclusions/v1",
    "Retrieves the configuration of 1 or more scheduled exclusions from the provided policy id.",
    "filevantage",
    [
      {
        "type": "string",
        "description": "The id of the policy to retrieve the scheduled exclusion configurations.",
        "name": "policy_id",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) scheduled exclusion ids in the form of ids=ID1&ids=ID2.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createScheduledExclusions",
    "POST",
    "/filevantage/entities/policy-scheduled-exclusions/v1",
    "Creates a new scheduled exclusion configuration for the provided policy id.",
    "filevantage",
    [
      {
        "description": "Create a new scheduled exclusion configuration for the specified policy.\n\n \n\n * "
        "policy_id to add the scheduled exclusion to.\n\n * name must be between 1 and 100 characters.\n\n * "
        "description can be between 0 and 500 characters.\n\n * users can be between 0 and 500 characters representing "
        "a comma separated list of user to exclude their changes.\n\n    *  admin* excludes changes made by all "
        "usernames that begin with admin. Falon GLOB syntax is supported.\n\n * processes can be between 0 and 500 "
        "characters representing a comma separated list of processes to exclude their changes.\n\n    * **\\RunMe.exe "
        "or **/RunMe.sh excludes changes made by RunMe.exe or RunMe.sh in any location.\n\n * schedule_start must be "
        "provided to indicate the start of the schedule. This date/time must be an rfc3339 formatted string  "
        "https://datatracker.ietf.org/doc/html/rfc3339.\n\n * schedule_end optionally provided to indicate the end of "
        "the schedule. This date/time must be an rfc3339 formatted string  "
        "https://datatracker.ietf.org/doc/html/rfc3339.\n\n * timezone  must be provided to indicate the TimeZone Name "
        "set for the provided scheduled_start and scheduled_end values. See "
        "https://en.wikipedia.org/wiki/List_of_tz_database_time_zones.\n\n * repeated optionally provided to indicate "
        "that the exclusion is applied repeatedly within the scheduled_start and scheduled_end time.\n\n    * "
        "start_time must be the hour(00-23) and minute(00-59) of the day formatted as HH:MM. Required if all_day is not "
        " set to true\n\n    * end_time must be the hour(00-23) and minute(00-59) of the day formatted as HH:MM. "
        "Required if all_day is not set to true\n\n    * all_day must be true or false to indicate the exclusion is "
        "applied all day. \n\n    * frequency must be one of daily, weekly or monthly. \n\n    * occurrence must be one "
        " of the following when frequency is set to monthly:\n\n      * 1st, 2nd, 3rd, 4th or Last represents the "
        "week.\n\n      * Days represents specific calendar days.\n\n    * weekly_days must be one or more of Monday, "
        "Tuesday, Wednesday, Thursday, Friday, Saturday or Sunday when frequency is set to weekly or frequency is set "
        "to monthly and occurrence is NOT set to Days. \n\n    * monthly_days must be set to one or more calendar days, "
        "between 1 and 31  when frequency is set to monthly and occurrence is set to Days. ",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updateScheduledExclusions",
    "PATCH",
    "/filevantage/entities/policy-scheduled-exclusions/v1",
    "Updates the provided scheduled exclusion configuration within the provided policy.",
    "filevantage",
    [
      {
        "description": "Update an existing scheduled exclusion for the specified policy.\n\n \n\n * policy_id "
        "to add the scheduled exclusion to.\n\n * name must be between 1 and 100 characters.\n\n * description can be "
        "between 0 and 500 characters.\n\n * users can be between 0 and 500 characters representing a comma separated "
        "list of user to exclude their changes.\n\n    *  admin* excludes changes made by all usernames that begin with "
        " admin. Falon GLOB syntax is supported.\n\n * processes can be between 0 and 500 characters representing a "
        "comma separated list of processes to exclude their changes.\n\n    * **\\RunMe.exe or **/RunMe.sh excludes "
        "changes made by RunMe.exe or RunMe.sh in any location.\n\n * schedule_start must be provided to indicate the "
        "start of the schedule. This date/time must be an rfc3339 formatted string  "
        "https://datatracker.ietf.org/doc/html/rfc3339.\n\n * schedule_end optionally provided to indicate the end of "
        "the schedule. This date/time must be an rfc3339 formatted string  "
        "https://datatracker.ietf.org/doc/html/rfc3339.\n\n * timezone  must be provided to indicate the TimeZone Name "
        "set for the provided scheduled_start and scheduled_end values. See "
        "https://en.wikipedia.org/wiki/List_of_tz_database_time_zones.\n\n * repeated optionally provided to indicate "
        "that the exclusion is applied repeatedly within the scheduled_start and scheduled_end time.\n\n    * "
        "start_time must be the hour(00-23) and minute(00-59) of the day formatted as HH:MM. Required if all_day is not "
        " set to true\n\n    * end_time must be the hour(00-23) and minute(00-59) of the day formatted as HH:MM. "
        "Required if all_day is not set to true\n\n    * all_day must be true or false to indicate the exclusion is "
        "applied all day. \n\n    * frequency must be one of daily, weekly or monthly. \n\n    * occurrence must be one "
        " of the following when frequency is set to monthly:\n\n      * 1st, 2nd, 3rd, 4th or Last represents the "
        "week.\n\n      * Days represents specific calendar days.\n\n    * weekly_days must be one or more of Monday, "
        "Tuesday, Wednesday, Thursday, Friday, Saturday or Sunday when frequency is set to weekly or frequency is set "
        "to monthly and occurrence is NOT set to Days. \n\n    * monthly_days must be set to one or more calendar days, "
        "between 1 and 31  when frequency is set to monthly and occurrence is set to Days. ",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteScheduledExclusions",
    "DELETE",
    "/filevantage/entities/policy-scheduled-exclusions/v1",
    "Deletes 1 or more scheduled exclusions from the provided policy id.",
    "filevantage",
    [
      {
        "type": "string",
        "description": "ID of the policy to delete the scheduled exclusions from.",
        "name": "policy_id",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) scheduled exclusion ids in the form of ids=ID1&ids=ID2.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "updateRuleGroupPrecedence",
    "PATCH",
    "/filevantage/entities/rule-groups-rule-precedence/v1",
    "Updates the rule precedence for all rules in the identified rule group.",
    "filevantage",
    [
      {
        "type": "string",
        "description": "Rule group from which to set the precedence.",
        "name": "rule_group_id",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) rule group ids in the form of ids=ID1&ids=ID2.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getRules",
    "GET",
    "/filevantage/entities/rule-groups-rules/v1",
    "Retrieves the configuration for 1 or more rules.",
    "filevantage",
    [
      {
        "type": "string",
        "description": "Rule group from which to retrieve the rule configuration.",
        "name": "rule_group_id",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) rule ids in the form of ids=ID1&ids=ID2.",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createRules",
    "POST",
    "/filevantage/entities/rule-groups-rules/v1",
    "Creates a new rule configuration within the specified rule group.",
    "filevantage",
    [
      {
        "description": "Create a new rule configuration for the specified rule group.\n\n * id is not "
        "supported for creation of a rule, the new id of the created rule will be included in the response.\n\n * "
        "rule_group_id to add the new rule configuration.\n\n * description can be between 0 and 500 characters.\n\n * "
        "path representing the file system or registry path to monitor.\n\n   * must be between 1 and 250 characters. "
        "\n\n   * All paths must end with the path separator, e.g. c:\\windows\\ /usr/bin/ \n\n * severity to "
        "categorize change events produced by this rule; must be one of: Low, Medium, High or Critical\n\n * depth "
        "below the base path to monitor; must be one of: 1, 2, 3, 4, 5 or ANY\n\n * precedence - is not supported for "
        "creation of a rule, new rules will be added last in precedence order.\n\nFalcon GLOB syntax is supported for "
        "the following 6 properties. Allowed rule group configuration is based on the type of rule group the rule group "
        " is added to.\n\n * include represents the files, directories, registry keys, or registry values that will be "
        "monitored. \n\n * exclude represents the files, directories, registry keys, or registry values that will NOT "
        "be monitored. \n\n * include_users represents the changes performed by specific users that will be "
        "monitored.\n\n * exclude_users represents the changes performed by specific users that will NOT be "
        "monitored.\n\n * include_processes represents the changes performed by specific processes that will be "
        "monitored.\n\n * exclude_processes represents the changes performed by specific processes that will be NOT "
        "monitored.\n\n * content_files represents the files whose content will be monitored. Listed files must match "
        "the file include pattern and not match the file exclude pattern\n\n * content_registry_values represents the "
        "registry values whose content will be monitored. Listed registry values must match the registry include "
        "pattern and not match the registry exclude pattern\n\n * enable_content_capture\n\n * "
        "enable_hash_capture\n\nFile system directory monitoring:\n\n * watch_delete_directory_changes\n\n * "
        "watch_create_directory_changes\n\n * watch_rename_directory_changes\n\n * watch_attributes_directory_changes "
        "(macOS is not supported at this time)\n\n * watch_permissions_directory_changes (macOS is not supported at "
        "this time)\n\nFile system file monitoring:\n\n * watch_rename_file_changes\n\n * watch_write_file_changes\n\n "
        "* watch_create_file_changes\n\n * watch_delete_file_changes\n\n * watch_attributes_file_changes (macOS is not "
        "supported at this time)\n\n * watch_permissions_file_changes (macOS is not supported at this time)\n\nWindows "
        "registry key and value monitoring: \n\n * watch_create_key_changes\n\n * watch_delete_key_changes\n\n * "
        "watch_rename_key_changes\n\n * watch_set_value_changes\n\n * watch_permissions_key_changes\n\n * "
        "watch_delete_value_changes\n\n * watch_create_file_changes",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updateRules",
    "PATCH",
    "/filevantage/entities/rule-groups-rules/v1",
    "Updates the provided rule configuration within the specified rule group.",
    "filevantage",
    [
      {
        "description": "Update the rule configuration for the specified rule ID and group.\n\n * id of the "
        "rule to update.\n\n * rule_group_id that contains the rule configuration.\n\n * description can be between 0 "
        "and 500 characters.\n\n * path representing the file system or registry path to monitor.\n\n   * must be "
        "between 1 and 250 characters. \n\n   * All paths must end with the path separator, e.g. c:\\windows\\ "
        "/usr/bin/ \n\n * severity to categorize change events produced by this rule; must be one of: Low, Medium, High "
        " or Critical\n\n * depth below the base path to monitor; must be one of: 1, 2, 3, 4, 5 or ANY\n\n * precedence "
        " is the order in which rules will be evaluated starting with 1. Specifying a precedence value that is already "
        "set for another rule in the group will result this rule being placed before that existing rule.\n\nFalcon GLOB "
        " syntax is supported for the following 6 properties. Allowed rule group configuration is based on the type of "
        "rule group the rule group is added to.\n\n * include represents the files, directories, registry keys, or "
        "registry values that will be monitored. \n\n * exclude represents the files, directories, registry keys, or "
        "registry values that will NOT be monitored. \n\n * include_users represents the changes performed by specific "
        "users that will be monitored.\n\n * exclude_users represents the changes performed by specific users that will "
        " NOT be monitored.\n\n * include_processes represents the changes performed by specific processes that will be "
        " monitored.\n\n * exclude_processes represents the changes performed by specific processes that will be NOT "
        "monitored.\n\n * content_files represents the files that will be monitored. Listed files must match the file "
        "include pattern and not match the file exclude pattern\n\n * content_registry_values represents the registry "
        "values whose content will be monitored. Listed registry values must match the registry include pattern and not "
        " match the registry exclude pattern\n\n * enable_content_capture\n\n * enable_hash_capture\n\nFile system "
        "directory monitoring:\n\n * watch_delete_directory_changes\n\n * watch_create_directory_changes\n\n * "
        "watch_rename_directory_changes\n\n * watch_attributes_directory_changes (macOS is not supported at this "
        "time)\n\n * watch_permissions_directory_changes (macOS is not supported at this time)\n\nFile system file "
        "monitoring:\n\n * watch_rename_file_changes\n\n * watch_write_file_changes\n\n * watch_create_file_changes\n\n "
        " * watch_delete_file_changes\n\n * watch_attributes_file_changes (macOS is not supported at this time)\n\n * "
        "watch_permissions_file_changes (macOS is not supported at this time)\n\nWindows registry key and value "
        "monitoring: \n\n * watch_create_key_changes\n\n * watch_delete_key_changes\n\n * watch_rename_key_changes\n\n "
        "* watch_set_value_changes\n\n * watch_delete_value_changes\n\n * watch_create_file_changes",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteRules",
    "DELETE",
    "/filevantage/entities/rule-groups-rules/v1",
    "Deletes 1 or more rules from the specified rule group.",
    "filevantage",
    [
      {
        "type": "string",
        "description": "The id of the rule group from which the rules will be deleted.",
        "name": "rule_group_id",
        "in": "query",
        "required": True
      },
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) rule ids in the form of ids=ID1&ids=ID2",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "getRuleGroups",
    "GET",
    "/filevantage/entities/rule-groups/v1",
    "Retrieves the rule group details for 1 or more rule groups.",
    "filevantage",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) rule group ids in the form of ids=ID1&ids=ID2",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "createRuleGroups",
    "POST",
    "/filevantage/entities/rule-groups/v1",
    "Creates a new rule group of the specified type.",
    "filevantage",
    [
      {
        "description": "Create a new rule group of a specific type.\n\n * name must be between 1 and 100 "
        "characters.\n\n * type must be one of WindowsFiles, WindowsRegistry, LinuxFiles or MacFiles.\n\n * description "
        " can be between 0 and 500 characters.\n\n Note: rules are added/removed from rule groups using their dedicated "
        "end-points.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "updateRuleGroups",
    "PATCH",
    "/filevantage/entities/rule-groups/v1",
    "Updates the provided rule group.",
    "filevantage",
    [
      {
        "description": "Enables updates to the following fields for an existing rule group. \n\n * id of the "
        "rule group to update.\n\n * name must be between 1 and 100 characters.\n\n * description can be between 0 and "
        "500 characters.\n\n * type may not be modified after the rule group is created.\n\n Note: rules are "
        "added/removed from rule groups using their dedicated end-points.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "deleteRuleGroups",
    "DELETE",
    "/filevantage/entities/rule-groups/v1",
    "Deletes 1 or more rule groups ",
    "filevantage",
    [
      {
        "type": "array",
        "items": {
          "type": "string"
        },
        "collectionFormat": "multi",
        "description": "One or more (up to 500) rule group ids in the form of ids=ID1&ids=ID2",
        "name": "ids",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "signalChangesExternal",
    "POST",
    "/filevantage/entities/workflow/v1",
    "Initiates workflows for the provided change ids",
    "filevantage",
    [
      {
        "description": "Change ids to initiate the workflows; limited to 100 per request.",
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "queryActionsMixin0",
    "GET",
    "/filevantage/queries/actions/v1",
    "Returns one or more action ids",
    "filevantage",
    [
      {
        "minimum": 0,
        "type": "integer",
        "description": "The first action index to return in the response. If not provided it will default to "
        "'0'. Use with the limit parameter to manage pagination of results.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of actions to return in the response (default: 100; max: 500). Use "
        "with the offset parameter to manage pagination of results",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The sort expression that should be used to sort the results (e.g. created_date|desc)",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter changes using a query in Falcon Query Language (FQL). \n\nCommon filter options "
        " include:\n\n - status\n - operation_type\n\n The full list of allowed filter parameters can be reviewed in "
        "our API documentation.",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "queryChanges",
    "GET",
    "/filevantage/queries/changes/v2",
    "Returns 1 or more change ids",
    "filevantage",
    [
      {
        "minimum": 0,
        "type": "integer",
        "default": 0,
        "description": "The offset to start retrieving records from. Defaults to 0 if not specified.",
        "name": "offset",
        "in": "query"
      },
      {
        "maximum": 500,
        "type": "integer",
        "default": 100,
        "description": "The maximum number of ids to return. Defaults to 100 if not specified. The maximum "
        "number of results that can be returned in a single call is 500.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort results using options like:\n  action_timestamp (timestamp of the change "
        "occurrence) \n\nSort either asc (ascending) or desc (descending). For example: action_timestamp|asc.\nThe full "
        "list of allowed sorting options can be reviewed in our API documentation.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter changes using a query in Falcon Query Language (FQL). \n\nCommon filter options "
        " include:\n\n - host.name\n - action_timestamp\n\n The full list of allowed filter parameters can be reviewed "
        "in our API documentation.",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "highVolumeQueryChanges",
    "GET",
    "/filevantage/queries/changes/v3",
    "Returns 1 or more change ids",
    "filevantage",
    [
      {
        "type": "string",
        "description": "A pagination token used with the limit parameter to manage pagination of results. On "
        "your first request don't provide a value for the after token. On subsequent requests provide the after token "
        "value from the previous response to continue pagination from where you left. If the response returns an empty "
        "after token it means there are no more results to return.",
        "name": "after",
        "in": "query"
      },
      {
        "maximum": 5000,
        "type": "integer",
        "default": 100,
        "description": "The maximum number of ids to return. Defaults to 100 if not specified. The maximum "
        "number of results that can be returned in a single call is 5000.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "default": "action_timestamp|desc",
        "description": "Sort results using options like:\n  action_timestamp (timestamp of the change "
        "occurrence) \n\nSort either asc (ascending) or desc (descending). For example: action_timestamp|asc. Defaults "
        "to action_timestamp|desc no value is specified.\nThe full list of allowed sorting options can be reviewed in "
        "our API documentation.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Filter changes using a query in Falcon Query Language (FQL). \n\nCommon filter options "
        " include:\n\n - host.name\n - action_timestamp\n\n The full list of allowed filter parameters can be reviewed "
        "in our API documentation.",
        "name": "filter",
        "in": "query"
      }
    ]
  ],
  [
    "queryPolicies",
    "GET",
    "/filevantage/queries/policies/v1",
    "Retrieve the ids of all policies that are assigned the provided policy type.",
    "filevantage",
    [
      {
        "minimum": 0,
        "type": "integer",
        "description": "The offset to start retrieving records from. Defaults to 0 if not specified.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of ids to return. Defaults to 100 if not specified. The maximum "
        "number of results that can be returned in a single call is 500.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort the returned ids based on one of the following properties:\n\nprecedence, "
        "created_timestamp or modified_timestamp\n\n Sort either asc (ascending) or desc (descending);  for example: "
        "precedence|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The types of policies to retrieve.\n\n Allowed values are: Windows, Linux or Mac.",
        "name": "type",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queryScheduledExclusions",
    "GET",
    "/filevantage/queries/policy-scheduled-exclusions/v1",
    "Retrieve the ids of all scheduled exclusions contained within the provided policy id.",
    "filevantage",
    [
      {
        "type": "string",
        "description": "The id of the policy from which to retrieve the scheduled exclusion ids.",
        "name": "policy_id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "queryRuleGroups",
    "GET",
    "/filevantage/queries/rule-groups/v1",
    "Retrieve the ids of all rule groups that are of the provided rule group type.",
    "filevantage",
    [
      {
        "minimum": 0,
        "type": "integer",
        "description": "The offset to start retrieving records from. Defaults to 0 if not specified.",
        "name": "offset",
        "in": "query"
      },
      {
        "type": "integer",
        "description": "The maximum number of ids to return. Defaults to 100 if not specified. The maximum "
        "number of results that can be returned in a single call is 500.",
        "name": "limit",
        "in": "query"
      },
      {
        "type": "string",
        "description": "Sort the returned ids based on one of the following properties:\n\n created_timestamp "
        "or modified_timestamp\n\n Sort either asc (ascending) or desc (descending);  for example: "
        "created_timestamp|asc.",
        "name": "sort",
        "in": "query"
      },
      {
        "type": "string",
        "description": "The rule group type to retrieve the ids of.\n\n Allowed values are: WindowsFiles, "
        "WindowsRegistry, LinuxFiles or MacFiles.",
        "name": "type",
        "in": "query",
        "required": True
      }
    ]
  ]
]
