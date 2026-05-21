"""FalconPy constant module.

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
from typing import List
from .._version import version
PREFER_NONETYPE: List[str] = [
    "report_executions_download_get", "report_executions_download.get",
    "RTR_ListFiles", "RTR_ListFilesV2", "RTR_GetExtractedFileContents",
    "RTR_DeleteSession"
]
PREFER_IDS_IN_BODY: List[str] = [
    "GetBehaviors", "GetCaseActivityByIds", "GetCaseEntitiesByIDs", "GetDetectSummaries",
    "GetEventsEntities", "GetHostMigrationsV1", "GetIncidents", "GetIntelIndicatorEntities",
    "GetQuarantineFiles", "GetRulesEntities", "GetSensorDetails", "GetVulnerabilities",
    "HostMigrationsActionsV1", "MigrationsActionsV1", "PatchEntitiesAlertsV2", "PerformActionV2",
    "PerformIncidentAction", "PostDeviceDetailsV2", "PostEntitiesAlertsV1", "PostMitreAttacks",
    "QueryDeviceLoginHistory", "QueryDeviceLoginHistoryV2", "QueryGetNetworkAddressHistoryV1",
    "RTR_ListQueuedSessions", "RTR_ListSessions", "UpdateDetectsByIdsV2", "cancel_scans",
    "UpdateQuarantinedDetectsByIds", "WorkflowExecutionsAction", "get_rules_get", "getChildrenV2",
    "performContentUpdatePoliciesAction", "performDeviceControlPoliciesAction", "userActionV1",
    "performFirewallPoliciesAction", "performGroupAction", "performPreventionPoliciesAction",
    "performRTResponsePoliciesAction", "performSensorUpdatePoliciesAction", "retrieveUsersGETV1",
    "setContentUpdatePoliciesPrecedence", "setDeviceControlPoliciesPrecedence",
    "setFirewallPoliciesPrecedence", "setPreventionPoliciesPrecedence", "signalChangesExternal",
    "setRTResponsePoliciesPrecedence", "setSensorUpdatePoliciesPrecedence", "GetDeviceDetails",
    "CreateSavedSearchesDeployV1", "cancel-scans", "get-rules-get", "WorkflowDefinitionsStatus",
    "WorkflowDefinitionsAction"
]
MOCK_OPERATIONS: List[str] = [
    "GetImageAssessmentReport", "DeleteImageDetails", "ImageMatchesPolicy"
]
# Restrict requests to only allowed HTTP methods
ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "PATCH", "DELETE", "UPDATE", "HEAD"]
# Default user-agent string
USER_AGENT: str = version(agent_string=True)
# Default maximum number of records to write to debug logs (when active)
MAX_DEBUG_RECORDS: int = 100
# Global maximum number of records returned from any endpoint across all service collections
GLOBAL_API_MAX_RETURN: int = 5000
# Largest available token renew window (in seconds).
MAX_TOKEN_RENEW_WINDOW: int = 1200
# Minimum available token renew window (in seconds).
MIN_TOKEN_RENEW_WINDOW: int = 120
# Maximum length for strings generated with the random_string function (in seconds).
MAX_RANDOM_STRING_LENGTH: int = 4096
