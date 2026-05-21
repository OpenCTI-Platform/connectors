"""The CrowdStrike Falcon OAuth2 API SDK.

 @@@@@@@  @@@@@@@    @@@@@@   @@@  @@@  @@@  @@@@@@@    @@@@@@   @@@@@@@  @@@@@@@   @@@  @@@  @@@  @@@@@@@@
@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@  @@@@@@@@  @@@@@@@   @@@@@@@  @@@@@@@@  @@@  @@@  @@@  @@@@@@@@
!@@       @@!  @@@  @@!  @@@  @@!  @@!  @@!  @@!  @@@  !@@         @@!    @@!  @@@  @@!  @@!  !@@  @@!
!@!       !@!  @!@  !@!  @!@  !@!  !@!  !@!  !@!  @!@  !@!         !@!    !@!  @!@  !@!  !@!  @!!  !@!
!@!       @!@!!@!   @!@  !@!  @!!  !!@  @!@  @!@  !@!  !!@@!!      @!!    @!@!!@!   !!@  @!@@!@!   @!!!:!
!!!       !!@!@!    !@!  !!!  !@!  !!!  !@!  !@!  !!!   !!@!!!     !!!    !!@!@!    !!!  !!@!!!    !!!!!:
:!!       !!: :!!   !!:  !!!  !!:  !!:  !!:  !!:  !!!       !:!    !!:    !!: :!!   !!:  !!: :!!   !!:
:!:       :!:  !:!  :!:  !:!  :!:  :!:  :!:  :!:  !:!      !:!     :!:    :!:  !:!  :!:  :!:  !:!  :!:
 ::: :::  ::   :::  ::::: ::   :::: :: :::    :::: ::  :::: ::      ::    ::   :::   ::   ::  :::   :: ::::
 :: :: :   :   : :   : :  :     :: :  : :    :: :  :   :: : :       :      :   : :  :     :   :::  : :: ::

                                                         _______       __                  _______
                                                        |   _   .---.-|  .----.-----.-----|   _   .--.--.
                                                        |.  1___|  _  |  |  __|  _  |     |.  1   |  |  |
                                                        |.  __) |___._|__|____|_____|__|__|.  ____|___  |
                                                        |:  |                             |:  |   |_____|
                                                        |::.|     CrowdStrike Falcon      |::.|
                                                        `---' OAuth2 API SDK for Python 3 `---'
"""
from ._version import _VERSION, _MAINTAINER, _AUTHOR, _AUTHOR_EMAIL
from ._version import _CREDITS, _DESCRIPTION, _TITLE, _PROJECT_URL
from ._version import _DOCS_URL, _KEYWORDS, version
from ._auth_object import (
    BaseFalconAuth,
    BearerToken,
    FalconInterface,
    UberInterface,
    InterfaceConfiguration
    )
from ._service_class import BaseServiceClass, ServiceClass
from ._util import confirm_base_region, confirm_base_url
from ._constant import (
    MAX_DEBUG_RECORDS,
    ALLOWED_METHODS,
    USER_AGENT,
    MIN_TOKEN_RENEW_WINDOW,
    MAX_TOKEN_RENEW_WINDOW,
    GLOBAL_API_MAX_RETURN,
    MOCK_OPERATIONS
    )
from ._enum import (
    BaseURL,
    ContainerBaseURL,
    TokenFailReason,
    IngestBaseURL,
    IngestFormat,
    TimeUnit
    )
from ._log import LogFacility
from ._error import (
    APIError,
    SDKError,
    SDKWarning,
    NoContentWarning,
    SSLDisabledWarning,
    RegionSelectError,
    InvalidCredentials,
    InvalidMethod,
    InvalidOperation,
    TokenNotSpecified,
    KeywordsOnly,
    CannotRevokeToken,
    FunctionalityNotImplemented,
    InvalidBaseURL,
    PayloadValidationError,
    NoAuthenticationMechanism,
    InvalidIndex,
    InvalidCredentialFormat,
    UnnecessaryEncodingUsed,
    DeprecatedClass,
    DeprecatedOperation,
    SDKDeprecationWarning,
    InvalidRoute,
    InvalidServiceCollection,
    InvalidOperationSearch
    )
from ._result import (
    Result,
    ExpandedResult,
    BaseDictionary,
    BaseResource,
    Resources,
    ResponseComponent,
    Meta,
    Headers,
    Errors,
    RawBody,
    BinaryFile
    )
from ._api_request import (
    APIRequest,
    RequestBehavior,
    RequestConnection,
    RequestMeta,
    RequestPayloads,
    RequestValidator
    )
from ._ngsiem import (
    HTTPEventCollector,
    HEC,
    IngestPayload,
    IngestConfig,
    SessionManager
)
from ._helper import random_string, Indicator, Color, find_operation
from .alerts import Alerts
from .api_integrations import APIIntegrations
from .api_complete import APIHarness, APIHarnessV2
from .aspm import ASPM
from .cao_hunting import CAOHunting
from .case_management import CaseManagement
from .certificate_based_exclusions import CertificateBasedExclusions
from .cloud_aws_registration import CloudAWSRegistration
from .cloud_azure_registration import CloudAzureRegistration
from .cloud_google_cloud_registration import CloudGoogleCloudRegistration
from .cloud_oci_registration import CloudOCIRegistration
from .cloud_policies import CloudPolicies
from .cloud_security import CloudSecurity
from .cloud_security_assets import CloudSecurityAssets
from .cloud_security_compliance import CloudSecurityCompliance
from .cloud_security_detections import CloudSecurityDetections
from .cloud_snapshots import CloudSnapshots
from .container_image_compliance import ContainerImageCompliance, ComplianceAssessments
from .configuration_assessment_evaluation_logic import ConfigurationAssessmentEvaluationLogic
from .configuration_assessment import ConfigurationAssessment
from .container_alerts import ContainerAlerts
from .container_detections import ContainerDetections
from .container_images import ContainerImages
from .container_packages import ContainerPackages
from .container_vulnerabilities import ContainerVulnerabilities
from .correlation_rules import CorrelationRules
from .correlation_rules_admin import CorrelationRulesAdmin
from .cloud_connect_aws import CloudConnectAWS
from .content_update_policies import ContentUpdatePolicies
from .cspm_registration import CSPMRegistration
from .custom_ioa import CustomIOA
from .custom_storage import CustomStorage
from .d4c_registration import D4CRegistration
from .data_protection_configuration import DataProtectionConfiguration
from .delivery_settings import DeliverySettings
from .deployments import Deployments
from .detects import Detects
from .device_content import DeviceContent
from .device_control_policies import DeviceControlPolicies
from .discover import Discover
from .downloads import Downloads
from .drift_indicators import DriftIndicators
from .event_streams import EventStreams
from .exposure_management import ExposureManagement
from .faas_execution import FaaSExecution
from .falcon_complete_dashboard import CompleteDashboard
from .falcon_container import FalconContainer
from .falconx_sandbox import FalconXSandbox
from .fdr import FDR
from .filevantage import FileVantage
from .firewall_management import FirewallManagement
from .firewall_policies import FirewallPolicies
from .foundry_logscale import FoundryLogScale
from .host_group import HostGroup
from .hosts import Hosts
from .host_migration import HostMigration
from .identity_protection import IdentityProtection
from .image_assessment_policies import ImageAssessmentPolicies
from .incidents import Incidents
from .intelligence_indicator_graph import IntelligenceIndicatorGraph
from .installation_tokens import InstallationTokens
from .intel import Intel
from .intelligence_feeds import IntelligenceFeeds
from .ioa_exclusions import IOAExclusions
from .ioc import IOC
from .iocs import Iocs
from .it_automation import ITAutomation, F4IT
from .kubernetes_container_compliance import KubernetesContainerCompliance
from .kubernetes_protection import KubernetesProtection
from .malquery import MalQuery
from .message_center import MessageCenter
from .ml_exclusions import MLExclusions
from .mobile_enrollment import MobileEnrollment
from .mssp import FlightControl
from .ngsiem import NGSIEM
from .oauth2 import OAuth2
from .ods import ODS
from .overwatch_dashboard import OverwatchDashboard
from .prevention_policy import PreventionPolicy, PreventionPolicies
from .quarantine import Quarantine
from .quick_scan import QuickScan
from .quick_scan_pro import QuickScanPro
from .real_time_response_admin import RealTimeResponseAdmin
from .real_time_response_audit import RealTimeResponseAudit
from .real_time_response import RealTimeResponse
from .recon import Recon
from .report_executions import ReportExecutions
from .response_policies import ResponsePolicies
from .saas_security import SaasSecurity
from .sample_uploads import SampleUploads
from .scheduled_reports import ScheduledReports
from .sensor_download import SensorDownload
from .sensor_update_policy import SensorUpdatePolicy, SensorUpdatePolicies
from .sensor_usage import SensorUsage
from .sensor_visibility_exclusions import SensorVisibilityExclusions
from .serverless_vulnerabilities import ServerlessVulnerabilities
from .spotlight_vulnerabilities import SpotlightVulnerabilities
from .spotlight_vulnerability_metadata import SpotlightVulnerabilityMetadata
from .spotlight_evaluation_logic import SpotlightEvaluationLogic
from .tailored_intelligence import TailoredIntelligence
from .threatgraph import ThreatGraph
from .unidentified_containers import UnidentifiedContainers
from .user_management import UserManagement
from .workflows import Workflows
from .zero_trust_assessment import ZeroTrustAssessment

__version__ = _VERSION
__maintainer__ = _MAINTAINER
__author__ = _AUTHOR
__author_email__ = _AUTHOR_EMAIL
__credits__ = _CREDITS
__description__ = _DESCRIPTION
__title__ = _TITLE
__project_url__ = _PROJECT_URL
__docs_url__ = _DOCS_URL
__keywords__ = _KEYWORDS
__all__ = [
    "confirm_base_url", "confirm_base_region", "BaseURL", "ServiceClass", "Alerts",
    "BaseServiceClass", "BaseFalconAuth", "FalconInterface", "UberInterface", "TokenFailReason",
    "APIHarness", "CloudConnectAWS", "CSPMRegistration", "CustomIOA", "D4CRegistration",
    "Detects", "DeviceControlPolicies", "Discover", "EventStreams", "CompleteDashboard",
    "FalconContainer", "FalconXSandbox", "FirewallManagement", "FirewallPolicies", "HostGroup",
    "Hosts", "IdentityProtection", "Incidents", "InstallationTokens", "Intel", "IOAExclusions",
    "IOC", "Iocs", "KubernetesProtection", "MalQuery", "MLExclusions", "FlightControl", "OAuth2",
    "OverwatchDashboard", "PreventionPolicy", "Quarantine", "QuickScan", "RealTimeResponseAdmin",
    "RealTimeResponse", "Recon", "ReportExecutions", "ResponsePolicies", "SampleUploads",
    "ScheduledReports", "SensorDownload", "SensorUpdatePolicy", "SensorVisibilityExclusions",
    "SpotlightVulnerabilities", "SpotlightEvaluationLogic", "UserManagement", "MAX_DEBUG_RECORDS",
    "ZeroTrustAssessment", "PreventionPolicies", "SensorUpdatePolicies", "MessageCenter",
    "FileVantage", "MobileEnrollment", "ContainerBaseURL", "TailoredIntelligence", "ODS", "FDR",
    "Result", "APIError", "SDKError", "SDKWarning", "NoContentWarning", "SSLDisabledWarning",
    "RegionSelectError", "InvalidCredentials", "InvalidMethod", "InvalidOperation",
    "TokenNotSpecified", "KeywordsOnly", "ALLOWED_METHODS", "USER_AGENT", "APIRequest",
    "ExpandedResult", "CannotRevokeToken", "Headers", "Meta", "Resources",
    "ResponseComponent", "BaseDictionary", "Errors", "BaseResource", "RawBody", "BinaryFile",
    "FunctionalityNotImplemented", "BearerToken", "LogFacility", "InvalidBaseURL",
    "InterfaceConfiguration", "RequestBehavior", "RequestConnection", "RequestMeta",
    "RequestPayloads", "RequestValidator", "PayloadValidationError", "MIN_TOKEN_RENEW_WINDOW",
    "MAX_TOKEN_RENEW_WINDOW", "GLOBAL_API_MAX_RETURN", "MOCK_OPERATIONS", "CloudSnapshots",
    "NoAuthenticationMechanism", "InvalidIndex", "version", "InvalidCredentialFormat",
    "UnnecessaryEncodingUsed", "APIHarnessV2", "CustomStorage", "FoundryLogScale",
    "RealTimeResponseAudit", "Workflows", "DeprecatedClass", "DeprecatedOperation",
    "SDKDeprecationWarning", "ConfigurationAssessmentEvaluationLogic", "ConfigurationAssessment",
    "ContainerAlerts", "ContainerDetections", "ContainerImages", "ContainerPackages",
    "ContainerVulnerabilities", "DriftIndicators", "UnidentifiedContainers",
    "ImageAssessmentPolicies", "APIIntegrations", "ThreatGraph", "ExposureManagement",
    "CertificateBasedExclusions", "ComplianceAssessments", "HostMigration", "QuickScanPro",
    "SensorUsage", "Downloads", "DeliverySettings", "ASPM", "IntelligenceFeeds",
    "NGSIEM", "CorrelationRules", "CloudAWSRegistration", "CloudAzureRegistration",
    "CloudOCIRegistration", "CloudSecurityAssets", "Deployments", "ServerlessVulnerabilities",
    "DeviceContent", "IntelligenceIndicatorGraph", "ContentUpdatePolicies", "CAOHunting",
    "ContainerImageCompliance", "FaaSExecution", "HEC", "IngestBaseURL", "IngestFormat",
    "IngestPayload", "HTTPEventCollector", "IngestConfig", "SessionManager", "TimeUnit",
    "Color", "Indicator", "random_string", "KubernetesContainerCompliance", "find_operation",
    "InvalidRoute", "InvalidServiceCollection", "InvalidOperationSearch", "ITAutomation", "F4IT",
    "CloudSecurityCompliance", "CaseManagement", "SaasSecurity", "SpotlightVulnerabilityMetadata",
    "DataProtectionConfiguration", "CorrelationRulesAdmin", "CloudSecurityDetections",
    "CloudPolicies", "CloudGoogleCloudRegistration", "CloudSecurity"
    ]
"""
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

⢻⣄
 ⠹⣿⣦         ⣦
  ⠈⣿⣿⣶⡀      ⠈⢿⣦
    ⠙⣿⣿⣿⣄      ⠹⣿⣶
      ⠙⣿⣿⣿⣶⣀     ⠻⣿⣿⣤
   ⠹⣄   ⠈⠻⣿⣿⣿⣶⡀    ⠙⢿⣿⣿⣤
    ⠙⣿⣦    ⠙⢿⣿⣿⣿⣶⣀   ⠈⠛⣿⣿⣿⣶⣄
      ⠛⣿⣷⣤    ⠙⢿⣿⣿⣿⣷⣤   ⠈⠛⣿⣿⣿⣿⣶⣤
        ⠙⣿⣿⣷⣤    ⠉⠻⣿⣿⣿⣿⣦⡀  ⠈⠻⣿⣿⣿⣿⣿⣿⣶⣤⣀
          ⠈⠛⣿⣿⣿⣶⡀   ⠈⠙⢿⣿⣿⣿⣶⡀  ⠉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣄⡀
             ⠈⠙⢿⣿⣿⣷⣤⡀   ⠉⠛⢿⣿⣿⣄  ⠉⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣤⣄
                 ⠉⠛⢿⣿⣿⣿⣤⡀   ⠙⢿⣿⣦  ⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣄⡀
                     ⠉⠛⢿⣿⣿⣶⣄   ⠙⣿⡀ ⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀
                          ⠉⠻⣿⣷⣄  ⠙⡄  ⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶
                              ⠙⢿⣦     ⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
                                 ⠻⣆    ⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
                  ⠈⠲⣀              ⠁     ⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁
                     ⠻⣷⣤⣀    ⠛⢶⣤⣀         ⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
                       ⠈⠛⣿⣿⣿⣶⣶⣶⣼⣿⣿⣷⣦⡀   ⣀   ⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣤⣄
                           ⠈⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⣶⡀ ⠈⢶⣤   ⠉⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣀
                                  ⠉⠙⠛⠿⣿⣿⣿⣦  ⠻⣿⣷⣶⣤⣀⣀⣀ ⣀⣀⣀⣤⣤⣴⣶⣶⣶⣶⣶⣶⣮⣭⣉⠛⠿⣿⣿⣿⣿⣦⠙⣷
                                         ⠉⠛⠶⡀ ⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣍⠻⣿⣿⣿⣷⡀
                                                ⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠷⠌⠻⣿⣿⣦
                                               ⠉⣶⣀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠉           ⠙⣿
                                                 ⠉⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧
     WE  STOP                                        ⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣤⣤⣤
     BREACHES                                          ⠈⠙⠛⠿⠛⠉⣿⣿⣿⠋     ⢿⡇
                                                             ⢻⣿⣄      ⠈⠈
                                                               ⠈⠉ FalconPy
"""
