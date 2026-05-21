"""The CrowdStrike Falcon OAuth2 API SDK endpoints module.

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
from typing import List, Any
from .deprecated import _case_management_deprecated
from .deprecated import _cloud_aws_registration_deprecated
from .deprecated import _cloud_azure_registration_deprecated
from .deprecated import _cloud_google_cloud_registration_deprecated
from .deprecated import _cloud_oci_registration_deprecated
from .deprecated import _cloud_security_deprecated
from .deprecated import _cloud_security_assets_deprecated
from .deprecated import _cloud_security_compliance_deprecated
from .deprecated import _cloud_security_detections_deprecated
from .deprecated import _correlation_rules_admin_deprecated
from .deprecated import _correlation_rules_deprecated
from .deprecated import _custom_ioa_deprecated
from .deprecated import _d4c_registration_deprecated
from .deprecated import _data_protection_configuration_deprecated
from .deprecated import _device_content_deprecated
from .deprecated import _discover_deprecated
from .deprecated import _fdr_deprecated
from .deprecated import _firewall_management_deprecated
from .deprecated import _hosts_deprecated
from .deprecated import _identity_protection_deprecated
from .deprecated import _installation_tokens_deprecated
from .deprecated import _ioc_deprecated
from .deprecated import _iocs_deprecated
from .deprecated import _ods_deprecated
from .deprecated import _real_time_response_deprecated
from .deprecated import _real_time_response_admin_deprecated
from .deprecated import _report_executions_deprecated
from .deprecated import _scheduled_reports_deprecated
from .deprecated import _zero_trust_assessment_deprecated
from .deprecated import _certificate_based_exclusions_deprecated
from .deprecated import _deprecated_operation_mapping
from .deprecated import _deprecated_class_mapping

from ._alerts import _alerts_endpoints
from ._api_integrations import _api_integrations_endpoints
from ._aspm import _aspm_endpoints
from ._cao_hunting import _cao_hunting_endpoints
from ._case_management import _case_management_endpoints
from ._certificate_based_exclusions import _certificate_based_exclusions_endpoints
from ._cloud_aws_registration import _cloud_aws_registration_endpoints
from ._cloud_azure_registration import _cloud_azure_registration_endpoints
from ._cloud_google_cloud_registration import _cloud_google_cloud_registration_endpoints
from ._cloud_oci_registration import _cloud_oci_registration_endpoints
from ._cloud_policies import _cloud_policies_endpoints
from ._cloud_security import _cloud_security_endpoints
from ._cloud_security_assets import _cloud_security_assets_endpoints
from ._cloud_security_compliance import _cloud_security_compliance_endpoints
from ._cloud_security_detections import _cloud_security_detections_endpoints
from ._cloud_connect_aws import _cloud_connect_aws_endpoints
from ._cloud_snapshots import _cloud_snapshots_endpoints
from ._container_image_compliance import _container_image_compliance_endpoints
from ._configuration_assessment_evaluation_logic import _configuration_assessment_evaluation_logic_endpoints
from ._configuration_assessment import _configuration_assessment_endpoints
from ._container_alerts import _container_alerts_endpoints
from ._container_detections import _container_detections_endpoints
from ._container_images import _container_images_endpoints
from ._container_packages import _container_packages_endpoints
from ._container_vulnerabilities import _container_vulnerabilities_endpoints
from ._content_update_policies import _content_update_policies_endpoints
from ._correlation_rules import _correlation_rules_endpoints
from ._correlation_rules_admin import _correlation_rules_admin_endpoints
from ._cspm_registration import _cspm_registration_endpoints
from ._custom_ioa import _custom_ioa_endpoints
from ._custom_storage import _custom_storage_endpoints
from ._d4c_registration import _d4c_registration_endpoints
from ._data_protection_configuration import _data_protection_configuration_endpoints
from ._delivery_settings import _delivery_settings_endpoints
from ._deployments import _deployments_endpoints
from ._detects import _detects_endpoints
from ._device_content import _device_content_endpoints
from ._device_control_policies import _device_control_policies_endpoints
from ._discover import _discover_endpoints
from ._downloads import _downloads_endpoints
from ._drift_indicators import _drift_indicators_endpoints
from ._event_streams import _event_streams_endpoints
from ._exposure_management import _exposure_management_endpoints
from ._faas_execution import _faas_execution_endpoints
from ._falcon_complete_dashboard import _falcon_complete_dashboard_endpoints
from ._falcon_container import _falcon_container_endpoints
from ._falconx_sandbox import _falconx_sandbox_endpoints
from ._fdr import _fdr_endpoints
from ._filevantage import _filevantage_endpoints
from ._firewall_management import _firewall_management_endpoints
from ._firewall_policies import _firewall_policies_endpoints
from ._foundry_logscale import _foundry_logscale_endpoints
from ._host_group import _host_group_endpoints
from ._hosts import _hosts_endpoints
from ._host_migration import _host_migration_endpoints
from ._identity_protection import _identity_protection_endpoints
from ._image_assessment_policies import _image_assessment_policies_endpoints
from ._incidents import _incidents_endpoints
from ._intelligence_indicator_graph import _intelligence_indicator_graph_endpoints
from ._intelligence_feeds import _intelligence_feeds_endpoints
from ._installation_tokens import _installation_tokens_endpoints
from ._intel import _intel_endpoints
from ._ioa_exclusions import _ioa_exclusions_endpoints
from ._ioc import _ioc_endpoints
from ._iocs import _iocs_endpoints
from ._it_automation import _it_automation_endpoints
from ._kubernetes_container_compliance import _kubernetes_container_compliance_endpoints
from ._kubernetes_protection import _kubernetes_protection_endpoints
from ._malquery import _malquery_endpoints
from ._message_center import _message_center_endpoints
from ._ml_exclusions import _ml_exclusions_endpoints
from ._mobile_enrollment import _mobile_enrollment_endpoints
from ._mssp import _mssp_endpoints
from ._ngsiem import _ngsiem_endpoints
from ._oauth2 import _oauth2_endpoints
from ._ods import _ods_endpoints
from ._overwatch_dashboard import _overwatch_dashboard_endpoints
from ._prevention_policies import _prevention_policies_endpoints
from ._quarantine import _quarantine_endpoints
from ._quick_scan import _quick_scan_endpoints
from ._quick_scan_pro import _quick_scan_pro_endpoints
from ._real_time_response import _real_time_response_endpoints
from ._real_time_response_admin import _real_time_response_admin_endpoints
from ._real_time_response_audit import _real_time_response_audit_endpoints
from ._recon import _recon_endpoints
from ._report_executions import _report_executions_endpoints
from ._response_policies import _response_policies_endpoints
from ._saas_security import _saas_security_endpoints
from ._sample_uploads import _sample_uploads_endpoints
from ._scheduled_reports import _scheduled_reports_endpoints
from ._sensor_download import _sensor_download_endpoints
from ._sensor_update_policies import _sensor_update_policies_endpoints
from ._sensor_usage import _sensor_usage_endpoints
from ._sensor_visibility_exclusions import _sensor_visibility_exclusions_endpoints
from ._serverless_vulnerabilities import _serverless_vulnerabilities_endpoints
from ._spotlight_evaluation_logic import _spotlight_evaluation_logic_endpoints
from ._spotlight_vulnerabilities import _spotlight_vulnerabilities_endpoints
from ._spotlight_vulnerability_metadata import _spotlight_vulnerability_metadata_endpoints
from ._tailored_intelligence import _tailored_intelligence_endpoints
from ._threatgraph import _threatgraph_endpoints
from ._unidentified_containers import _unidentified_containers_endpoints
from ._user_management import _user_management_endpoints
from ._workflows import _workflows_endpoints
from ._zero_trust_assessment import _zero_trust_assessment_endpoints

api_endpoints: List[Any] = []
api_endpoints.extend(_alerts_endpoints)
api_endpoints.extend(_api_integrations_endpoints)
api_endpoints.extend(_aspm_endpoints)
api_endpoints.extend(_cao_hunting_endpoints)
api_endpoints.extend(_case_management_endpoints)
api_endpoints.extend(_certificate_based_exclusions_endpoints)
api_endpoints.extend(_cloud_connect_aws_endpoints)
api_endpoints.extend(_cloud_aws_registration_endpoints)
api_endpoints.extend(_cloud_azure_registration_endpoints)
api_endpoints.extend(_cloud_google_cloud_registration_endpoints)
api_endpoints.extend(_cloud_oci_registration_endpoints)
api_endpoints.extend(_cloud_policies_endpoints)
api_endpoints.extend(_cloud_security_endpoints)
api_endpoints.extend(_cloud_security_assets_endpoints)
api_endpoints.extend(_cloud_security_compliance_endpoints)
api_endpoints.extend(_cloud_security_detections_endpoints)
api_endpoints.extend(_cloud_snapshots_endpoints)
api_endpoints.extend(_container_image_compliance_endpoints)
api_endpoints.extend(_configuration_assessment_evaluation_logic_endpoints)
api_endpoints.extend(_configuration_assessment_endpoints)
api_endpoints.extend(_container_alerts_endpoints)
api_endpoints.extend(_container_detections_endpoints)
api_endpoints.extend(_container_images_endpoints)
api_endpoints.extend(_container_packages_endpoints)
api_endpoints.extend(_container_vulnerabilities_endpoints)
api_endpoints.extend(_content_update_policies_endpoints)
api_endpoints.extend(_correlation_rules_admin_endpoints)
api_endpoints.extend(_correlation_rules_endpoints)
api_endpoints.extend(_cspm_registration_endpoints)
api_endpoints.extend(_custom_ioa_endpoints)
api_endpoints.extend(_custom_storage_endpoints)
api_endpoints.extend(_d4c_registration_endpoints)
api_endpoints.extend(_data_protection_configuration_endpoints)
api_endpoints.extend(_delivery_settings_endpoints)
api_endpoints.extend(_detects_endpoints)
api_endpoints.extend(_device_content_endpoints)
api_endpoints.extend(_device_control_policies_endpoints)
api_endpoints.extend(_discover_endpoints)
api_endpoints.extend(_deployments_endpoints)
api_endpoints.extend(_downloads_endpoints)
api_endpoints.extend(_drift_indicators_endpoints)
api_endpoints.extend(_event_streams_endpoints)
api_endpoints.extend(_exposure_management_endpoints)
api_endpoints.extend(_faas_execution_endpoints)
api_endpoints.extend(_falcon_complete_dashboard_endpoints)
api_endpoints.extend(_falcon_container_endpoints)
api_endpoints.extend(_falconx_sandbox_endpoints)
api_endpoints.extend(_fdr_endpoints)
api_endpoints.extend(_filevantage_endpoints)
api_endpoints.extend(_firewall_management_endpoints)
api_endpoints.extend(_firewall_policies_endpoints)
api_endpoints.extend(_foundry_logscale_endpoints)
api_endpoints.extend(_host_group_endpoints)
api_endpoints.extend(_hosts_endpoints)
api_endpoints.extend(_host_migration_endpoints)
api_endpoints.extend(_identity_protection_endpoints)
api_endpoints.extend(_image_assessment_policies_endpoints)
api_endpoints.extend(_incidents_endpoints)
api_endpoints.extend(_intelligence_indicator_graph_endpoints)
api_endpoints.extend(_installation_tokens_endpoints)
api_endpoints.extend(_intelligence_feeds_endpoints)
api_endpoints.extend(_intel_endpoints)
api_endpoints.extend(_ioa_exclusions_endpoints)
api_endpoints.extend(_ioc_endpoints)
api_endpoints.extend(_iocs_endpoints)
api_endpoints.extend(_it_automation_endpoints)
api_endpoints.extend(_kubernetes_container_compliance_endpoints)
api_endpoints.extend(_kubernetes_protection_endpoints)
api_endpoints.extend(_malquery_endpoints)
api_endpoints.extend(_message_center_endpoints)
api_endpoints.extend(_ml_exclusions_endpoints)
api_endpoints.extend(_mobile_enrollment_endpoints)
api_endpoints.extend(_mssp_endpoints)
api_endpoints.extend(_ngsiem_endpoints)
api_endpoints.extend(_oauth2_endpoints)
api_endpoints.extend(_ods_endpoints)
api_endpoints.extend(_overwatch_dashboard_endpoints)
api_endpoints.extend(_prevention_policies_endpoints)
api_endpoints.extend(_quarantine_endpoints)
api_endpoints.extend(_quick_scan_endpoints)
api_endpoints.extend(_quick_scan_pro_endpoints)
api_endpoints.extend(_real_time_response_endpoints)
api_endpoints.extend(_real_time_response_admin_endpoints)
api_endpoints.extend(_real_time_response_audit_endpoints)
api_endpoints.extend(_recon_endpoints)
api_endpoints.extend(_report_executions_endpoints)
api_endpoints.extend(_response_policies_endpoints)
api_endpoints.extend(_saas_security_endpoints)
api_endpoints.extend(_sample_uploads_endpoints)
api_endpoints.extend(_scheduled_reports_endpoints)
api_endpoints.extend(_sensor_download_endpoints)
api_endpoints.extend(_sensor_update_policies_endpoints)
api_endpoints.extend(_sensor_usage_endpoints)
api_endpoints.extend(_sensor_visibility_exclusions_endpoints)
api_endpoints.extend(_serverless_vulnerabilities_endpoints)
api_endpoints.extend(_spotlight_evaluation_logic_endpoints)
api_endpoints.extend(_spotlight_vulnerabilities_endpoints)
api_endpoints.extend(_spotlight_vulnerability_metadata_endpoints)
api_endpoints.extend(_tailored_intelligence_endpoints)
api_endpoints.extend(_threatgraph_endpoints)
api_endpoints.extend(_unidentified_containers_endpoints)
api_endpoints.extend(_user_management_endpoints)
api_endpoints.extend(_workflows_endpoints)
api_endpoints.extend(_zero_trust_assessment_endpoints)

# Deprecated endpoints
deprecated_endpoints = []
deprecated_endpoints.extend(_case_management_deprecated)
deprecated_endpoints.extend(_cloud_aws_registration_deprecated)
deprecated_endpoints.extend(_cloud_azure_registration_deprecated)
deprecated_endpoints.extend(_cloud_google_cloud_registration_deprecated)
deprecated_endpoints.extend(_cloud_oci_registration_deprecated)
deprecated_endpoints.extend(_cloud_security_deprecated)
deprecated_endpoints.extend(_cloud_security_assets_deprecated)
deprecated_endpoints.extend(_cloud_security_compliance_deprecated)
deprecated_endpoints.extend(_cloud_security_detections_deprecated)
deprecated_endpoints.extend(_correlation_rules_admin_deprecated)
deprecated_endpoints.extend(_correlation_rules_deprecated)
deprecated_endpoints.extend(_certificate_based_exclusions_deprecated)
deprecated_endpoints.extend(_custom_ioa_deprecated)
deprecated_endpoints.extend(_d4c_registration_deprecated)
deprecated_endpoints.extend(_data_protection_configuration_deprecated)
deprecated_endpoints.extend(_device_content_deprecated)
deprecated_endpoints.extend(_discover_deprecated)
deprecated_endpoints.extend(_fdr_deprecated)
deprecated_endpoints.extend(_firewall_management_deprecated)
deprecated_endpoints.extend(_hosts_deprecated)
deprecated_endpoints.extend(_identity_protection_deprecated)
deprecated_endpoints.extend(_installation_tokens_deprecated)
deprecated_endpoints.extend(_ioc_deprecated)
deprecated_endpoints.extend(_iocs_deprecated)
deprecated_endpoints.extend(_ods_deprecated)
deprecated_endpoints.extend(_real_time_response_deprecated)
deprecated_endpoints.extend(_real_time_response_admin_deprecated)
deprecated_endpoints.extend(_report_executions_deprecated)
deprecated_endpoints.extend(_scheduled_reports_deprecated)
deprecated_endpoints.extend(_zero_trust_assessment_deprecated)

# Mapping of manually deprecated endpoints
operation_deprecation_mapping = _deprecated_operation_mapping
class_deprecation_mapping = _deprecated_class_mapping

# api_endpoints contains all endpoints, production and deprecated
api_endpoints.extend(deprecated_endpoints)
