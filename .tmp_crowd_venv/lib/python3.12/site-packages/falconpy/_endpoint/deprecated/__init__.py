"""The CrowdStrike Falcon OAuth2 API SDK deprecated endpoints module.

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
#                                                                             .---.        .-----------
#                                                                            /     \  __  /    ------
#                                                                           / /     \(..)/    -----
#  _____                                     __            __              //////   ' \/ `   ---
# |     \.-----.-----.----.-----.----.---.-.|  |_.-----.--|  |            //// / // :    : ---
# |  --  |  -__|  _  |   _|  -__|  __|  _  ||   _|  -__|  _  |           // /   /  /`    '--
# |_____/|_____|   __|__| |_____|____|___._||____|_____|_____|          //          //..\\
#              |__|                                                                UU    UU
# The following operations reference legacy naming convention and are considered deprecated.
# These operation IDs are maintained for backwards compatibility purposes only, Move all code
# references to use the new operations IDs defined above that align with the IDs defined in
# the service classes.
from ._case_management import _case_management_endpoints
from ._cloud_aws_registration import _cloud_aws_registration_endpoints
from ._cloud_azure_registration import _cloud_azure_registration_endpoints
from ._cloud_google_cloud_registration import _cloud_google_cloud_registration_endpoints
from ._cloud_oci_registration import _cloud_oci_registration_endpoints
from ._cloud_security import _cloud_security_endpoints
from ._cloud_security_assets import _cloud_security_assets_endpoints
from ._cloud_security_compliance import _cloud_security_compliance_endpoints
from ._cloud_security_detections import _cloud_security_detections_endpoints
from ._custom_ioa import _custom_ioa_endpoints
from ._correlation_rules import _correlation_rules_endpoints
from ._correlation_rules_admin import _correlation_rules_admin_endpoints
from ._d4c_registration import _d4c_registration_endpoints
from ._data_protection_configuration import _data_protection_configuration_endpoints
from ._device_content import _device_content_endpoints
from ._discover import _discover_endpoints
from ._exposure_management import _exposure_management_endpoints
from ._fdr import _fdr_endpoints
from ._firewall_management import _firewall_management_endpoints
from ._hosts import _hosts_endpoints
from ._identity_protection import _identity_protection_endpoints
from ._installation_tokens import _installation_tokens_endpoints
from ._ioc import _ioc_endpoints
from ._iocs import _iocs_endpoints
from ._ods import _ods_endpoints
from ._real_time_response import _real_time_response_endpoints
from ._real_time_response_admin import _real_time_response_admin_endpoints
from ._report_executions import _report_executions_endpoints
from ._scheduled_reports import _scheduled_reports_endpoints
from ._zero_trust_assessment import _zero_trust_assessment_endpoints
from ._mapping import _deprecated_op_mapping, _deprecated_cls_mapping
from ._certificate_based_exclusions import _certificate_based_exclusions_endpoints

_case_management_deprecated = _case_management_endpoints
_cloud_aws_registration_deprecated = _cloud_aws_registration_endpoints
_cloud_azure_registration_deprecated = _cloud_azure_registration_endpoints
_cloud_google_cloud_registration_deprecated = _cloud_google_cloud_registration_endpoints
_cloud_oci_registration_deprecated = _cloud_oci_registration_endpoints
_cloud_security_deprecated = _cloud_security_endpoints
_cloud_security_assets_deprecated = _cloud_security_assets_endpoints
_cloud_security_compliance_deprecated = _cloud_security_compliance_endpoints
_cloud_security_detections_deprecated = _cloud_security_detections_endpoints
_correlation_rules_admin_deprecated = _correlation_rules_admin_endpoints
_correlation_rules_deprecated = _correlation_rules_endpoints
_custom_ioa_deprecated = _custom_ioa_endpoints
_d4c_registration_deprecated = _d4c_registration_endpoints
_data_protection_configuration_deprecated = _data_protection_configuration_endpoints
_device_content_deprecated = _device_content_endpoints
_discover_deprecated = _discover_endpoints
_exposure_management_deprecated = _exposure_management_endpoints
_fdr_deprecated = _fdr_endpoints
_firewall_management_deprecated = _firewall_management_endpoints
_hosts_deprecated = _hosts_endpoints
_identity_protection_deprecated = _identity_protection_endpoints
_installation_tokens_deprecated = _installation_tokens_endpoints
_ioc_deprecated = _ioc_endpoints
_iocs_deprecated = _iocs_endpoints
_ods_deprecated = _ods_endpoints
_real_time_response_deprecated = _real_time_response_endpoints
_real_time_response_admin_deprecated = _real_time_response_admin_endpoints
_report_executions_deprecated = _report_executions_endpoints
_scheduled_reports_deprecated = _scheduled_reports_endpoints
_zero_trust_assessment_deprecated = _zero_trust_assessment_endpoints
_certificate_based_exclusions_deprecated = _certificate_based_exclusions_endpoints
_deprecated_operation_mapping = _deprecated_op_mapping
_deprecated_class_mapping = _deprecated_cls_mapping
