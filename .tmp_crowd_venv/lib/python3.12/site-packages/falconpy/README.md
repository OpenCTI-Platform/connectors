![CrowdStrike FalconPy](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png#gh-light-mode-only)
![CrowdStrike FalconPy](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo-red.png#gh-dark-mode-only)

# FalconPy - The CrowdStrike Falcon SDK for Python
This folder contains the FalconPy project, a Python interface handler for the CrowdStrike Falcon OAuth2 API.

## Service Classes
### Currently implemented
Each class defined below represents a single CrowdStrike Falcon API service collection, with methods defined
for every single operation available within that service collection.
| Source file | Swagger documentation |
| :--- | :--- |
| `cloud_connect_aws.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-connect-aws |
| `cspm-registration.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cspm-registration |
| `custom_ioa.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/custom-ioa |
| `d4c_registration.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/d4c-registration |
| `detects.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/detects |
| `device_control_policies.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/device-control-policies |
| `discover.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/discover |
| `event_streams.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/event-streams |
| `falcon_complete_dashboard.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falcon-complete-dashboard |
| `falcon_container.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falcon-container |
| `falconx_sandbox.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox |
| `filevantage.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage |
| `firewall_management.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management |
| `firewall_policies.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-policies |
| `host_group.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-group |
| `hosts.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts |
| `identity_protection.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/identity-protection |
| `incidents.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/incidents |
| `installation_tokens.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/installation-tokens |
| `intel.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel |
| `ioa_exclusions.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioa-exclusions |
| `ioc.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc |
| `iocs.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs |
| `kubernetes_protection.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection |
| `malquery.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery |
| `message_center.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center |
| `ml_exclusions.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ml-exclusions |
| `mobile_enrollment.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mobile-enrollment |
| `mssp.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp |
| `oauth2.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/oauth2 |
| `ods.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ods |
| `overwatch_dashboard.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/overwatch-dashboard |
| `prevention_policy.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/prevention-policies |
| `quarantine.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quarantine |
| `quick_scan.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan |
| `real_time_response_admin.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response-admin |
| `real_time_response.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response |
| `recon.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/recon |
| `report_executions.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/report-executions |
| `response_policies.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/response-policies |
| `sample_uploads.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads |
| `scheduled_reports.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/scheduled-reports |
| `sensor_download.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-download |
| `sensor_update_policy.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-update-policies |
| `sensor_visibility_exclusions.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-visibility-exclusions |
| `spotlight_evaluation_logic.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/spotlight-evaluation-logic |
| `spotlight_vulnerabilities.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/spotlight-vulnerabilities |
| `tailored_intelligence.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/tailored-intelligence |
| `user_management.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management |
| `zero_trust_assessment.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html#/zero-trust-assessment |

## The Uber Class
#### A single class to interface with the entire API
The Uber class is a harness that leverages operation IDs to look up the necessary detail to interact with the entire API.
You can also leverage the Uber Class to interact with operations not yet defined within the private endpoint submodule by
making use of the `override` keyword.
| Source file | Swagger documentation |
| :--- | :--- |
| `api_complete.py` | https://assets.falcon.crowdstrike.com/support/api/swagger.html |
