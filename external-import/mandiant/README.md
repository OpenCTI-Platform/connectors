# Mandiant Connector

This connector connects to the Mandiant Advantage API V4 and gather all data from a given date.

## Configuration

The connector can be configured with the following variables:

| Env var                                                  | Default                               | Description                                                                 |
|----------------------------------------------------------|---------------------------------------|-----------------------------------------------------------------------------|
| `MANDIANT_API_URL`                                       | https://api.intelligence.mandiant.com | URL for the Mandiant API                                                    |
| `MANDIANT_API_V4_KEY_ID`                                 |                                       | Mandiant API Key ID                                                         |
| `MANDIANT_API_V4_KEY_SECRET`                             |                                       | Mandiant API Key Secret                                                     |
| `MANDIANT_IMPORT_START_DATE`                             | 2023-01-01                            | Date to start collect data                                                  |
| `MANDIANT_INDICATOR_IMPORT_START_DATE`                   | 2023-01-01                            | Date to start collect indicators                                            |
| `MANDIANT_IMPORT_PERIOD`                                 | 2                                     | Number of days to fetch in one round trip                                   |
| `MANDIANT_INDICATOR_MINIMUM_SCORE`                       | 80                                    | Minimum score (based on mscore) that an indicator must have to be processed |
| `MANDIANT_CREATE_NOTES`                                  | False                                 | Create notes                                                                |
| `MANDIANT_REMOVE_STATEMENT_MARKING`                      | False                                 | Remove statement marking                                                    |
| `MANDIANT_IMPORT_ACTORS`                                 | True                                  | Enable to collect actors                                                    |
| `MANDIANT_IMPORT_ACTORS_INTERVAL`                        | 1                                     | Interval in hours to check and collect new actors                           |
| `MANDIANT_IMPORT_ACTORS_ALIASES`                         | False                                 | Import actors aliases                                                       |
| `MANDIANT_IMPORT_REPORTS`                                | True                                  | Enable to collect reports                                                   |
| `MANDIANT_IMPORT_REPORTS_INTERVAL`                       | 1                                     | Interval in hours to check and collect new reports                          |
| `MANDIANT_IMPORT_MALWARES`                               | True                                  | Enable to collect malwares                                                  |
| `MANDIANT_IMPORT_MALWARES_INTERVAL`                      | 1                                     | Interval in hours to check and collect new malwares                         |
| `MANDIANT_IMPORT_MALWARES_ALIASES`                       | False                                 | Import malware aliases                                                      |
| `MANDIANT_IMPORT_CAMPAIGNS`                              | True                                  | Enable to collect campaigns                                                 |
| `MANDIANT_IMPORT_CAMPAIGNS_INTERVAL`                     | 1                                     | Interval in hours to check and collect new campaigns                        |
| `MANDIANT_IMPORT_INDICATORS`                             | False                                 | Enable to collect indicators                                                |
| `MANDIANT_IMPORT_INDICATORS_INTERVAL`                    | 1                                     | Interval in hours to check and collect new indicators                       |
| `MANDIANT_IMPORT_VULNERABILITIES`                        | False                                 | Enable to collect vulnerabilities                                           |
| `MANDIANT_IMPORT_VULNERABILITIES_INTERVAL`               | 1                                     | Interval in hours to check and collect new vulnerabilities                  |
| `MANDIANT_ACTOR_PROFILE_REPORT`                          | True                                  | Enable to collect report type actor profile                                 |
| `MANDIANT_COUNTRY_PROFILE_REPORT`                        | True                                  | Enable to collect report type country_profile                               |
| `MANDIANT_EVENT_COVERAGE_IMPLICATION_REPORT`             | True                                  | Enable to collect report type event_coverage_implication                    |
| `MANDIANT_EXECUTIVE_PERSPECTIVE_REPORT`                  | True                                  | Enable to collect report type executive_perspective                         |
| `MANDIANT_ICS_SECURITY_ROUNDUP_REPORT`                   | True                                  | Enable to collect report type ics_security_roundup                          |
| `MANDIANT_INDUSTRY_REPORTING_REPORT`                     | True                                  | Enable to collect report type industry_reporting                            |
| `MANDIANT_MALWARE_PROFILE_REPORT`                        | True                                  | Enable to collect report type malware_profile                               |
| `MANDIANT_NETWORK_ACTIVITY_REPORT`                       | True                                  | Enable to collect report type network_activity_reports                      |
| `MANDIANT_PATCH_REPORT`                                  | True                                  | Enable to collect report type patch_report                                  |
| `MANDIANT_TTP_DEEP_DIVE_REPORT`                          | True                                  | Enable to collect report type ttp_deep_dive                                 |
| `MANDIANT_THREAT_ACTIVITY_ALERT_REPORT`                  | True                                  | Enable to collect report type threat_activity_alert                         |
| `MANDIANT_THREAT_ACTIVITY_REPORT`                        | True                                  | Enable to collect report type threat_activity_report                        |
| `MANDIANT_TRENDS_AND_FORECASTING_REPORT`                 | True                                  | Enable to collect report type trends_and_forecasting                        |
| `MANDIANT_VULNERABILITY_REPORT`                          | True                                  | Enable to collect report type vulnerability_report                          |
| `MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT`      | True                                  | Enable to collect report type weekly_vulnerability_exploitation_report      |
| `MANDIANT_NEWS_ANALYSIS_REPORT`                          | True                                  | Enable to collect report type news_analysis                                 |
| `MANDIANT_ACTOR_PROFILE_REPORT_TYPE`                     | actor-profile                         | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_COUNTRY_PROFILE_REPORT_TYPE`                   | country-profile                       | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_EVENT_COVERAGE_IMPLICATION_REPORT_TYPE`        | event-coverage                        | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_EXECUTIVE_PERSPECTIVE_REPORT_TYPE`             | executive-perspective                 | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_ICS_SECURITY_ROUNDUP_REPORT_TYPE`              | ics-security-roundup                  | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_INDUSTRY_REPORTING_REPORT_TYPE`                | industry                              | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_MALWARE_PROFILE_REPORT_TYPE`                   | malware-profile                       | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_NETWORK_ACTIVITY_REPORT_TYPE`                  | network-activity                      | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_PATCH_REPORT_TYPE`                             | patch                                 | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_TTP_DEEP_DIVE_REPORT_TYPE`                     | ttp-deep-dive                         | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_THREAT_ACTIVITY_ALERT_REPORT_TYPE`             | threat-alert                          | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_THREAT_ACTIVITY_REPORT_TYPE`                   | threat-activity                       | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_TRENDS_AND_FORECASTING_REPORT_TYPE`            | trends-forecasting                    | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_VULNERABILITY_REPORT_TYPE`                     | vulnerability                         | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT_TYPE` | vulnerability-exploitation            | Report type on vocabulary `report_types_ov`                                 |
| `MANDIANT_NEWS_ANALYSIS_REPORT_TYPE`                     | news-analysis                         | Report type on vocabulary `report_types_ov`                                 |