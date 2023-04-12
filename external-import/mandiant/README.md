# Mandiant Connector

This connector connects to the Mandiant Advantage API V4 and gather all data from a given date.

## Configuration

The connector can be configured with the following variables:

| Env var | Default | Description |
| - | - | - |
| `MANDIANT_API_URL` | https://api.intelligence.mandiant.com | URL for the Mandiant API |
| `MANDIANT_API_V4_KEY_ID` | | Mandiant API Key ID |
| `MANDIANT_API_V4_KEY_SECRET` | | Mandiant API Key Secret |
| `MANDIANT_INTERVAL` | 1 | Number of the days between each collection. |
| `MANDIANT_IMPORT_START_DATE` | 2023-01-01 | Date to start collect data |
| `MANDIANT_COLLECTIONS` | actor,malware,indicator,vulnerability,report | Type of data to be collected |
| `MANDIANT_REPORT_TYPES_IGNORED` | News Analysis| Type of data to be collected |
| `MANDIANT_INDICATOR_MINIMUM_SCORE` | 80 | Minimum score (based on mscore) that an indicator must have to be processed |
| `MANDIANT_IMPORT_ACTORS` | True | Enable to collect actors |
| `MANDIANT_IMPORT_REPORTS` | True | Enable to collect reports |
| `MANDIANT_IMPORT_MALWARES` | True | Enable to collect malwares |
| `MANDIANT_IMPORT_CAMPAIGNS` | True | Enable to collect campaigns |
| `MANDIANT_IMPORT_INDICATORS` | True | Enable to collect indicators |
| `MANDIANT_IMPORT_VULNERABILITIES` | True | Enable to collect vulnerabilities |
| `MANDIANT_ACTOR_PROFILE` | True | Enable to collect report type actor profile |
| `MANDIANT_COUNTRY_PROFILE` | True | Enable to collect report type country_profile |
| `MANDIANT_EVENT_COVERAGE_IMPLICATION` | True | Enable to collect report type event_coverage_implication |
| `MANDIANT_EXECUTIVE_PERSPECTIVE` | True | Enable to collect report type executive_perspective |
| `MANDIANT_ICS_SECURITY_ROUNDUP` | True | Enable to collect report type ics_security_roundup |
| `MANDIANT_INDUSTRY_REPORTING` | True | Enable to collect report type industry_reporting |
| `MANDIANT_MALWARE_PROFILE` | True | Enable to collect report type malware_profile |
| `MANDIANT_NETWORK_ACTIVITY_REPORTS` | True | Enable to collect report type network_activity_reports |
| `MANDIANT_PATCH_REPORT` | True | Enable to collect report type patch_report |
| `MANDIANT_TTP_DEEP_DIVE` | True | Enable to collect report type ttp_deep_dive |
| `MANDIANT_THREAT_ACTIVITY_ALERT` | True | Enable to collect report type threat_activity_alert |
| `MANDIANT_THREAT_ACTIVITY_REPORT` | True | Enable to collect report type threat_activity_report |
| `MANDIANT_TRENDS_AND_FORECASTING` | True | Enable to collect report type trends_and_forecasting |
| `MANDIANT_VULNERABILITY_REPORT` | True | Enable to collect report type vulnerability_report |
| `MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT` | True | Enable to collect report type weekly_vulnerability_exploitation_report |
| `MANDIANT_NEWS_ANALYSIS` | True | Enable to collect report type news_analysis |
