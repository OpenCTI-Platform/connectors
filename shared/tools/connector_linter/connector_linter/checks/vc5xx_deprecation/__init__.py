"""VC5xx — Deprecation checks.

Detects usage of deprecated patterns, configuration variables, and APIs
that must be migrated for verified-connector status.

VC501  no-legacy-interval          Must use duration_period (ISO 8601), not interval
VC502  no-deprecated-report-status Must not use deprecated x_opencti_report_status
VC503  no-deprecated-helper-logger Must use connector_logger instead of helper.log_{level}()
VC504  no-deprecated-confidence    Must not use deprecated confidence level (since 6.0)
VC505  no-direct-api-calls        Connector should not use direct GraphQL API calls
VC506  no-update-existing-data    Must not use deprecated UPDATE_EXISTING_DATA
"""
