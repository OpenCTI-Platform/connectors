"""VC1xx — Configuration checks.

Validates connector configuration files (docker-compose.yml, .env.sample,
config.yml.sample) for compliance with OpenCTI conventions.

VC101  config-token-default        OPENCTI_TOKEN must default to ChangeMe
VC102  config-url-default          OPENCTI_URL must default to http://localhost
VC103  config-variable-prefix      Env vars must use OPENCTI_, CONNECTOR_, or <NAME>_ prefix
VC104  config-file-samples         config.yml.sample + docker-compose/env must exist
VC105  no-absolute-import-date     Import dates must use ISO duration, not absolute dates
"""
