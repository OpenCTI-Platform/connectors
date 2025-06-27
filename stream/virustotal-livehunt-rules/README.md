# OpenCTI VirusTotal Livehunt Stream connector

This connector allows organizations to create and manage VirusTotal Livehunts from OpenCTI. 
When enabling a Yara rule in OpenCTI automatically it does create a new Livehunt in VirusTotal.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                   |
| ------------------------------------ | ----------------------------------- | ------------ |-----------------------------------------------------------------------------------------------|
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | The name of the VirusTotal Livehunt Stream instance, to identify it if you have multiple VirusTotal Livehunt connectors.       |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Must be `Virustotal` for this connector.                                                      |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `virustotal_livehunt_token`          | `VIRUSTOTAL_LIVEHUNT_TOKEN`         | Yes          | The VirusTotal API token                                                                      |
| `virustotal_livehunt_notification_emails` |`VIRUSTOTAL_LIVEHUNT_NOTIFICATION_EMAILS`         | Yes          | List of emails to receive notifications when the rule gets triggered. Format: `["email1@example.com", "email2@example.com"]` |
| `virustotal_livehunt_shared_owners`  | `VIRUSTOTAL_LIVEHUNT_SHARED_OWNERS` | No          | Existing Virustotal users or groups ID that the rule will be shared with. Format: `["user1", "user2"]` |
| `virustotal_livehunt_new_files_only` | `VIRUSTOTAL_LIVEHUNT_NEW_FILES_ONLY`| No          | If set to `true`, automatically adds `new_file` condition to all YARA rules. Default: `false` |

## Features

### YARA Rule Management
- Automatically creates VirusTotal Livehunt rules from OpenCTI YARA indicators
- Updates rules when changes are made in OpenCTI
- Supports rule sharing with other VirusTotal users or groups

### New Files Only Mode
When `virustotal_livehunt_new_files_only` is enabled, the connector automatically modifies YARA rules to only match new files. This is done by adding `new_file and` to the rule's condition section. For example:

```yara
rule example {
    strings:
        $a = "suspicious_string"
    condition:
        new_file and $a
}
```

This ensures that rules only trigger on newly uploaded files to VirusTotal, reducing noise from historical matches.

### Email Notifications
- Supports multiple email addresses for notifications
- Emails are sent when rules match files in VirusTotal
- Notification list can be updated through configuration

## Usage

1. Create a YARA rule in OpenCTI under Analyses
2. Enable detection for the rule
3. The connector will automatically create a corresponding Livehunt rule in VirusTotal
4. Monitor email notifications for matches

## Troubleshooting

- Set `connector_log_level` to `debug` for detailed logging
- Verify your VirusTotal API token has the necessary permissions
- Check email format in configuration matches the expected JSON array format
- Ensure OpenCTI YARA rules have detection enabled