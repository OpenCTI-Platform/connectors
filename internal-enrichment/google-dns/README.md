# OpenCTI Google DNS Connector

This OpenCTI connector enriches Domain Name Observables by querying DNS for
various record types using the Google Public DNS service:

- `NS`
- `A`
- `CNAME`
- `MX`
- `TXT`

The connector then creates Observables and Relationships among them based on the
query answers.

## Configuration variables

Find all the configuration variables available (default/required) here: [Connector Configurations](./__metadata__)