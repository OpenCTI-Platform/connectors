# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type      | Required | Possible values                                                                                           | Deprecated | Default | Description                                                                                                                    |
| -------- |-----------| ------ |-----------------------------------------------------------------------------------------------------------| ---------- |---------|--------------------------------------------------------------------------------------------------------------------------------|
| OPENCTI_URL | `string`  | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats)      |  |         | The base URL of the OpenCTI instance.                                                                                          |
| OPENCTI_TOKEN | `string`  | ✅ | string                                                                                                    |  |         | The API token to connect to OpenCTI.                                                                                           |
| ANYRUN_API_KEY | `string`  | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |         | ANY.RUN Sandbox API-KEY. See 'Generate API KEY' section in the README file.                                                    |
| ANYRUN_LOOKUP_DEPTH | `integer`  | | integer                                                                                                   |  | `90`     | Specify the number of days from the current date for which you want to lookup.                                                                   |
