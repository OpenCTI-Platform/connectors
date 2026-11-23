# Connector Configurations

Below is an exhaustive enumeration of all configurable parameters available, each accompanied by detailed explanations of their purposes, default behaviors, and usage guidelines to help you understand and utilize them effectively.

### Type: `object`

| Property | Type | Required | Possible values | Deprecated | Default | Description |
| -------- | ---- | -------- | --------------- | ---------- | ------- | ----------- |
| OPENCTI_URL | `string` | ✅ | Format: [`uri`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The base URL of the OpenCTI instance. |
| OPENCTI_TOKEN | `string` | ✅ | Format: [`password`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  |  | The API token to connect to OpenCTI. |
| CONNECTOR_NAME | `string` |  | string |  | `"BeaconBeagle"` | The name of the connector. |
| CONNECTOR_SCOPE | `array` |  | string |  | `["beaconbeagle"]` | The scope of the connector. |
| CONNECTOR_LOG_LEVEL | `string` |  | `debug` `info` `warn` `warning` `error` |  | `"error"` | The minimum level of logs to display. |
| CONNECTOR_TYPE | `const` |  | `EXTERNAL_IMPORT` |  | `"EXTERNAL_IMPORT"` |  |
| CONNECTOR_DURATION_PERIOD | `string` |  | Format: [`duration`](https://json-schema.org/understanding-json-schema/reference/string#built-in-formats) |  | `"PT2H"` | The period of time to await between two runs of the connector. |
| BEACONBEAGLE_URL | `string` |  | string |  | `"https://beaconbeagle.com/api/v1/c2?q=&protocol=&port=&min_endpoints=0&first_after=&first_before=&last_after=&last_before=&sort=firsttime&order=desc"` | The BeaconBeagle C2 list URL. |
| BEACONBEAGLE_ADD_URLS | `boolean` |  | boolean |  | `false` | Save URLs from BeaconBeagle into OpenCTI. |
| BEACONBEAGLE_ADD_USERAGENT | `boolean` |  | boolean |  | `false` | Save User-Agent strings as observables. |
| BEACONBEAGLE_LINK_TOOL | `string` |  | string |  | `""` | Tool name (e.g. 'CobaltStrike') to link observables to. Leave empty to skip the link. |
| BEACONBEAGLE_LINK_AP | `string` |  | string |  | `""` | Attack-pattern reference. Either a plain name or '<MITRE_ID> <name>' (e.g. 'T1071 Standard Application Layer Protocol'). Leave empty to skip. |
| BEACONBEAGLE_LINK_COUNTRY | `boolean` |  | boolean |  | `false` | Create a Country location for each C2 IP and link it. |
| BEACONBEAGLE_LINK_BGPAS | `boolean` |  | boolean |  | `false` | Create an Autonomous-System observable for each C2 IP and link it. |
| BEACONBEAGLE_SEARCH_BGPAS | `boolean` |  | boolean |  | `false` | Fall back to 'whois -h bgp.tools' when the BeaconBeagle payload is missing the AS / country fields. Generates outbound traffic to bgp.tools. |
| BEACONBEAGLE_LINK_WATERMARK_TXT | `string` |  | string |  | `""` | Suffix appended to the Text observable that tracks CobaltStrike licence watermarks. Leave empty to disable. |
| BEACONBEAGLE_LINKS_DURATION | `integer` |  | integer |  | `24` | Duration in hours used as the indicator valid_from-valid_until window when BeaconBeagle does not provide a lasttime for a C2 entry. |
| BEACONBEAGLE_MARKING | `string` |  | `TLP:CLEAR` `TLP:WHITE` `TLP:GREEN` `TLP:AMBER` `TLP:AMBER+STRICT` `TLP:RED` |  | `"TLP:GREEN"` | Marking definition applied on every produced object. |
| BEACONBEAGLE_INTERVAL | `integer` |  | integer | ⛔️ | `null` | Use CONNECTOR_DURATION_PERIOD instead. |
| BEACONBEAGLE_MARKING_DEFINITION | `string` |  | string | ⛔️ | `null` | Use BEACONBEAGLE_MARKING instead. |
| BEACONBEAGLE_LINK_WATERMARK | `string` |  | string | ⛔️ | `null` | Use BEACONBEAGLE_LINK_WATERMARK_TXT instead. |
