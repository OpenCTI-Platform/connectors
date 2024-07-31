# Maltiverse - OpenCTI connector

This connector enables you to bring the information from [Maltiverse](https://maltiverse.com) into OpenCTI

## Installation

There is a [`docker-compose.yml`](docker-compose.yml) example you can use to enable this connector as explained in the [official documentation](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8).

### Requirements

- OpenCTI Platform >= 6.2.9

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `user`                        | `MALTIVERSE_USER`                       | Yes          | User to use when perform requests                                                                                                                           |
| `passwd`                        | `MALTIVERSE_PASS`                       | Yes          | Password to use when perform requests                                                                                                                           |
| `feeds`                        | `MALTIVERSE_FEEDS`                       | Yes          | List of feeds to retrieve from maltiverse                                                                                                                           |
| `poll_interval`                        | `MALTIVERSE_POLL_INTERVAL`                       | Yes          | Interval between connector runs                                                                                                                           |
