ENTITY_TYPE_MAPPER = {
    "domain-name": {
        "chronicle_entity_field": "hostname",
        "chronicle_entity_type": "DOMAIN_NAME",
    },
    "hostname": {
        "chronicle_entity_field": "hostname",
        "chronicle_entity_type": "DOMAIN_NAME",
    },
    "ipv4-addr": {
        "chronicle_entity_field": "ip",
        "chronicle_entity_type": "IP_ADDRESS",
    },
    "ipv6-addr": {
        "chronicle_entity_field": "ip",
        "chronicle_entity_type": "IP_ADDRESS",
    },
    "url": {
        "chronicle_entity_field": "url",
        "chronicle_entity_type": "URL",
    },
    "stixfile": {
        "chronicle_entity_field": "file",
        "chronicle_entity_type": "FILE",
    },
}

HASH_TYPES_MAPPER = {
    "md5": "md5",
    "sha-1": "sha1",
    "sha-256": "sha256",
    "sha1": "sha1",
    "sha256": "sha256",
}
