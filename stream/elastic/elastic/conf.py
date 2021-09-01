# This is just the defaults as a Python dict. Please override any settings in a `config.yml`
defaults: dict = {
    "opencti": {
        "ssl_verify": True,
        "token": None,
        "url": "http://localhost:8080",
    },
    "connector": {
        "id": None,
        "type": "STREAM",
        "name": "Elastic CTI Connector",
        "scope": "elasticsearch",
        "mode": "ecs",
        "confidence_level": 80,
        "log_level": "INFO",
        "entity_description": "Elastic detection engine results via connector",
        "entity_name": "Elastic CTI Cluster",
        "live_stream_id": "ChangeMe",
    },
    "elastic": {
        "signals": {
            "query_interval": "5m",
            "lookback_interval": "5m",
            "signal_index": ".siem-signals-*",
            "query": '{"query":{"bool":{"must":{"match":{"signal.rule.type":"threat_match"}}}}}',
        },
        "sightings_tlp": None,
    },
    "cloud": {"auth": None, "id": None},
    "output": {
        "elasticsearch": {
            "hosts": ["localhost:9200"],
            "ssl_verify": True,
            "username": None,
            "password": None,
            "api_key": None,
            "index": "opencti-{now/d}",
        }
    },
    "setup": {
        "ilm": {
            "enabled": True,
            "overwrite": False,
            "pattern": "{now/d}-000001",
            "policy_name": "opencti",
            "rollover_alias": "opencti",
        },
        "template": {
            "enabled": True,
            "name": "opencti",
            "overwrite": False,
            "pattern": "opencti-*",
        },
    },
}
