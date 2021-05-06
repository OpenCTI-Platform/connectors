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
        "name": "Elastic Threat Intel Connector",
        "scope": "elastic",
        "confidence_level": 80,
        "log_level": "info",
        "entity_description": "Elastic detection engine results via connector",
        "entity_name": "Elastic ThreatIntel Cluster",
    },
    "elastic": {
        "import_from_date": None,
        "import_label": "*",
        "indicator_types": ["stix"],
        "max_tlp": None,
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
            "index": "threatintel-%{+yyyy.MM.dd}",
        }
    },
    "setup": {
        "ilm": {
            "enabled": True,
            "overwrite": False,
            "pattern": "%{now/d}-000001",
            "policy_name": "threatintel",
            "rollover_alias": "threatintel",
        },
        "template": {
            "enabled": True,
            "name": "threatintel",
            "overwrite": False,
            "pattern": "threatintel-*",
        },
    },
}
