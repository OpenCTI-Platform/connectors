# This is just the defaults as a Python dict. Please override any settings in a `config.yml`
defaults: dict = {
    "opencti": {
        "ssl_verify": True,
        "token": None,
        "url": "http://localhost:8080",
    },
    "connector": {
        "id": None,
        "type": "EXTERNAL_IMPORT",
        "name": "Elastic CTI Connector",
        "scope": "elasticsearch",
        "confidence_level": 80,
        "log_level": "INFO",
        "entity_description": "Elastic detection engine results via connector",
        "entity_name": "Elastic CTI Cluster",
    },
    "client": {
        "name": None,
        "cloud": {"auth": None, "id": None},
        "elasticsearch": {
            "hosts": ["localhost:9200"],
            "ssl_verify": True,
            "username": None,
            "password": None,
            "api_key": None,
        }
    },
    "scanner": {
        "ping": {
            "time_sensitivity": 300,
            "target_sensitivity": 2,
        }
    },
    "manager": {
        "incident": {
            "buffer_time": 60,
        }
    }
}
