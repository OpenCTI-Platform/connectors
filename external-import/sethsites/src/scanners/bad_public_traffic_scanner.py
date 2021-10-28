from datetime import datetime, timedelta
from threading import Event
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from pycti import OpenCTIConnectorHelper, get_config_variable
from scanners import Scanner
from managers import IncidentManager, EnvironmentManager, RelationshipManager
from scalpl import Cut


class BadPublicTrafficScanner(Scanner):
    def __init__(self,
                 config: Cut,
                 env_manager: EnvironmentManager,
                 es: Elasticsearch,
                 helper: OpenCTIConnectorHelper,
                 incident_manager: IncidentManager,
                 relationship_manager: RelationshipManager,
                 shutdown_event: Event):
        super(BadPublicTrafficScanner, self).__init__(config, env_manager, es, helper, incident_manager,
                                                      relationship_manager, shutdown_event)