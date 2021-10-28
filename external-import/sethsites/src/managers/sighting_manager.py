import threading
import ciso8601
from pycti import OpenCTIConnectorHelper


class SightingManager:
    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self._lock = threading.Lock()
        self.sightings = {}
        # this needs to be a config item
        self.buffer_time = 30 * 60 * 1000

        # We should read in all the incidents from opencti
        self.read_sightings_from_opencti()
        # we need to make sure we upload all incidents to opencti before we shut down

    def read_sightings_from_opencti(self):
        pass

